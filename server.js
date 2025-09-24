import express from 'express';
import Stripe from 'stripe';
import fetch from 'node-fetch';
import bodyParser from 'body-parser';

const app = express();

// Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

// CORS for your site
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://www.vetletters.com'); // change if needed
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// JSON for normal routes
app.use('/api', bodyParser.json());

// 1) Create PaymentIntent route
app.post('/api/create-payment-intent', async (req, res) => {
  try {
    const { amount, currency = 'usd', product = 'VetLetters', lead = {} } = req.body;

    // Upsert lead in Zoho
    const accessToken = await getZohoAccessToken();
    const leadId = await upsertZohoLead(accessToken, lead, product, amount);

    // Create PaymentIntent with dynamic methods
    const pi = await stripe.paymentIntents.create({
      amount,
      currency,
      automatic_payment_methods: { enabled: true }, // card, Klarna, Affirm when eligible
      metadata: {
        zoho_lead_id: leadId,
        product_name: product,
        source: 'vetletters_site'
      },
      receipt_email: lead.email
    });

    res.json({ clientSecret: pi.client_secret });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

// 2) Stripe webhook - use raw body for signature verification
app.post('/api/stripe-webhook',
  bodyParser.raw({ type: 'application/json' }),
  async (req, res) => {
    let event;
    try {
      const sig = req.headers['stripe-signature'];
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('Webhook signature check failed', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === 'payment_intent.succeeded') {
        const pi = event.data.object;
        const leadId = pi.metadata?.zoho_lead_id;
        const charge = pi.charges?.data?.[0];
        const method = charge?.payment_method_details?.type;
        const amount = (pi.amount_received || pi.amount) / 100;
        const receipt = charge?.receipt_url;

        const accessToken = await getZohoAccessToken();
        await updateZohoLeadPaid(accessToken, leadId, {
          product_name: pi.metadata?.product_name,
          amount,
          method,
          receipt
        });
      }

      if (event.type === 'payment_intent.payment_failed') {
        const pi = event.data.object;
        const leadId = pi.metadata?.zoho_lead_id;
        const accessToken = await getZohoAccessToken();
        await markZohoLeadFailed(accessToken, leadId);
      }

      res.json({ received: true });
    } catch (err) {
      console.error('Webhook handling failed', err);
      res.status(500).send('Server error');
    }
  }
);

// Start server
app.listen(process.env.PORT || 3000, () => {
  console.log('Server listening');
});

/* ---------------- Zoho helpers ---------------- */

const ZOHO_ACCOUNTS = 'https://accounts.zoho.com';
const ZOHO_API_BASE = process.env.ZOHO_API_BASE || 'https://www.zohoapis.com';

// Refresh token flow
async function getZohoAccessToken() {
  // If you already inject a fresh access token, you can skip refresh here
  const url = `${ZOHO_ACCOUNTS}/oauth/v2/token?refresh_token=${process.env.ZOHO_REFRESH_TOKEN}&client_id=${process.env.ZOHO_CLIENT_ID}&client_secret=${process.env.ZOHO_CLIENT_SECRET}&grant_type=refresh_token`;
  const r = await fetch(url, { method: 'POST' });
  if (!r.ok) throw new Error(`Zoho token error ${r.status}`);
  const j = await r.json();
  if (!j.access_token) throw new Error('No Zoho access token');
  return j.access_token;
}

// Upsert by email. Creates if not found.
async function upsertZohoLead(accessToken, lead, product, amountCents) {
  const found = await searchZohoLeadByEmail(accessToken, lead.email);
  if (found) {
    await updateZohoLead(accessToken, found.id, {
      Product_Name: product,
      Order_Status: 'Pending',
      Order_Date: new Date().toISOString().slice(0, 10),
      Description: lead.claim_type ? `Claim Type: ${lead.claim_type}` : undefined
    });
    return found.id;
  }

  const payload = {
    data: [{
      Company: 'VetLetters',           // Zoho Leads often require Company and Last_Name
      Last_Name: lead.last_name || lead.email || 'Unknown',
      First_Name: lead.first_name || '',
      Email: lead.email,
      Phone: lead.phone || '',
      Product_Name: product,
      Order_Status: 'Pending',
      Order_Date: new Date().toISOString().slice(0, 10),
      Description: lead.claim_type ? `Claim Type: ${lead.claim_type}` : ''
    }]
  };

  const r = await fetch(`${ZOHO_API_BASE}/crm/v3/Leads`, {
    method: 'POST',
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  const id = j?.data?.[0]?.details?.id;
  if (!id) throw new Error('Zoho create lead failed');
  return id;
}

async function searchZohoLeadByEmail(accessToken, email) {
  if (!email) return null;
  const url = `${ZOHO_API_BASE}/crm/v3/Leads/search?email=${encodeURIComponent(email)}`;
  const r = await fetch(url, { headers: { Authorization: `Zoho-oauthtoken ${accessToken}` } });
  if (r.status === 204) return null;
  if (!r.ok) return null;
  const j = await r.json();
  return j?.data?.[0] || null;
}

async function updateZohoLead(accessToken, id, fields) {
  const payload = { data: [{ id, ...fields }] };
  const r = await fetch(`${ZOHO_API_BASE}/crm/v3/Leads`, {
    method: 'PUT',
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!r.ok) throw new Error('Zoho update lead failed');
}

async function addZohoNote(accessToken, leadId, title, content) {
  const payload = {
    data: [{
      Note_Title: title,
      Note_Content: content,
      Parent_Id: leadId,
      se_module: 'Leads'
    }]
  };
  const r = await fetch(`${ZOHO_API_BASE}/crm/v3/Notes`, {
    method: 'POST',
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!r.ok) throw new Error('Zoho add note failed');
}

async function updateZohoLeadPaid(accessToken, leadId, info) {
  await updateZohoLead(accessToken, leadId, {
    Order_Status: 'Paid',
    Order_Date: new Date().toISOString().slice(0, 10),
    Product_Name: info.product_name,
    Amount: info.amount,                // create this custom field if you want exact amount stored
    Payment_Method: info.method         // create this custom field or store in Description
  });

  const note = `Payment received. Method: ${info.method}. Amount: $${info.amount}. Receipt: ${info.receipt}`;
  await addZohoNote(accessToken, leadId, 'Stripe Payment', note);
}

async function markZohoLeadFailed(accessToken, leadId) {
  await updateZohoLead(accessToken, leadId, { Order_Status: 'Failed' });
}
