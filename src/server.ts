// server.js
// Run on Render as a Web Service. Set env vars listed at the bottom.
// Node 18+ (uses global fetch). If you're on older Node, add `npm i node-fetch` and import it.

const express = require('express');
const Stripe = require('stripe');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

/* ----------------------------- CORS (allowlist) ----------------------------- */
const ALLOW = [
  'https://www.vetletters.com',
  'https://vetletters.com',
  // Zoho Sites editor/runtime assets domain (wildcard match)
  'https://zohositescontent.com',
  'https://.zohositescontent.com'
];
// Lightweight CORS middleware (kept simple)
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  const allowed = ALLOW.some(a =>
    origin === a ||
    (a.startsWith('https://.') && origin.endsWith(a.replace('https://.', '.'))) ||
    (a === 'https://zohositescontent.com' && origin.endsWith('.zohositescontent.com'))
  );
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/* --------------------------- Stripe Webhook (RAW) --------------------------- */
/**
 * IMPORTANT: This route must use raw body, BEFORE any JSON parser.
 * Stripe requires the exact raw payload for signature verification.
 */
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'payment_intent.succeeded') {
      const pi = event.data.object;
      await handlePaymentSucceeded(pi);
    }

    if (event.type === 'payment_intent.payment_failed') {
      const pi = event.data.object;
      await handlePaymentFailed(pi);
    }

    res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook handling error:', err);
    res.status(500).send('Server error');
  }
});

/* ------------------- JSON parser for normal /api routes -------------------- */
app.use('/api', express.json());

/* ------------------- Create PaymentIntent (+ upsert CRM) ------------------- */
/**
 * Body:
 * {
 *   amount: 89900,            // cents
 *   currency: "usd",
 *   product: "VetLetters Standard",
 *   lead: { first_name, last_name, email, phone, claim_type }
 * }
 */
app.post('/api/create-payment-intent', async (req, res) => {
  try {
    const { amount, currency = 'usd', product = 'VetLetters', lead = {} } = req.body;

    if (!amount || !lead?.email) {
      return res.status(400).json({ error: 'Missing amount or lead.email' });
    }

    // 1) Upsert Zoho Lead as Pending / with today Order_Date
    const accessToken = await getZohoAccessToken();
    const zohoLeadId = await upsertZohoLead(accessToken, lead, product, amount);

    // 2) Create Stripe PaymentIntent (dynamic PMs => card, Klarna, Affirm if eligible)
    const pi = await stripe.paymentIntents.create({
      amount,
      currency,
      automatic_payment_methods: { enabled: true },
      metadata: {
        zoho_lead_id: zohoLeadId,
        product_name: product,
        source: 'vetletters_site'
      },
      receipt_email: lead.email
    });

    return res.json({ clientSecret: pi.client_secret });
  } catch (err) {
    console.error('❌ create-payment-intent error:', err);
    res.status(400).json({ error: err.message });
  }
});

/* ------------------------------- Healthcheck ------------------------------- */
app.get('/', (_req, res) => {
  res.type('text').send('VetLetters API OK');
});

/* =============================== Helpers =================================== */
/* ----------------------------- Stripe helpers ------------------------------ */
async function handlePaymentSucceeded(pi) {
  try {
    const leadId = pi?.metadata?.zoho_lead_id;
    if (!leadId) return;

    const charge = pi.charges?.data?.[0];
    const method = charge?.payment_method_details?.type || 'unknown';
    const amount = (pi.amount_received || pi.amount) / 100;
    const receipt = charge?.receipt_url || '';
    const product = pi?.metadata?.product_name || '';

    const accessToken = await getZohoAccessToken();
    await updateZohoLeadPaid(accessToken, leadId, {
      product_name: product,
      amount,
      method,
      receipt
    });
  } catch (err) {
    console.error('❌ handlePaymentSucceeded error:', err);
  }
}

async function handlePaymentFailed(pi) {
  try {
    const leadId = pi?.metadata?.zoho_lead_id;
    if (!leadId) return;
    const accessToken = await getZohoAccessToken();
    await markZohoLeadFailed(accessToken, leadId);
  } catch (err) {
    console.error('❌ handlePaymentFailed error:', err);
  }
}

/* ------------------------------ Zoho helpers ------------------------------- */
const ZOHO_ACCOUNTS = process.env.ZOHO_ACCOUNTS_BASE || 'https://accounts.zoho.com';
const ZOHO_API_BASE = process.env.ZOHO_API_BASE || 'https://www.zohoapis.com';

/** Exchange refresh token -> access token */
async function getZohoAccessToken() {
  const url = `${ZOHO_ACCOUNTS}/oauth/v2/token` +
              `?refresh_token=${encodeURIComponent(process.env.ZOHO_REFRESH_TOKEN)}` +
              `&client_id=${encodeURIComponent(process.env.ZOHO_CLIENT_ID)}` +
              `&client_secret=${encodeURIComponent(process.env.ZOHO_CLIENT_SECRET)}` +
              `&grant_type=refresh_token`;

  const r = await fetch(url, { method: 'POST' });
  if (!r.ok) throw new Error(`Zoho token error ${r.status}`);
  const j = await r.json();
  if (!j.access_token) throw new Error('No Zoho access token');
  return j.access_token;
}

/** Basic Zoho request wrapper */
async function zohoReq(accessToken, method, path, body) {
  const r = await fetch(`${ZOHO_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Zoho-oauthtoken ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (r.status === 204) return null;
  const text = await r.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    const msg = data?.message || data?.data?.[0]?.message || `Zoho ${method} ${path} failed`;
    throw new Error(msg);
  }
  return data;
}

/** Search lead by email (tries dedicated email search, then criteria) */
async function searchZohoLeadByEmail(accessToken, email) {
  if (!email) return null;
  // Try email search endpoint
  try {
    const r1 = await zohoReq(accessToken, 'GET', `/crm/v3/Leads/search?email=${encodeURIComponent(email)}`);
    if (r1?.data?.length) return r1.data[0];
  } catch (_e) { /* fall back to criteria */ }

  // Criteria fallback
  const criteria = encodeURIComponent(`(Email:equals:${email})`);
  const r2 = await zohoReq(accessToken, 'GET', `/crm/v3/Leads/search?criteria=${criteria}`);
  return r2?.data?.[0] || null;
}

/** Update Zoho lead fields (ignore undefined) */
async function updateZohoLead(accessToken, id, fields) {
  const clean = {};
  Object.entries(fields || {}).forEach(([k, v]) => {
    if (typeof v !== 'undefined' && v !== null) clean[k] = v;
  });
  const payload = { data: [{ id, ...clean }] };
  await zohoReq(accessToken, 'PUT', '/crm/v3/Leads', payload);
}

/** Create lead */
async function createZohoLead(accessToken, leadFields) {
  const payload = { data: [leadFields] };
  const resp = await zohoReq(accessToken, 'POST', '/crm/v3/Leads', payload);
  const id = resp?.data?.[0]?.details?.id;
  if (!id) throw new Error('Zoho create lead failed');
  return id;
}

/** Add a Zoho Note on a Lead */
async function addZohoNote(accessToken, leadId, title, content) {
  const payload = {
    data: [{
      Note_Title: title,
      Note_Content: content,
      Parent_Id: leadId,
      se_module: 'Leads'
    }]
  };
  await zohoReq(accessToken, 'POST', '/crm/v3/Notes', payload);
}

/** Upsert lead by email; set Pending + today date + basic fields */
async function upsertZohoLead(accessToken, lead, product, amountCents) {
  const today = new Date().toISOString().slice(0, 10);

  const existing = await searchZohoLeadByEmail(accessToken, lead.email);
  const baseFields = {
    Product_Name: product,
    Order_Status: 'Pending',
    Order_Date: today
  };

  const desc = lead.claim_type ? `Claim Type: ${lead.claim_type}` : '';
  if (existing?.id) {
    await updateZohoLead(accessToken, existing.id, {
      ...baseFields,
      Description: desc || existing.Description || ''
    });
    return existing.id;
  }

  // Zoho Leads often require Company + Last_Name
  const createFields = {
    Company: 'VetLetters',
    Last_Name: lead.last_name || lead.email || 'Unknown',
    First_Name: lead.first_name || '',
    Email: lead.email,
    Phone: lead.phone || '',
    Description: desc,
    ...baseFields
  };
  const id = await createZohoLead(accessToken, createFields);
  return id;
}

/** Mark Paid and add Note; optionally write custom fields if present */
async function updateZohoLeadPaid(accessToken, leadId, info) {
  const today = new Date().toISOString().slice(0, 10);

  // Base updates (safe, known fields)
  const updates = {
    Order_Status: 'Paid',
    Order_Date: today,
    Product_Name: info.product_name
  };

  // If you created custom fields in Zoho, set their API names here:
  // e.g., ZOHO_FIELD_AMOUNT="Amount", ZOHO_FIELD_PAYMENT_METHOD="Payment_Method"
  if (process.env.ZOHO_FIELD_AMOUNT) {
    updates[process.env.ZOHO_FIELD_AMOUNT] = info.amount;
  }
  if (process.env.ZOHO_FIELD_PAYMENT_METHOD) {
    updates[process.env.ZOHO_FIELD_PAYMENT_METHOD] = info.method;
  }

  await updateZohoLead(accessToken, leadId, updates);

  const note = `Payment received.
Method: ${info.method}
Amount: $${info.amount}
Receipt: ${info.receipt || 'N/A'}`;
  await addZohoNote(accessToken, leadId, 'Stripe Payment', note);
}

/** Mark Failed */
async function markZohoLeadFailed(accessToken, leadId) {
  await updateZohoLead(accessToken, leadId, { Order_Status: 'Failed' });
}

/* ------------------------------ Start server ------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ VetLetters API listening on :${PORT}`);
});
