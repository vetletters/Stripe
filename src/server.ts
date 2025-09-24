import express, { Request, Response, NextFunction } from "express";
import Stripe from "stripe";

const PORT = Number(process.env.PORT || 3000);

// ---- Stripe (required) ----
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) throw new Error("Missing STRIPE_SECRET_KEY");
const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// ---- Zoho (optional: if unset, CRM steps are skipped) ----
const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID;
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET;
const ZOHO_REFRESH_TOKEN = process.env.ZOHO_REFRESH_TOKEN;
const ZOHO_API_BASE = process.env.ZOHO_API_BASE || "https://www.zohoapis.com";
const ZOHO_ACCOUNTS_BASE =
  process.env.ZOHO_ACCOUNTS_BASE || "https://accounts.zoho.com";
const ZOHO_FIELD_AMOUNT = process.env.ZOHO_FIELD_AMOUNT;            // e.g. "Amount"
const ZOHO_FIELD_PAYMENT_METHOD = process.env.ZOHO_FIELD_PAYMENT_METHOD; // e.g. "Payment_Method"
const hasZoho = !!(ZOHO_CLIENT_ID && ZOHO_CLIENT_SECRET && ZOHO_REFRESH_TOKEN);

const app = express();

/* ----------------------------- CORS allowlist ----------------------------- */
const ALLOW = [
  "https://www.vetletters.com",
  "https://vetletters.com",
  ".zohositescontent.com", // allow any subdomain that ends with this
];

app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = (req.headers.origin || "") as string;
  const allowed = ALLOW.some((a) => (a.startsWith(".") ? origin.endsWith(a) : origin === a));
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Stripe-Signature");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

/* --------------------------- Stripe webhook (RAW) -------------------------- */
// MUST be before any JSON middleware.
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req: Request, res: Response) => {
    if (!STRIPE_WEBHOOK_SECRET) return res.status(500).send("Webhook secret not set");
    try {
      const sig = req.headers["stripe-signature"] as string;
      const event = stripe.webhooks.constructEvent(
        (req as any).body, // raw Buffer
        sig,
        STRIPE_WEBHOOK_SECRET
      );

      if (event.type === "payment_intent.succeeded") {
        await onPaymentSucceeded(event.data.object as Stripe.PaymentIntent);
      } else if (event.type === "payment_intent.payment_failed") {
        await onPaymentFailed(event.data.object as Stripe.PaymentIntent);
      }
      res.json({ received: true });
    } catch (err: any) {
      console.error("Webhook error:", err.message);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  }
);

/* ----------------------- JSON parser for normal APIs ----------------------- */
app.use("/api", express.json());

/* ----------------- Create PaymentIntent (+ optional Zoho) ------------------ */
/**
 * POST /api/create-payment-intent
 * Body: {
 *   amount: number (cents),
 *   currency?: 'usd',
 *   product?: string,
 *   lead: { first_name?, last_name?, email, phone?, claim_type? }
 * }
 */
app.post("/api/create-payment-intent", async (req: Request, res: Response) => {
  try {
    const {
      amount,
      currency = "usd",
      product = "VetLetters",
      lead = {},
    }: {
      amount: number;
      currency?: string;
      product?: string;
      lead: {
        first_name?: string;
        last_name?: string;
        email?: string;
        phone?: string;
        claim_type?: string;
      };
    } = req.body || {};

    if (!amount || !lead?.email) {
      return res.status(400).json({ error: "Missing amount or lead.email" });
    }

    // 1) Upsert Zoho (if Zoho creds provided)
    let zohoLeadId = "";
    if (hasZoho) {
      try {
        const access = await getZohoAccessToken();
        zohoLeadId = await upsertZohoLead(access, lead, product);
      } catch (e: any) {
        console.warn("Zoho upsert skipped:", e.message);
      }
    }

    // 2) Create PaymentIntent (dynamic methods => card/Klarna/Affirm when eligible)
    const pi = await stripe.paymentIntents.create({
      amount,
      currency,
      automatic_payment_methods: { enabled: true },
      metadata: {
        zoho_lead_id: zohoLeadId,
        product_name: product,
        source: "vetletters_site",
      },
      receipt_email: lead.email,
    });

    res.json({ clientSecret: pi.client_secret });
  } catch (err: any) {
    console.error("create-payment-intent error:", err);
    res.status(400).json({ error: err.message || "Unable to create payment" });
  }
});

/* -------------------------------- Healthcheck ----------------------------- */
app.get("/", (_req, res) => res.type("text").send("VetLetters API OK"));

/* =============================== Handlers ================================== */
async function onPaymentSucceeded(pi: Stripe.PaymentIntent) {
  try {
    const leadId = pi.metadata?.zoho_lead_id;
    if (!leadId || !hasZoho) return;

    const charge = pi.charges?.data?.[0];
    const method = (charge?.payment_method_details as any)?.type || "unknown";
    const amount = (pi.amount_received || pi.amount) / 100;
    const receipt = (charge as any)?.receipt_url || "";
    const product = pi.metadata?.product_name || "";

    const access = await getZohoAccessToken();
    await updateZohoLeadPaid(access, leadId, {
      product_name: product,
      amount,
      method,
      receipt,
    });
  } catch (e) {
    console.error("onPaymentSucceeded error:", e);
  }
}

async function onPaymentFailed(pi: Stripe.PaymentIntent) {
  try {
    const leadId = pi.metadata?.zoho_lead_id;
    if (!leadId || !hasZoho) return;
    const access = await getZohoAccessToken();
    await markZohoLeadFailed(access, leadId);
  } catch (e) {
    console.error("onPaymentFailed error:", e);
  }
}

/* ================================ Zoho ===================================== */
async function getZohoAccessToken(): Promise<string> {
  const url =
    `${ZOHO_ACCOUNTS_BASE}/oauth/v2/token` +
    `?refresh_token=${encodeURIComponent(ZOHO_REFRESH_TOKEN!)}` +
    `&client_id=${encodeURIComponent(ZOHO_CLIENT_ID!)}` +
    `&client_secret=${encodeURIComponent(ZOHO_CLIENT_SECRET!)}` +
    `&grant_type=refresh_token`;

  const r = await fetch(url, { method: "POST" });
  if (!r.ok) throw new Error(`Zoho token error ${r.status}`);
  const j = (await r.json()) as { access_token?: string };
  if (!j.access_token) throw new Error("No Zoho access token");
  return j.access_token!;
}

async function zohoReq<T = any>(
  accessToken: string,
  method: "GET" | "POST" | "PUT",
  path: string,
  body?: unknown
): Promise<T | null> {
  const r = await fetch(`${ZOHO_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Zoho-oauthtoken ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 204) return null;
  const text = await r.text();
  let data: any;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    const msg = data?.message || data?.data?.[0]?.message || `Zoho ${method} ${path} failed (${r.status})`;
    throw new Error(msg);
  }
  return data as T;
}

async function searchZohoLeadByEmail(accessToken: string, email?: string) {
  if (!email) return null;
  try {
    const r1 = await zohoReq<any>(accessToken, "GET", `/crm/v3/Leads/search?email=${encodeURIComponent(email)}`);
    if (r1?.data?.length) return r1.data[0];
  } catch {}
  const criteria = encodeURIComponent(`(Email:equals:${email})`);
  const r2 = await zohoReq<any>(accessToken, "GET", `/crm/v3/Leads/search?criteria=${criteria}`);
  return r2?.data?.[0] || null;
}

async function updateZohoLead(accessToken: string, id: string, fields: Record<string, any>) {
  const clean: Record<string, any> = {};
  Object.entries(fields).forEach(([k, v]) => { if (v !== undefined && v !== null) clean[k] = v; });
  await zohoReq(accessToken, "PUT", "/crm/v3/Leads", { data: [{ id, ...clean }] });
}

async function createZohoLead(accessToken: string, fields: Record<string, any>): Promise<string> {
  const resp = await zohoReq<any>(accessToken, "POST", "/crm/v3/Leads", { data: [fields] });
  const id = resp?.data?.[0]?.details?.id;
  if (!id) throw new Error("Zoho create lead failed");
  return id;
}

async function addZohoNote(accessToken: string, leadId: string, title: string, content: string) {
  await zohoReq(accessToken, "POST", "/crm/v3/Notes", {
    data: [{ Note_Title: title, Note_Content: content, Parent_Id: leadId, se_module: "Leads" }],
  });
}

async function upsertZohoLead(
  accessToken: string,
  lead: { first_name?: string; last_name?: string; email?: string; phone?: string; claim_type?: string },
  product: string
): Promise<string> {
  const today = new Date().toISOString().slice(0, 10);
  const existing = await searchZohoLeadByEmail(accessToken, lead.email);
  const baseFields = { Product_Name: product, Order_Status: "Pending", Order_Date: today };
  const desc = lead.claim_type ? `Claim Type: ${lead.claim_type}` : "";

  if (existing?.id) {
    await updateZohoLead(accessToken, existing.id, { ...baseFields, Description: desc || existing.Description || "" });
    return existing.id;
  }
  const fields = {
    Company: "VetLetters",
    Last_Name: lead.last_name || lead.email || "Unknown",
    First_Name: lead.first_name || "",
    Email: lead.email,
    Phone: lead.phone || "",
    Description: desc,
    ...baseFields,
  };
  return await createZohoLead(accessToken, fields);
}

async function updateZohoLeadPaid(
  accessToken: string,
  leadId: string,
  info: { product_name: string; amount: number; method: string; receipt: string }
) {
  const today = new Date().toISOString().slice(0, 10);
  const updates: Record<string, any> = {
    Order_Status: "Paid",
    Order_Date: today,
    Product_Name: info.product_name,
  };
  if (ZOHO_FIELD_AMOUNT) updates[ZOHO_FIELD_AMOUNT] = info.amount;
  if (ZOHO_FIELD_PAYMENT_METHOD) updates[ZOHO_FIELD_PAYMENT_METHOD] = info.method;

  await updateZohoLead(accessToken, leadId, updates);

  const note =
    `Payment received.\n` +
    `Method: ${info.method}\n` +
    `Amount: $${info.amount}\n` +
    `Receipt: ${info.receipt || "N/A"}`;
  await addZohoNote(accessToken, leadId, "Stripe Payment", note);
}

async function markZohoLeadFailed(accessToken: string, leadId: string) {
  await updateZohoLead(accessToken, leadId, { Order_Status: "Failed" });
}

/* --------------------------------- Start ---------------------------------- */
app.listen(PORT, () => {
  console.log(`✅ VetLetters API listening on :${PORT}`);
});
