// src/server.ts
import express, { Request, Response, NextFunction } from "express";
import Stripe from "stripe";
import https from "https";
import * as dns from "node:dns/promises";
import { URL } from "node:url";

/* ============================ Config & Setup ============================ */

const PORT: number = Number(process.env.PORT || 3000);

// Stripe (required)
const STRIPE_SECRET_KEY: string | undefined = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) throw new Error("Missing STRIPE_SECRET_KEY");

// TLS/HTTP client tuning (helps avoid transient network issues on some hosts)
const agent = new https.Agent({
  keepAlive: true,
  family: 4, // prefer IPv4
  // uncomment to force TLS 1.2 if your platform has TLS handshake quirks
  // secureProtocol: "TLSv1_2_method",
});
// Choose Node or Fetch HTTP client (toggle by env if needed)
const httpClient =
  process.env.STRIPE_HTTP_CLIENT === "fetch"
    ? Stripe.createFetchHttpClient()
    : Stripe.createNodeHttpClient(agent);

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
  httpClient,
  maxNetworkRetries: 2,
  timeout: 30000,
});
const STRIPE_WEBHOOK_SECRET: string | undefined = process.env.STRIPE_WEBHOOK_SECRET;

// Zoho (optional; CRM is skipped if any are missing)
const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID;
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET;
const ZOHO_REFRESH_TOKEN = process.env.ZOHO_REFRESH_TOKEN;
const ZOHO_API_BASE: string = process.env.ZOHO_API_BASE || "https://www.zohoapis.com";
const ZOHO_ACCOUNTS_BASE: string = process.env.ZOHO_ACCOUNTS_BASE || "https://accounts.zoho.com";
const ZOHO_FIELD_AMOUNT: string | undefined = process.env.ZOHO_FIELD_AMOUNT; // e.g. "Amount"
const ZOHO_FIELD_PAYMENT_METHOD: string | undefined = process.env.ZOHO_FIELD_PAYMENT_METHOD; // e.g. "Payment_Method"
const HAS_ZOHO: boolean = !!(ZOHO_CLIENT_ID && ZOHO_CLIENT_SECRET && ZOHO_REFRESH_TOKEN);

type Lead = {
  first_name?: string;
  last_name?: string;
  email: string;
  phone?: string;
  claim_type?: string;
};

const app = express();

/* =============================== CORS =================================== */

const ALLOW: string[] = [
  "https://www.vetletters.com",
  "https://vetletters.com",
  ".zohositescontent.com", // suffix match for Zoho Sites assets
];

app.use((req: Request, res: Response, next: NextFunction): void => {
  const origin = String(req.headers.origin || "");
  const allowed = ALLOW.some((a) => (a.startsWith(".") ? origin.endsWith(a) : origin === a));
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Stripe-Signature");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  if (req.method === "OPTIONS") {
    res.sendStatus(200);
    return;
  }
  next();
});

/* ============================ Stripe Webhook ============================ */
// MUST be before any JSON middleware.
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req: Request, res: Response): Promise<void> => {
    if (!STRIPE_WEBHOOK_SECRET) {
      res.status(500).send("Webhook secret not set");
      return;
    }
    try {
      const sig = String(req.headers["stripe-signature"] || "");
      const event = stripe.webhooks.constructEvent(
        (req as unknown as { body: Buffer }).body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );

      if (event.type === "payment_intent.succeeded") {
        await onPaymentSucceeded(event.data.object as Stripe.PaymentIntent);
      } else if (event.type === "payment_intent.payment_failed") {
        await onPaymentFailed(event.data.object as Stripe.PaymentIntent);
      }

      res.json({ received: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("Webhook error:", msg);
      res.status(400).send(`Webhook Error: ${msg}`);
    }
  }
);

/* ============================ JSON for /api ============================= */
app.use("/api", express.json());

/* ============================ Diagnostics =============================== */
// Basic Stripe account reachability (uses your current STRIPE_SECRET_KEY)
app.get("/api/diag/stripe", async (_req: Request, res: Response) => {
  try {
    const acct = await stripe.accounts.retrieve();
    res.json({ ok: true, account: acct.id });
  } catch (e: any) {
    res.status(500).json({
      ok: false,
      type: e?.type,
      code: e?.code,
      message: e?.message,
      statusCode: e?.statusCode,
      requestId: e?.requestId,
    });
  }
});

// Network probe: DNS + raw HTTPS to Stripe and Google (no auth)
app.get("/api/diag/net", async (_req: Request, res: Response) => {
  const results: any = { dns: {}, https: {} };
  try {
    results.dns.api_stripe = await dns.lookup("api.stripe.com", { all: true });
  } catch (e: any) {
    results.dns.api_stripe = { error: e?.message || String(e) };
  }
  try {
    results.https.stripe = await rawHttpsGet("https://api.stripe.com/v1/charges", agent);
  } catch (e: any) {
    results.https.stripe = { error: e?.message || String(e) };
  }
  try {
    results.https.google = await rawHttpsGet("https://www.google.com/generate_204", agent);
  } catch (e: any) {
    results.https.google = { error: e?.message || String(e) };
  }
  res.json(results);
});

async function rawHttpsGet(urlStr: string, ag: https.Agent): Promise<{ ok: boolean; status?: number; error?: string }> {
  const url = new URL(urlStr);
  return new Promise((resolve) => {
    const req = https.request(
      {
        method: "GET",
        protocol: url.protocol,
        hostname: url.hostname,
        path: url.pathname + url.search,
        agent: ag,
        timeout: 15000,
      },
      (resp) => {
        // We expect 401 from Stripe when unauthenticated; that's still a successful TCP/TLS connection.
        resolve({ ok: true, status: resp.statusCode ?? 0 });
        resp.resume(); // drain
      }
    );
    req.on("error", (err) => resolve({ ok: false, error: err.message }));
    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });
    req.end();
  });
}

/* ====================== Create PaymentIntent API ======================= */
/**
 * POST /api/create-payment-intent
 * Body: { amount: number, currency?: 'usd', product?: string, lead: Lead }
 */
app.post("/api/create-payment-intent", async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      amount,
      currency = "usd",
      product = "VetLetters",
      lead = {},
    }: {
      amount?: number;
      currency?: string;
      product?: string;
      lead?: Partial<Lead>;
    } = (req.body ?? {}) as Record<string, unknown> as any;

    if (!amount || !lead?.email) {
      res.status(400).json({ error: "Missing amount or lead.email" });
      return;
    }

    // Upsert Zoho lead (optional)
    let zohoLeadId = "";
    if (HAS_ZOHO) {
      try {
        const access = await getZohoAccessToken();
        zohoLeadId = await upsertZohoLead(access, lead as Lead, product);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn("Zoho upsert skipped:", msg);
      }
    }

    // Create PI with dynamic methods (card/Klarna/Affirm when eligible)
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
    res.status(400).json({
      error: err?.message || "Unable to create payment",
      stripe: { type: err?.type, code: err?.code, requestId: err?.requestId },
    });
  }
});

/* =============================== Healthcheck ============================== */
app.get("/", (_req: Request, res: Response): void => {
  res.type("text").send("VetLetters API OK");
});

/* =========================== Stripe Helpers ============================== */

async function getLatestCharge(pi: Stripe.PaymentIntent): Promise<Stripe.Charge | null> {
  try {
    if (!pi.latest_charge) return null;

    if (typeof pi.latest_charge === "string") {
      const ch = (await stripe.charges.retrieve(pi.latest_charge)) as unknown as Stripe.Charge;
      return ch;
    }
    return pi.latest_charge as Stripe.Charge;
  } catch {
    try {
      const full = await stripe.paymentIntents.retrieve(pi.id, { expand: ["latest_charge"] });
      if (!full.latest_charge) return null;
      if (typeof full.latest_charge === "string") {
        const ch = (await stripe.charges.retrieve(full.latest_charge)) as unknown as Stripe.Charge;
        return ch;
      }
      return full.latest_charge as Stripe.Charge;
    } catch {
      return null;
    }
  }
}

async function onPaymentSucceeded(pi: Stripe.PaymentIntent): Promise<void> {
  try {
    const leadId = pi.metadata?.zoho_lead_id;
    if (!leadId || !HAS_ZOHO) return;

    const charge = await getLatestCharge(pi);
    const method: string =
      (charge as unknown as { payment_method_details?: { type?: string } })?.payment_method_details?.type || "unknown";
    const amount: number = (pi.amount_received || pi.amount) / 100;
    const receipt: string = (charge as unknown as { receipt_url?: string })?.receipt_url || "";
    const product: string = pi.metadata?.product_name || "";

    const access = await getZohoAccessToken();
    await updateZohoLeadPaid(access, leadId, {
      product_name: product,
      amount,
      method,
      receipt,
    });
  } catch (e: unknown) {
    console.error("onPaymentSucceeded error:", e instanceof Error ? e.message : String(e));
  }
}

async function onPaymentFailed(pi: Stripe.PaymentIntent): Promise<void> {
  try {
    const leadId = pi.metadata?.zoho_lead_id;
    if (!leadId || !HAS_ZOHO) return;
    const access = await getZohoAccessToken();
    await markZohoLeadFailed(access, leadId);
  } catch (e: unknown) {
    console.error("onPaymentFailed error:", e instanceof Error ? e.message : String(e));
  }
}

/* ============================= Zoho Helpers ============================== */

async function getZohoAccessToken(): Promise<string> {
  if (!HAS_ZOHO) throw new Error("Zoho credentials missing");

  const params = new URLSearchParams();
  params.set("refresh_token", ZOHO_REFRESH_TOKEN as string);
  params.set("client_id", ZOHO_CLIENT_ID as string);
  params.set("client_secret", ZOHO_CLIENT_SECRET as string);
  params.set("grant_type", "refresh_token");

  const r = await fetch(`${ZOHO_ACCOUNTS_BASE}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!r.ok) throw new Error(`Zoho token error ${r.status}`);
  const j = (await r.json()) as unknown as { access_token?: string };
  if (!j.access_token) throw new Error("No Zoho access token");
  return j.access_token;
}

async function zohoReq<T = unknown>(
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

  let data: unknown;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!r.ok) {
    const msg =
      (data as any)?.message ||
      (data as any)?.data?.[0]?.message ||
      `Zoho ${method} ${path} failed (${r.status})`;
    throw new Error(String(msg));
  }
  return data as T;
}

async function searchZohoLeadByEmail(accessToken: string, email: string): Promise<any | null> {
  // Try direct email search
  try {
    const r1 = await zohoReq<any>(
      accessToken,
      "GET",
      `/crm/v3/Leads/search?email=${encodeURIComponent(email)}`
    );
    if (r1?.data?.length) return r1.data[0];
  } catch {
    // ignore; try criteria below
  }

  const criteria = encodeURIComponent(`(Email:equals:${email})`);
  const r2 = await zohoReq<any>(
    accessToken,
    "GET",
    `/crm/v3/Leads/search?criteria=${criteria}`
  );
  return r2?.data?.[0] || null;
}

async function updateZohoLead(
  accessToken: string,
  id: string,
  fields: Record<string, unknown>
): Promise<void> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== "undefined" && v !== null) clean[k] = v;
  }
  await zohoReq(
    accessToken,
    "PUT",
    "/crm/v3/Leads",
    { data: [{ id, ...clean }] }
  );
}

async function createZohoLead(
  accessToken: string,
  leadFields: Record<string, unknown>
): Promise<string> {
  const resp = await zohoReq<any>(
    accessToken,
    "POST",
    "/crm/v3/Leads",
    { data: [leadFields] }
  );
  const id: string | undefined = resp?.data?.[0]?.details?.id;
  if (!id) throw new Error("Zoho create lead failed");
  return id;
}

async function addZohoNote(
  accessToken: string,
  leadId: string,
  title: string,
  content: string
): Promise<void> {
  await zohoReq(accessToken, "POST", "/crm/v3/Notes", {
    data: [
      {
        Note_Title: title,
        Note_Content: content,
        Parent_Id: leadId,
        se_module: "Leads",
      },
    ],
  });
}

async function upsertZohoLead(
  accessToken: string,
  lead: Lead,
  product: string
): Promise<string> {
  const today = new Date().toISOString().slice(0, 10);
  const existing = await searchZohoLeadByEmail(accessToken, lead.email);

  const baseFields = {
    Product_Name: product,
    Order_Status: "Pending",
    Order_Date: today,
  };
  const desc = lead.claim_type ? `Claim Type: ${lead.claim_type}` : "";

  if (existing?.id) {
    await updateZohoLead(accessToken, existing.id, {
      ...baseFields,
      Description: desc || existing.Description || "",
    });
    return String(existing.id);
  }

  // Zoho Leads often require Company + Last_Name
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
): Promise<void> {
  const today = new Date().toISOString().slice(0, 10);

  const updates: Record<string, unknown> = {
    Order_Status: "Paid",
    Order_Date: today,
    Product_Name: info.product_name,
  };
  if (ZOHO_FIELD_AMOUNT) (updates as any)[ZOHO_FIELD_AMOUNT] = info.amount;
  if (ZOHO_FIELD_PAYMENT_METHOD) (updates as any)[ZOHO_FIELD_PAYMENT_METHOD] = info.method;

  await updateZohoLead(accessToken, leadId, updates);

  const note =
    `Payment received.\n` +
    `Method: ${info.method}\n` +
    `Amount: $${info.amount}\n` +
    `Receipt: ${info.receipt || "N/A"}`;

  await addZohoNote(accessToken, leadId, "Stripe Payment", note);
}

async function markZohoLeadFailed(accessToken: string, leadId: string): Promise<void> {
  await updateZohoLead(accessToken, leadId, { Order_Status: "Failed" });
}

/* ================================ Start =================================== */

app.listen(PORT, (): void => {
  console.log(`✅ VetLetters API listening on :${PORT}`);
});
