import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface StripeConfig {
  secretKey: string;
  webhookSecret: string;
  publishableKey: string;
  prices: Record<string, string>; // plan name -> Stripe price ID
}

// ---------------------------------------------------------------------------
// Stripe API helpers (native fetch, no SDK)
// ---------------------------------------------------------------------------

const STRIPE_API = "https://api.stripe.com/v1";

function authHeader(secretKey: string): string {
  return `Basic ${Buffer.from(`${secretKey}:`).toString("base64")}`;
}

function encodeFormBody(params: Record<string, string | undefined>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  }
  return parts.join("&");
}

async function stripePost<T>(
  secretKey: string,
  path: string,
  params: Record<string, string | undefined>
): Promise<T> {
  const response = await fetch(`${STRIPE_API}${path}`, {
    method: "POST",
    headers: {
      Authorization: authHeader(secretKey),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: encodeFormBody(params),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Stripe API error (${response.status}) on POST ${path}: ${errorBody}`
    );
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Webhook signature verification (Stripe v1 scheme)
// ---------------------------------------------------------------------------

interface StripeWebhookHeader {
  timestamp: string;
  signatures: string[];
}

function parseSignatureHeader(header: string): StripeWebhookHeader {
  const parts = header.split(",");
  let timestamp = "";
  const signatures: string[] = [];

  for (const part of parts) {
    const [key, value] = part.split("=", 2);
    if (key === "t") {
      timestamp = value;
    } else if (key === "v1") {
      signatures.push(value);
    }
  }

  if (!timestamp || signatures.length === 0) {
    throw new Error("Invalid Stripe webhook signature header");
  }

  return { timestamp, signatures };
}

const WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutes

function verifySignature(
  payload: string,
  header: string,
  secret: string
): void {
  const { timestamp, signatures } = parseSignatureHeader(header);

  const timestampNum = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestampNum) > WEBHOOK_TOLERANCE_SECONDS) {
    throw new Error("Webhook timestamp is outside the tolerance zone");
  }

  const signedPayload = `${timestamp}.${payload}`;
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("hex");

  const isValid = signatures.some((sig) =>
    crypto.timingSafeEqual(
      Buffer.from(expectedSignature, "hex"),
      Buffer.from(sig, "hex")
    )
  );

  if (!isValid) {
    throw new Error("Webhook signature verification failed");
  }
}

// ---------------------------------------------------------------------------
// Stripe event types (minimal)
// ---------------------------------------------------------------------------

export interface StripeEvent {
  id: string;
  type: string;
  data: {
    object: Record<string, unknown>;
  };
}

// ---------------------------------------------------------------------------
// Repository interface (subset needed for webhook processing)
// ---------------------------------------------------------------------------

interface BillingRepository {
  upsertSubscription(
    orgId: string,
    input: {
      plan: string;
      status: string;
      customerId?: string;
      subscriptionId?: string;
      currentPeriodEnd?: string;
      cancelAtPeriodEnd?: boolean;
    }
  ): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Checkout session
// ---------------------------------------------------------------------------

export interface CreateCheckoutParams {
  orgId: string;
  plan: string;
  customerEmail?: string;
  successUrl: string;
  cancelUrl: string;
}

interface StripeCheckoutSession {
  id: string;
  url: string;
}

export async function createCheckoutSession(
  config: StripeConfig,
  params: CreateCheckoutParams
): Promise<{ sessionId: string; url: string }> {
  const priceId = config.prices[params.plan];
  if (!priceId) {
    throw new Error(`Unknown plan: ${params.plan}`);
  }

  const body: Record<string, string | undefined> = {
    mode: "subscription",
    "line_items[0][price]": priceId,
    "line_items[0][quantity]": "1",
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    "metadata[orgId]": params.orgId,
    "metadata[plan]": params.plan,
    customer_email: params.customerEmail,
    "subscription_data[metadata][orgId]": params.orgId,
    "subscription_data[metadata][plan]": params.plan,
  };

  const session = await stripePost<StripeCheckoutSession>(
    config.secretKey,
    "/checkout/sessions",
    body
  );

  return { sessionId: session.id, url: session.url };
}

// ---------------------------------------------------------------------------
// Construct webhook event (verify + parse)
// ---------------------------------------------------------------------------

export function constructWebhookEvent(
  config: StripeConfig,
  payload: string,
  signature: string
): StripeEvent {
  verifySignature(payload, signature, config.webhookSecret);
  const event = JSON.parse(payload) as StripeEvent;

  if (!event.id || !event.type || !event.data?.object) {
    throw new Error("Invalid Stripe event payload");
  }

  return event;
}

// ---------------------------------------------------------------------------
// Webhook event handlers
// ---------------------------------------------------------------------------

function resolvePlanFromMetadata(
  metadata: Record<string, unknown> | undefined
): string {
  return (metadata?.plan as string) ?? "free";
}

function resolveOrgId(
  metadata: Record<string, unknown> | undefined
): string | null {
  return (metadata?.orgId as string) ?? null;
}

export async function handleWebhookEvent(
  event: StripeEvent,
  repository: BillingRepository
): Promise<{ handled: boolean; orgId?: string }> {
  const obj = event.data.object;

  switch (event.type) {
    case "checkout.session.completed": {
      const orgId = resolveOrgId(obj.metadata as Record<string, unknown>);
      if (!orgId) {
        return { handled: false };
      }

      const subscription = obj.subscription as string | undefined;
      const customer = obj.customer as string | undefined;
      const plan = resolvePlanFromMetadata(
        obj.metadata as Record<string, unknown>
      );

      await repository.upsertSubscription(orgId, {
        plan,
        status: "active",
        customerId: customer,
        subscriptionId: subscription,
      });

      return { handled: true, orgId };
    }

    case "customer.subscription.updated": {
      const metadata = obj.metadata as Record<string, unknown> | undefined;
      const orgId = resolveOrgId(metadata);
      if (!orgId) {
        return { handled: false };
      }

      const stripeStatus = obj.status as string;
      const plan = resolvePlanFromMetadata(metadata);
      const cancelAtPeriodEnd = obj.cancel_at_period_end as boolean | undefined;
      const currentPeriodEnd = obj.current_period_end as number | undefined;

      // Map Stripe statuses to our SubscriptionStatus
      const statusMap: Record<string, string> = {
        active: "active",
        trialing: "trialing",
        past_due: "past_due",
        canceled: "canceled",
        incomplete: "incomplete",
        incomplete_expired: "canceled",
        unpaid: "past_due",
        paused: "past_due",
      };

      await repository.upsertSubscription(orgId, {
        plan,
        status: statusMap[stripeStatus] ?? "active",
        subscriptionId: obj.id as string,
        customerId: obj.customer as string,
        currentPeriodEnd: currentPeriodEnd
          ? new Date(currentPeriodEnd * 1000).toISOString()
          : undefined,
        cancelAtPeriodEnd: cancelAtPeriodEnd ?? false,
      });

      return { handled: true, orgId };
    }

    case "customer.subscription.deleted": {
      const metadata = obj.metadata as Record<string, unknown> | undefined;
      const orgId = resolveOrgId(metadata);
      if (!orgId) {
        return { handled: false };
      }

      await repository.upsertSubscription(orgId, {
        plan: "free",
        status: "canceled",
        subscriptionId: obj.id as string,
        customerId: obj.customer as string,
        cancelAtPeriodEnd: false,
      });

      return { handled: true, orgId };
    }

    case "invoice.payment_failed": {
      const subscriptionId = obj.subscription as string | undefined;
      const metadata = obj.subscription_details as
        | Record<string, unknown>
        | undefined;
      const subMetadata = metadata?.metadata as
        | Record<string, unknown>
        | undefined;
      const orgId = resolveOrgId(subMetadata);

      if (!orgId) {
        return { handled: false };
      }

      const plan = resolvePlanFromMetadata(subMetadata);

      await repository.upsertSubscription(orgId, {
        plan,
        status: "past_due",
        subscriptionId,
        customerId: obj.customer as string,
      });

      return { handled: true, orgId };
    }

    default:
      return { handled: false };
  }
}

// ---------------------------------------------------------------------------
// Billing portal session
// ---------------------------------------------------------------------------

interface StripePortalSession {
  id: string;
  url: string;
}

export async function createPortalSession(
  config: StripeConfig,
  customerId: string,
  returnUrl?: string
): Promise<{ url: string }> {
  const session = await stripePost<StripePortalSession>(
    config.secretKey,
    "/billing_portal/sessions",
    {
      customer: customerId,
      return_url: returnUrl,
    }
  );

  return { url: session.url };
}
