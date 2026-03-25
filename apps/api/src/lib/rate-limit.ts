import type { Context, Next } from "hono";

interface Bucket {
  tokens: number;
  lastRefill: number;
}

interface RateLimitOptions {
  /** Time window in milliseconds */
  windowMs: number;
  /** Maximum requests per window */
  max: number;
}

class TokenBucketStore {
  private buckets = new Map<string, Bucket>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(private windowMs: number) {
    // Clean up stale entries every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
    // Prevent the interval from keeping the process alive
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  consume(key: string, max: number): { allowed: boolean; retryAfter: number } {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: max, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = (elapsed / this.windowMs) * max;
    bucket.tokens = Math.min(max, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, retryAfter: 0 };
    }

    // Denied — calculate retry time
    const retryAfter = Math.ceil(((1 - bucket.tokens) / max) * this.windowMs / 1000);
    return { allowed: false, retryAfter };
  }

  private cleanup() {
    const cutoff = Date.now() - this.windowMs * 2;
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastRefill < cutoff) {
        this.buckets.delete(key);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
  }
}

function getClientIp(c: Context): string {
  return (
    c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
    c.req.header("cf-connecting-ip") ??
    c.req.header("x-real-ip") ??
    "unknown"
  );
}

/**
 * Rate limit by client IP address. Use for public endpoints.
 */
export function rateLimitByIp(opts: RateLimitOptions) {
  const store = new TokenBucketStore(opts.windowMs);

  return async (c: Context, next: Next) => {
    const key = `ip:${getClientIp(c)}`;
    const { allowed, retryAfter } = store.consume(key, opts.max);

    if (!allowed) {
      c.header("Retry-After", String(retryAfter));
      return c.json({ error: "Rate limit exceeded", retryAfter }, 429);
    }

    await next();
  };
}

/**
 * Rate limit by authenticated org ID, falling back to IP.
 * Use for auth-required endpoints.
 */
export function rateLimitByAuth(opts: RateLimitOptions) {
  const store = new TokenBucketStore(opts.windowMs);

  return async (c: Context, next: Next) => {
    const auth = c.get("auth") as { orgId?: string } | null;
    const key = auth?.orgId ? `org:${auth.orgId}` : `ip:${getClientIp(c)}`;
    const { allowed, retryAfter } = store.consume(key, opts.max);

    if (!allowed) {
      c.header("Retry-After", String(retryAfter));
      return c.json({ error: "Rate limit exceeded", retryAfter }, 429);
    }

    await next();
  };
}
