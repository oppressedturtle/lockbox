/**
 * Fixed-window rate limiter (in-memory).
 *
 * Used to throttle and lock out the auth endpoints (CRYPTO.md threat model:
 * online guessing of the auth value). Keys are arbitrary strings — callers
 * compose them from client IP and/or account email so we can limit both a single
 * source hammering many accounts and many sources hammering one account.
 *
 * This is intentionally a small, swappable abstraction: a single-process Map is
 * the right default for LockBox's single-container deploy. A multi-instance
 * deploy would back the same `RateLimiter` interface with Redis/Postgres without
 * touching call sites.
 */

export interface RateLimitResult {
  /** Whether this attempt is permitted. */
  allowed: boolean;
  /** Attempts still allowed in the current window (0 when blocked). */
  remaining: number;
  /** Seconds until the window resets (for a `Retry-After` header). */
  retryAfterSeconds: number;
}

export interface RateLimitOptions {
  /** Max attempts permitted per window. */
  limit: number;
  /** Window length in milliseconds. */
  windowMs: number;
}

interface Bucket {
  count: number;
  /** Epoch ms when the current window resets. */
  resetAt: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly options: RateLimitOptions) {}

  /**
   * Record an attempt against `key` and report whether it is allowed.
   *
   * @param now injectable clock (epoch ms) for deterministic tests.
   */
  hit(key: string, now: number = Date.now()): RateLimitResult {
    const existing = this.buckets.get(key);

    if (!existing || existing.resetAt <= now) {
      const resetAt = now + this.options.windowMs;
      this.buckets.set(key, { count: 1, resetAt });
      return {
        allowed: true,
        remaining: this.options.limit - 1,
        retryAfterSeconds: Math.ceil(this.options.windowMs / 1000),
      };
    }

    existing.count += 1;
    const allowed = existing.count <= this.options.limit;
    return {
      allowed,
      remaining: Math.max(0, this.options.limit - existing.count),
      retryAfterSeconds: Math.max(0, Math.ceil((existing.resetAt - now) / 1000)),
    };
  }

  /** Clear a key's window — e.g. after a successful login. */
  reset(key: string): void {
    this.buckets.delete(key);
  }

  /** Drop expired buckets so the Map can't grow unbounded under churn. */
  prune(now: number = Date.now()): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
  }
}

/**
 * Shared limiters for the auth surface. Module-level singletons so all route
 * handlers in a process see the same counters.
 *
 * - `authLimiter`: per-IP throttle across all auth endpoints (coarse DoS guard).
 * - `loginLimiter`: per-account lockout on failed logins (online-guessing guard).
 */
export const authLimiter = new RateLimiter({ limit: 30, windowMs: 15 * 60 * 1000 });
export const loginLimiter = new RateLimiter({ limit: 8, windowMs: 15 * 60 * 1000 });
