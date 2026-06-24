import { describe, expect, it } from 'vitest';
import { RateLimiter } from './rateLimit';

describe('RateLimiter (fixed window)', () => {
  it('allows up to the limit then blocks within a window', () => {
    const rl = new RateLimiter({ limit: 3, windowMs: 1000 });
    const t = 10_000;
    expect(rl.hit('k', t).allowed).toBe(true);
    expect(rl.hit('k', t).allowed).toBe(true);
    const third = rl.hit('k', t);
    expect(third.allowed).toBe(true);
    expect(third.remaining).toBe(0);
    const fourth = rl.hit('k', t);
    expect(fourth.allowed).toBe(false);
    expect(fourth.retryAfterSeconds).toBe(1);
  });

  it('resets after the window elapses', () => {
    const rl = new RateLimiter({ limit: 1, windowMs: 1000 });
    expect(rl.hit('k', 0).allowed).toBe(true);
    expect(rl.hit('k', 500).allowed).toBe(false);
    expect(rl.hit('k', 1000).allowed).toBe(true);
  });

  it('tracks keys independently', () => {
    const rl = new RateLimiter({ limit: 1, windowMs: 1000 });
    expect(rl.hit('a', 0).allowed).toBe(true);
    expect(rl.hit('b', 0).allowed).toBe(true);
    expect(rl.hit('a', 0).allowed).toBe(false);
  });

  it('reset() clears a key', () => {
    const rl = new RateLimiter({ limit: 1, windowMs: 1000 });
    expect(rl.hit('k', 0).allowed).toBe(true);
    expect(rl.hit('k', 0).allowed).toBe(false);
    rl.reset('k');
    expect(rl.hit('k', 0).allowed).toBe(true);
  });

  it('prune() drops only expired buckets', () => {
    const rl = new RateLimiter({ limit: 1, windowMs: 1000 });
    rl.hit('old', 0);
    rl.hit('fresh', 900);
    rl.prune(1000);
    // 'old' window (resetAt 1000) is expired and pruned → fresh allowance again.
    expect(rl.hit('old', 1000).allowed).toBe(true);
    // 'fresh' (resetAt 1900) still active → already at limit.
    expect(rl.hit('fresh', 1000).allowed).toBe(false);
  });
});
