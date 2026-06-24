/**
 * Small HTTP helpers shared by the auth route handlers.
 */
import { NextResponse, type NextRequest } from 'next/server';

/**
 * Best-effort client IP for rate-limit keying.
 *
 * Behind the production reverse proxy / platform load balancer the real client
 * is in `x-forwarded-for` (first hop). We fall back to `x-real-ip` and finally a
 * sentinel so a missing header degrades to a shared bucket rather than throwing.
 */
export function clientIp(req: NextRequest): string {
  const xff = req.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.headers.get('x-real-ip')?.trim() || 'unknown';
}

/** JSON 429 with a `Retry-After` header. */
export function tooManyRequests(retryAfterSeconds: number): NextResponse {
  return NextResponse.json(
    { error: 'Too many requests. Please slow down and try again later.' },
    { status: 429, headers: { 'Retry-After': String(Math.max(0, retryAfterSeconds)) } },
  );
}

/** JSON 400 for malformed/invalid request bodies (no internals leaked). */
export function badRequest(message = 'Invalid request.'): NextResponse {
  return NextResponse.json({ error: message }, { status: 400 });
}

/** Uniform 401 — used for every "bad credentials" path to avoid enumeration. */
export function unauthorized(message = 'Invalid email or password.'): NextResponse {
  return NextResponse.json({ error: message }, { status: 401 });
}

/** Parse a JSON body, returning `null` (not throwing) on malformed input. */
export async function readJson(req: NextRequest): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    return null;
  }
}
