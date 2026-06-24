/**
 * POST /api/auth/logout — clear the session cookie.
 *
 * Stateless tokens have no server record to revoke, so logout simply expires the
 * cookie. (Short token TTL + client-side vault auto-lock bound the blast radius
 * of a leaked token — CRYPTO.md §5.)
 */
import { NextResponse } from 'next/server';
import { clearSessionCookie } from '@/lib/server/cookies';

export async function POST(): Promise<NextResponse> {
  const res = NextResponse.json({ ok: true });
  clearSessionCookie(res);
  return res;
}
