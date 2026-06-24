/**
 * Session glue between requests, the token signer, and the cookie.
 */
import type { NextRequest, NextResponse } from 'next/server';
import { getEnv } from '@/lib/env';
import { createSessionToken, verifySessionToken } from './session';
import { SESSION_COOKIE, setSessionCookie } from './cookies';

/** Issue a fresh session token for `userId` and attach it to the response. */
export async function attachSession(res: NextResponse, userId: string): Promise<void> {
  const secret = getEnv().SESSION_SECRET;
  const token = await createSessionToken(userId, secret);
  const payload = await verifySessionToken(token, secret);
  // payload is always present for a token we just minted; guard for type-safety.
  setSessionCookie(res, token, payload?.expiresAt ?? Date.now());
}

/** Resolve the authenticated user id from the session cookie, or `null`. */
export async function getSessionUserId(req: NextRequest): Promise<string | null> {
  const token = req.cookies.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  const payload = await verifySessionToken(token, getEnv().SESSION_SECRET);
  return payload?.userId ?? null;
}
