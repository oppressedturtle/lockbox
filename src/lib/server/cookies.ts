/**
 * Session cookie wiring.
 *
 * The session token lives in an httpOnly, SameSite=Strict cookie so it is never
 * readable by JavaScript (XSS containment — critical for a secrets app) and is
 * not sent on cross-site requests (CSRF containment). `Secure` is enabled
 * outside development so the cookie only travels over HTTPS in production.
 */
import type { NextResponse } from 'next/server';
import { getEnv } from '@/lib/env';

export const SESSION_COOKIE = 'lockbox_session';

function baseCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict' as const,
    secure: getEnv().NODE_ENV === 'production',
    path: '/',
  };
}

/** Attach the session token to a response with a matching max-age. */
export function setSessionCookie(res: NextResponse, token: string, expiresAt: number): void {
  const maxAgeSeconds = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  res.cookies.set({
    name: SESSION_COOKIE,
    value: token,
    ...baseCookieOptions(),
    maxAge: maxAgeSeconds,
  });
}

/** Expire the session cookie (logout). */
export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set({
    name: SESSION_COOKIE,
    value: '',
    ...baseCookieOptions(),
    maxAge: 0,
  });
}
