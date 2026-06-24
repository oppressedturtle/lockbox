/**
 * POST /api/auth/login — prove knowledge of AK and open a session.
 *
 * The client re-derived MK → AK from the master password + the salt it fetched
 * from /salt, and sends AK as `authVerifierInput`. The server checks it against
 * the stored Argon2id verifier. On success it issues a signed session cookie;
 * the vault key VK is re-derived in the browser and never touches the server.
 *
 * Hardening: per-IP throttle + per-account lockout (online-guessing guard), and
 * an Argon2id "spend" on the unknown-email branch so timing can't distinguish a
 * missing account from a wrong password. Every failure returns an identical 401.
 */
import { NextResponse, type NextRequest } from 'next/server';
import { db } from '@/lib/db';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { loginSchema } from '@/lib/server/auth-schemas';
import { spendVerifyTime, verifyAuthValue } from '@/lib/server/argon2';
import { authLimiter, loginLimiter } from '@/lib/server/rateLimit';
import { attachSession } from '@/lib/server/auth';
import { badRequest, clientIp, readJson, tooManyRequests, unauthorized } from '@/lib/server/http';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const ipThrottle = authLimiter.hit(`login:${clientIp(req)}`);
  if (!ipThrottle.allowed) return tooManyRequests(ipThrottle.retryAfterSeconds);

  const parsed = loginSchema.safeParse(await readJson(req));
  if (!parsed.success) return badRequest(parsed.error.issues[0]?.message ?? 'Invalid request.');

  const { email, authVerifierInput } = parsed.data;

  // Per-account lockout: counts every attempt, reset on success below.
  const lockout = loginLimiter.hit(`login:${email}`);
  if (!lockout.allowed) return tooManyRequests(lockout.retryAfterSeconds);

  const authValue = base64ToBytes(authVerifierInput);
  const user = await db.user.findUnique({
    where: { email },
    select: { id: true, authVerifier: true },
  });

  const ok = user
    ? await verifyAuthValue(user.authVerifier, authValue)
    : await spendVerifyTime(authValue);

  if (!ok || !user) return unauthorized();

  loginLimiter.reset(`login:${email}`);
  const res = NextResponse.json({ user: { id: user.id, email } });
  await attachSession(res, user.id);
  return res;
}
