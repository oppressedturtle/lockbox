/**
 * POST /api/auth/salt — return the KDF salt + params for an email.
 *
 * The client needs the per-user salt and Argon2id params to re-derive MK at
 * login. To prevent account enumeration, an *unknown* email gets a deterministic
 * decoy salt with the default params, indistinguishable from a real account
 * (CRYPTO.md §2.2). The actual pass/fail is decided later, uniformly, at /login.
 */
import { NextResponse, type NextRequest } from 'next/server';
import { db } from '@/lib/db';
import { bytesToBase64 } from '@/lib/crypto/encoding';
import { DEFAULT_ARGON2_PARAMS } from '@/lib/crypto/kdf';
import { getEnv } from '@/lib/env';
import { saltSchema } from '@/lib/server/auth-schemas';
import { deriveDecoySalt } from '@/lib/server/decoy';
import { authLimiter } from '@/lib/server/rateLimit';
import { badRequest, clientIp, readJson, tooManyRequests } from '@/lib/server/http';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const throttle = authLimiter.hit(`salt:${clientIp(req)}`);
  if (!throttle.allowed) return tooManyRequests(throttle.retryAfterSeconds);

  const parsed = saltSchema.safeParse(await readJson(req));
  if (!parsed.success) return badRequest(parsed.error.issues[0]?.message ?? 'Invalid request.');

  const { email } = parsed.data;
  const user = await db.user.findUnique({
    where: { email },
    select: { kdfSalt: true, kdfMemoryKiB: true, kdfIterations: true, kdfParallelism: true },
  });

  if (user) {
    return NextResponse.json({
      kdfSalt: bytesToBase64(new Uint8Array(user.kdfSalt)),
      kdfMemoryKiB: user.kdfMemoryKiB,
      kdfIterations: user.kdfIterations,
      kdfParallelism: user.kdfParallelism,
    });
  }

  const decoy = await deriveDecoySalt(email, getEnv().SESSION_SECRET);
  return NextResponse.json({
    kdfSalt: bytesToBase64(decoy),
    kdfMemoryKiB: DEFAULT_ARGON2_PARAMS.memorySizeKiB,
    kdfIterations: DEFAULT_ARGON2_PARAMS.iterations,
    kdfParallelism: DEFAULT_ARGON2_PARAMS.parallelism,
  });
}
