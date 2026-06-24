/**
 * POST /api/auth/register — create a zero-knowledge account.
 *
 * The client has already derived MK → AK locally and sends only:
 *   { email, kdfSalt, authVerifierInput (AK), kdf params }
 * The master password and vault key never leave the browser. The server stores
 * the KDF salt/params (so the client can re-derive at login) plus an Argon2id
 * verifier of AK — never AK itself in the clear (CRYPTO.md §4.3).
 */
import { NextResponse, type NextRequest } from 'next/server';
import { Prisma } from '@/generated/prisma/client';
import { db } from '@/lib/db';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { registerSchema } from '@/lib/server/auth-schemas';
import { hashAuthValue } from '@/lib/server/argon2';
import { authLimiter } from '@/lib/server/rateLimit';
import { attachSession } from '@/lib/server/auth';
import { badRequest, clientIp, readJson, tooManyRequests } from '@/lib/server/http';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const throttle = authLimiter.hit(`register:${clientIp(req)}`);
  if (!throttle.allowed) return tooManyRequests(throttle.retryAfterSeconds);

  const parsed = registerSchema.safeParse(await readJson(req));
  if (!parsed.success) return badRequest(parsed.error.issues[0]?.message ?? 'Invalid request.');

  const { email, kdfSalt, authVerifierInput, kdfMemoryKiB, kdfIterations, kdfParallelism } =
    parsed.data;

  const authVerifier = await hashAuthValue(base64ToBytes(authVerifierInput));

  let userId: string;
  try {
    const user = await db.user.create({
      data: {
        email,
        kdfSalt: Buffer.from(base64ToBytes(kdfSalt)),
        kdfMemoryKiB,
        kdfIterations,
        kdfParallelism,
        authVerifier,
      },
      select: { id: true },
    });
    userId = user.id;
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      return NextResponse.json(
        { error: 'An account with this email already exists.' },
        { status: 409 },
      );
    }
    throw err;
  }

  const res = NextResponse.json({ user: { id: userId, email } }, { status: 201 });
  await attachSession(res, userId);
  return res;
}
