/**
 * /api/vault — collection endpoint for the authenticated user's vault items.
 *
 *   GET  → list all of the caller's items (ciphertext + IV), newest first.
 *   POST → create a new item from client-encrypted ciphertext + IV.
 *
 * Zero-knowledge: the server stores and returns only opaque ciphertext (CRYPTO.md
 * §4.1). Every query is scoped to the session's `userId`, so one account can
 * never see or touch another's rows.
 */
import { NextResponse, type NextRequest } from 'next/server';
import { db } from '@/lib/db';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { getSessionUserId } from '@/lib/server/auth';
import { createVaultItemSchema } from '@/lib/server/vault-schemas';
import { serializeVaultItem, vaultItemSelect } from '@/lib/server/vault';
import { authLimiter } from '@/lib/server/rateLimit';
import {
  badRequest,
  clientIp,
  notAuthenticated,
  readJson,
  tooManyRequests,
} from '@/lib/server/http';

export async function GET(req: NextRequest): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return notAuthenticated();

  const items = await db.vaultItem.findMany({
    where: { userId },
    orderBy: { updatedAt: 'desc' },
    select: vaultItemSelect,
  });

  return NextResponse.json({ items: items.map(serializeVaultItem) });
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return notAuthenticated();

  const throttle = authLimiter.hit(`vault:write:${clientIp(req)}`);
  if (!throttle.allowed) return tooManyRequests(throttle.retryAfterSeconds);

  const parsed = createVaultItemSchema.safeParse(await readJson(req));
  if (!parsed.success) return badRequest(parsed.error.issues[0]?.message ?? 'Invalid request.');

  const item = await db.vaultItem.create({
    data: {
      userId,
      ciphertext: Buffer.from(base64ToBytes(parsed.data.ciphertext)),
      iv: Buffer.from(base64ToBytes(parsed.data.iv)),
    },
    select: vaultItemSelect,
  });

  return NextResponse.json({ item: serializeVaultItem(item) }, { status: 201 });
}
