/**
 * /api/vault/[id] — single vault-item endpoint.
 *
 *   GET    → fetch one item the caller owns.
 *   PUT    → replace ciphertext + IV with optimistic-concurrency check.
 *   DELETE → remove the item.
 *
 * Every operation is scoped to the session `userId`. A row owned by another user
 * (or a non-existent id) returns 404 with no distinction, so the API is not an
 * IDOR oracle for which ids exist (CRYPTO.md threat model).
 */
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { getSessionUserId } from '@/lib/server/auth';
import { updateVaultItemSchema } from '@/lib/server/vault-schemas';
import { serializeVaultItem, vaultItemSelect } from '@/lib/server/vault';
import { authLimiter } from '@/lib/server/rateLimit';
import {
  badRequest,
  clientIp,
  notAuthenticated,
  notFound,
  readJson,
  tooManyRequests,
} from '@/lib/server/http';

const idSchema = z.string().uuid();

interface RouteContext {
  params: { id: string };
}

export async function GET(req: NextRequest, { params }: RouteContext): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return notAuthenticated();

  const id = idSchema.safeParse(params.id);
  if (!id.success) return notFound();

  const item = await db.vaultItem.findFirst({
    where: { id: id.data, userId },
    select: vaultItemSelect,
  });
  if (!item) return notFound();

  return NextResponse.json({ item: serializeVaultItem(item) });
}

export async function PUT(req: NextRequest, { params }: RouteContext): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return notAuthenticated();

  const throttle = authLimiter.hit(`vault:write:${clientIp(req)}`);
  if (!throttle.allowed) return tooManyRequests(throttle.retryAfterSeconds);

  const id = idSchema.safeParse(params.id);
  if (!id.success) return notFound();

  const parsed = updateVaultItemSchema.safeParse(await readJson(req));
  if (!parsed.success) return badRequest(parsed.error.issues[0]?.message ?? 'Invalid request.');

  const current = await db.vaultItem.findFirst({
    where: { id: id.data, userId },
    select: { version: true },
  });
  if (!current) return notFound();

  // Optimistic concurrency: refuse if the row moved on since the client read it.
  if (current.version !== parsed.data.expectedVersion) {
    const latest = await db.vaultItem.findFirst({
      where: { id: id.data, userId },
      select: vaultItemSelect,
    });
    return NextResponse.json(
      {
        error: 'This item was modified elsewhere. Reload and reapply your change.',
        item: latest ? serializeVaultItem(latest) : null,
      },
      { status: 409 },
    );
  }

  // Guard the write by version too, so a concurrent update racing this one loses.
  const result = await db.vaultItem.updateMany({
    where: { id: id.data, userId, version: parsed.data.expectedVersion },
    data: {
      ciphertext: Buffer.from(base64ToBytes(parsed.data.ciphertext)),
      iv: Buffer.from(base64ToBytes(parsed.data.iv)),
      version: { increment: 1 },
    },
  });
  if (result.count === 0) return notFound();

  const updated = await db.vaultItem.findFirst({
    where: { id: id.data, userId },
    select: vaultItemSelect,
  });
  if (!updated) return notFound();

  return NextResponse.json({ item: serializeVaultItem(updated) });
}

export async function DELETE(req: NextRequest, { params }: RouteContext): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return notAuthenticated();

  const id = idSchema.safeParse(params.id);
  if (!id.success) return notFound();

  const result = await db.vaultItem.deleteMany({ where: { id: id.data, userId } });
  if (result.count === 0) return notFound();

  return NextResponse.json({ ok: true });
}
