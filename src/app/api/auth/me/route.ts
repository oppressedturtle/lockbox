/**
 * GET /api/auth/me — report the current session's account, if any.
 *
 * Used by the client to decide whether to show the unlock screen or the vault.
 * Returns 401 when there is no valid session. Note: an active session identifies
 * the account but does not unlock the vault — that still requires the master
 * password to re-derive VK in the browser (CRYPTO.md §5).
 */
import { NextResponse, type NextRequest } from 'next/server';
import { db } from '@/lib/db';
import { getSessionUserId } from '@/lib/server/auth';

export async function GET(req: NextRequest): Promise<NextResponse> {
  const userId = await getSessionUserId(req);
  if (!userId) return NextResponse.json({ error: 'Not authenticated.' }, { status: 401 });

  const user = await db.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true },
  });
  if (!user) return NextResponse.json({ error: 'Not authenticated.' }, { status: 401 });

  return NextResponse.json({ user });
}
