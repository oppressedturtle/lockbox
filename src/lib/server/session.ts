/**
 * Stateless, HMAC-signed session tokens (CRYPTO.md §5).
 *
 * A token authenticates the *account* only — it carries a user id and an expiry,
 * signed with HMAC-SHA256 under the server secret. It deliberately carries no key
 * material: possessing a valid token lets the server identify the user, but the
 * vault stays locked until the browser re-derives the vault key from the master
 * password. A stolen token therefore cannot decrypt anything.
 *
 * Format: `base64(utf8("<userId>:<expiryMs>")) . base64(hmac)`. Both halves are
 * standard base64 (cookie-safe octets). Verification is constant-time and never
 * throws — any malformed/expired/tampered token yields `null`.
 */
import {
  bytesToBase64,
  base64ToBytes,
  utf8ToBytes,
  bytesToUtf8,
  asBufferSource,
} from '@/lib/crypto/encoding';

/** Default session lifetime: 12 hours. */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

export interface SessionPayload {
  userId: string;
  /** Absolute expiry, epoch milliseconds. */
  expiresAt: number;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    asBufferSource(utf8ToBytes(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

async function hmac(secret: string, data: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, asBufferSource(data));
  return new Uint8Array(sig);
}

/** Length-independent, content constant-time byte comparison. */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Create a signed session token for a user.
 *
 * @param now injectable clock (epoch ms) for deterministic tests.
 */
export async function createSessionToken(
  userId: string,
  secret: string,
  ttlMs: number = SESSION_TTL_MS,
  now: number = Date.now(),
): Promise<string> {
  const expiresAt = now + ttlMs;
  const payload = `${userId}:${expiresAt}`;
  const payloadBytes = utf8ToBytes(payload);
  const sig = await hmac(secret, payloadBytes);
  return `${bytesToBase64(payloadBytes)}.${bytesToBase64(sig)}`;
}

/**
 * Verify a session token and return its payload, or `null` if it is malformed,
 * tampered, signed under a different secret, or expired.
 */
export async function verifySessionToken(
  token: string,
  secret: string,
  now: number = Date.now(),
): Promise<SessionPayload | null> {
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;

  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);

  let payloadBytes: Uint8Array;
  let providedSig: Uint8Array;
  try {
    payloadBytes = base64ToBytes(payloadB64);
    providedSig = base64ToBytes(sigB64);
  } catch {
    return null;
  }

  const expectedSig = await hmac(secret, payloadBytes);
  if (!timingSafeEqual(providedSig, expectedSig)) return null;

  const payload = bytesToUtf8(payloadBytes);
  const sep = payload.lastIndexOf(':');
  if (sep <= 0) return null;

  const userId = payload.slice(0, sep);
  const expiresAt = Number(payload.slice(sep + 1));
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return null;

  return { userId, expiresAt };
}
