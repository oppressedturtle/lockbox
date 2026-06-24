/**
 * Enumeration-resistant decoy KDF salt.
 *
 * The salt endpoint must return a salt for *any* email, otherwise a "user not
 * found" response would let an attacker enumerate registered accounts. For an
 * unknown email we return a deterministic, stable salt derived as
 * HMAC-SHA256(SESSION_SECRET, "lockbox:salt-decoy:" + email), truncated to 16
 * bytes. It is indistinguishable from a real random salt, stable across requests
 * (so repeated probes look like a settled account), and reveals nothing.
 */
import { asBufferSource, utf8ToBytes } from '@/lib/crypto/encoding';
import { SALT_BYTES } from '@/lib/crypto/random';

const DECOY_INFO = 'lockbox:salt-decoy:';

export async function deriveDecoySalt(email: string, secret: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    asBufferSource(utf8ToBytes(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign(
    'HMAC',
    key,
    asBufferSource(utf8ToBytes(DECOY_INFO + email)),
  );
  return new Uint8Array(mac).slice(0, SALT_BYTES);
}
