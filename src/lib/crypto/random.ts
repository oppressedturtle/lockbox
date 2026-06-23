/**
 * CSPRNG helpers.
 *
 * All randomness in LockBox (salts, IVs, generated passwords) comes from the
 * platform CSPRNG via `crypto.getRandomValues`. This module centralises access
 * so call sites never reach for a non-cryptographic `Math.random`.
 */

/** Number of bytes in a user salt (see CRYPTO.md §2.2). */
export const SALT_BYTES = 16;

/** Number of bytes in an AES-GCM IV/nonce (see CRYPTO.md §3.1). */
export const IV_BYTES = 12;

/**
 * Return `length` cryptographically-secure random bytes.
 *
 * @throws RangeError if `length` is not a positive integer.
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(`randomBytes: length must be a positive integer, got ${length}`);
  }
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/** A fresh 16-byte user salt. */
export function generateSalt(): Uint8Array {
  return randomBytes(SALT_BYTES);
}

/** A fresh 12-byte AES-GCM IV. Never reuse one with the same key (CRYPTO.md §3.1). */
export function generateIv(): Uint8Array {
  return randomBytes(IV_BYTES);
}
