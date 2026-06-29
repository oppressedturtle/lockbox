import { describe, expect, it } from 'vitest';
import {
  createVaultItemSchema,
  updateVaultItemSchema,
  MIN_CIPHERTEXT_BYTES,
  MAX_CIPHERTEXT_BYTES,
} from './vault-schemas';
import { bytesToBase64 } from '@/lib/crypto/encoding';
import { IV_BYTES } from '@/lib/crypto/random';

/** base64 of `n` zero bytes — a stand-in for opaque ciphertext of a given length. */
function b64(n: number): string {
  return bytesToBase64(new Uint8Array(n));
}

const validIv = b64(IV_BYTES);
const validCiphertext = b64(MIN_CIPHERTEXT_BYTES);

describe('createVaultItemSchema', () => {
  it('accepts well-formed ciphertext + IV', () => {
    const r = createVaultItemSchema.safeParse({ ciphertext: validCiphertext, iv: validIv });
    expect(r.success).toBe(true);
  });

  it('rejects ciphertext shorter than the GCM tag', () => {
    const r = createVaultItemSchema.safeParse({
      ciphertext: b64(MIN_CIPHERTEXT_BYTES - 1),
      iv: validIv,
    });
    expect(r.success).toBe(false);
  });

  it('rejects ciphertext over the size cap', () => {
    const r = createVaultItemSchema.safeParse({
      ciphertext: b64(MAX_CIPHERTEXT_BYTES + 1),
      iv: validIv,
    });
    expect(r.success).toBe(false);
  });

  it('rejects an IV that is not exactly 12 bytes', () => {
    expect(
      createVaultItemSchema.safeParse({ ciphertext: validCiphertext, iv: b64(IV_BYTES - 1) })
        .success,
    ).toBe(false);
    expect(
      createVaultItemSchema.safeParse({ ciphertext: validCiphertext, iv: b64(IV_BYTES + 1) })
        .success,
    ).toBe(false);
  });

  it('rejects non-base64 input', () => {
    const r = createVaultItemSchema.safeParse({ ciphertext: 'not base64 !!!', iv: validIv });
    expect(r.success).toBe(false);
  });

  it('rejects missing fields', () => {
    expect(createVaultItemSchema.safeParse({ ciphertext: validCiphertext }).success).toBe(false);
    expect(createVaultItemSchema.safeParse({ iv: validIv }).success).toBe(false);
  });
});

describe('updateVaultItemSchema', () => {
  it('accepts ciphertext + IV + a non-negative expectedVersion', () => {
    const r = updateVaultItemSchema.safeParse({
      ciphertext: validCiphertext,
      iv: validIv,
      expectedVersion: 0,
    });
    expect(r.success).toBe(true);
  });

  it('rejects a negative or non-integer expectedVersion', () => {
    expect(
      updateVaultItemSchema.safeParse({
        ciphertext: validCiphertext,
        iv: validIv,
        expectedVersion: -1,
      }).success,
    ).toBe(false);
    expect(
      updateVaultItemSchema.safeParse({
        ciphertext: validCiphertext,
        iv: validIv,
        expectedVersion: 1.5,
      }).success,
    ).toBe(false);
  });

  it('rejects a missing expectedVersion (no blind overwrite)', () => {
    const r = updateVaultItemSchema.safeParse({ ciphertext: validCiphertext, iv: validIv });
    expect(r.success).toBe(false);
  });
});
