/**
 * Request validation for the vault-item endpoints.
 *
 * The server is zero-knowledge here: every payload is opaque ciphertext + its
 * IV (CRYPTO.md §4.1). We validate base64 shape and byte-length bounds strictly
 * so malformed or abusive input is rejected before it touches the database, but
 * we never look inside — the item kind, title, secrets etc. all live encrypted
 * in `ciphertext` and the server can't (and mustn't) parse them.
 */
import { z } from 'zod';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { IV_BYTES } from '@/lib/crypto/random';

/**
 * AES-256-GCM lower bound: even an empty plaintext yields the 16-byte (128-bit)
 * authentication tag. Anything shorter cannot be valid ciphertext.
 */
export const MIN_CIPHERTEXT_BYTES = 16;

/**
 * Upper bound on a single item's ciphertext. A vault entry (login, note, card,
 * TOTP secret) is small JSON; 64 KiB is comfortably generous while capping how
 * much an authenticated client can push per row.
 */
export const MAX_CIPHERTEXT_BYTES = 64 * 1024;

/** A base64 string decoding to a byte length within `[minBytes, maxBytes]`. */
function base64Within(minBytes: number, maxBytes: number, label: string) {
  return z.string().superRefine((value, ctx) => {
    let decoded: Uint8Array;
    try {
      decoded = base64ToBytes(value);
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${label} is not valid base64` });
      return;
    }
    if (decoded.length < minBytes || decoded.length > maxBytes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          minBytes === maxBytes
            ? `${label} must decode to ${minBytes} bytes`
            : `${label} must decode to between ${minBytes} and ${maxBytes} bytes`,
      });
    }
  });
}

const ciphertextSchema = base64Within(MIN_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_BYTES, 'ciphertext');
const ivSchema = base64Within(IV_BYTES, IV_BYTES, 'iv');

/** Create a new vault item — client uploads ciphertext + IV only. */
export const createVaultItemSchema = z.object({
  ciphertext: ciphertextSchema,
  iv: ivSchema,
});

export type CreateVaultItemInput = z.infer<typeof createVaultItemSchema>;

/**
 * Update an existing item. `expectedVersion` is the version the client last saw;
 * the handler refuses the write if the stored row has moved on (optimistic
 * concurrency, CRYPTO.md §4.1) so a stale tab can't silently clobber a newer edit.
 */
export const updateVaultItemSchema = z.object({
  ciphertext: ciphertextSchema,
  iv: ivSchema,
  expectedVersion: z.number().int().min(0),
});

export type UpdateVaultItemInput = z.infer<typeof updateVaultItemSchema>;
