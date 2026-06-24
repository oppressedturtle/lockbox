/**
 * Request validation for the auth endpoints.
 *
 * Everything the client sends here is either non-secret (email, KDF salt +
 * params) or the auth value (AK) — never the master password or vault key. We
 * validate shapes and byte lengths strictly so malformed input is rejected
 * before it ever reaches the database or the verifier.
 */
import { z } from 'zod';
import { base64ToBytes } from '@/lib/crypto/encoding';
import { SALT_BYTES } from '@/lib/crypto/random';

/** AK is a 256-bit HKDF output (see crypto/keys.ts). */
export const AUTH_VALUE_BYTES = 32;

/** A base64 string that decodes to exactly `expectedBytes` bytes. */
function base64OfLength(expectedBytes: number, label: string) {
  return z.string().superRefine((value, ctx) => {
    let decoded: Uint8Array;
    try {
      decoded = base64ToBytes(value);
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${label} is not valid base64` });
      return;
    }
    if (decoded.length !== expectedBytes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${label} must decode to ${expectedBytes} bytes`,
      });
    }
  });
}

/** Normalised email: trimmed, lowercased, RFC-ish, length-bounded. */
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('A valid email is required')
  .max(254);

/**
 * Client-supplied Argon2id parameters used to derive MK. Bounded so a malicious
 * client cannot force the browser (or a future server-side re-derivation) into
 * absurd memory/time costs, while still allowing the documented defaults.
 */
const kdfParamsSchema = z.object({
  kdfMemoryKiB: z
    .number()
    .int()
    .min(8 * 1024)
    .max(256 * 1024)
    .default(64 * 1024),
  kdfIterations: z.number().int().min(1).max(10).default(3),
  kdfParallelism: z.number().int().min(1).max(4).default(1),
});

export const registerSchema = z
  .object({
    email: emailSchema,
    kdfSalt: base64OfLength(SALT_BYTES, 'kdfSalt'),
    authVerifierInput: base64OfLength(AUTH_VALUE_BYTES, 'authVerifierInput'),
  })
  .merge(kdfParamsSchema);

export type RegisterInput = z.infer<typeof registerSchema>;

export const saltSchema = z.object({
  email: emailSchema,
});

export const loginSchema = z.object({
  email: emailSchema,
  authVerifierInput: base64OfLength(AUTH_VALUE_BYTES, 'authVerifierInput'),
});

export type LoginInput = z.infer<typeof loginSchema>;
