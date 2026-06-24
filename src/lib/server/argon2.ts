/**
 * Server-side verifier for the client's auth key (AK).
 *
 * In the zero-knowledge handshake (CRYPTO.md §4.3) the client derives AK from
 * the master password and sends it to the server *once* over TLS. AK is
 * cryptographically independent from the vault key (VK), so the server learning
 * AK can never decrypt the vault. We still never store AK in the clear: at rest
 * we keep only an Argon2id verifier (a PHC string with its own random salt), so
 * a database breach reveals neither AK nor anything that decrypts the vault.
 *
 * AK is already a uniformly random 256-bit value, so the verifier's job is not
 * to slow down a password guesser (there is nothing low-entropy to guess) — it
 * is to be a salted, one-way commitment that supports constant-time verification.
 * Modest Argon2id parameters are therefore sufficient here.
 */
import { argon2id, argon2Verify } from 'hash-wasm';

/** Argon2id parameters for the server-side AK verifier. */
export const SERVER_VERIFIER_PARAMS = {
  /** 19 MiB — enough to be memory-hard, light enough to verify quickly. */
  memorySizeKiB: 19_456,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

/** 16 random bytes of server-side salt per verifier. */
const SERVER_SALT_BYTES = 16;

/**
 * Produce a PHC-encoded Argon2id verifier of the supplied auth value.
 *
 * @param authValue raw AK bytes received from the client (decoded from base64).
 * @returns a self-describing PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
 */
export async function hashAuthValue(authValue: Uint8Array): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SERVER_SALT_BYTES));
  return argon2id({
    password: authValue,
    salt,
    parallelism: SERVER_VERIFIER_PARAMS.parallelism,
    iterations: SERVER_VERIFIER_PARAMS.iterations,
    memorySize: SERVER_VERIFIER_PARAMS.memorySizeKiB,
    hashLength: SERVER_VERIFIER_PARAMS.hashLength,
    outputType: 'encoded',
  });
}

/**
 * Constant-time verification of an auth value against a stored PHC verifier.
 *
 * Returns `false` (never throws) on any malformed verifier so callers can treat
 * "bad credentials" and "corrupt row" identically without leaking which it was.
 */
export async function verifyAuthValue(verifier: string, authValue: Uint8Array): Promise<boolean> {
  try {
    return await argon2Verify({ password: authValue, hash: verifier });
  } catch {
    return false;
  }
}

/**
 * Cached dummy verifier used to equalise login timing when the account does not
 * exist. Computed once on first use so an unknown-email login path performs the
 * same Argon2id work as a real one, denying a timing-based enumeration oracle.
 */
let dummyVerifier: Promise<string> | undefined;

/**
 * Always returns `false`, but spends the same Argon2id verification time as a
 * real {@link verifyAuthValue}. Call this on the "user not found" branch of login.
 */
export async function spendVerifyTime(authValue: Uint8Array): Promise<false> {
  dummyVerifier ??= hashAuthValue(
    crypto.getRandomValues(new Uint8Array(AUTH_VALUE_BYTES_INTERNAL)),
  );
  await verifyAuthValue(await dummyVerifier, authValue);
  return false;
}

/** AK length in bytes (kept local to avoid a server→schema import cycle). */
const AUTH_VALUE_BYTES_INTERNAL = 32;
