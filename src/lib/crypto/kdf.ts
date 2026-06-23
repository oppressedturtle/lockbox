/**
 * Argon2id password-based key derivation (CRYPTO.md §3).
 *
 * Web Crypto has no native Argon2, so we use the vetted `hash-wasm` WASM build.
 * The master password is turned into a 256-bit master key (MK) that never leaves
 * the device and is never stored. From MK we derive independent vault and auth
 * keys via HKDF (see keys.ts).
 */
import { argon2id } from "hash-wasm";

/** Argon2id tuning parameters. */
export interface Argon2Params {
  /** Memory cost in KiB. */
  memorySizeKiB: number;
  /** Time cost (iterations / passes). */
  iterations: number;
  /** Degree of parallelism (lanes). */
  parallelism: number;
  /** Derived key length in bytes. */
  keyLengthBytes: number;
}

/**
 * Default parameters from CRYPTO.md §3: 64 MiB memory, 3 iterations, 1 lane,
 * 32-byte output. Tuned for ~250–500 ms on a typical laptop.
 *
 * Frozen so callers cannot accidentally mutate the shared default.
 */
export const DEFAULT_ARGON2_PARAMS: Readonly<Argon2Params> = Object.freeze({
  memorySizeKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
  keyLengthBytes: 32,
});

/**
 * Derive the 256-bit master key (MK) from a master password and per-user salt.
 *
 * @param password  The user's master password (UTF-8). Held only transiently.
 * @param salt      The 16-byte per-user salt (CRYPTO.md §2.2).
 * @param params    Argon2id parameters; defaults to {@link DEFAULT_ARGON2_PARAMS}.
 * @returns         Raw master-key bytes (length = `params.keyLengthBytes`).
 * @throws RangeError on an empty password or salt.
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new RangeError("deriveMasterKey: password must not be empty");
  }
  if (salt.length === 0) {
    throw new RangeError("deriveMasterKey: salt must not be empty");
  }

  const hash = await argon2id({
    password,
    salt,
    memorySize: params.memorySizeKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: params.keyLengthBytes,
    outputType: "binary",
  });

  return hash;
}
