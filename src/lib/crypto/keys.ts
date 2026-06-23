/**
 * Key hierarchy: master key → vault key + auth key (CRYPTO.md §2).
 *
 * Two independent 256-bit sub-keys are derived from the master key (MK) via
 * HKDF-SHA256 with distinct `info` labels. This independence is the central
 * zero-knowledge property: a server that learns the auth key cannot derive the
 * vault key from it.
 */

import { asBufferSource } from "./encoding";

/** HKDF `info` labels — distinct domains keep the sub-keys cryptographically separate. */
export const VAULT_KEY_INFO = "lockbox:vault";
export const AUTH_KEY_INFO = "lockbox:auth";

const SUBKEY_BYTES = 32; // 256-bit sub-keys

/**
 * HKDF-SHA256 expand of the master key into a labelled 256-bit sub-key.
 *
 * HKDF salt is empty here by design: MK is already a high-entropy uniformly
 * random key (Argon2id output), and the per-purpose `info` label provides the
 * domain separation we need. See RFC 5869 §3.1.
 */
async function deriveSubKeyBits(
  masterKey: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(masterKey),
    "HKDF",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: asBufferSource(new TextEncoder().encode(info)),
    },
    baseKey,
    SUBKEY_BYTES * 8,
  );

  return new Uint8Array(bits);
}

/** Derive the raw vault-key bytes (used to build an AES-256-GCM key). */
export function deriveVaultKeyBytes(masterKey: Uint8Array): Promise<Uint8Array> {
  return deriveSubKeyBits(masterKey, VAULT_KEY_INFO);
}

/** Derive the raw auth-key bytes (proof of master-password knowledge to the server). */
export function deriveAuthKeyBytes(masterKey: Uint8Array): Promise<Uint8Array> {
  return deriveSubKeyBits(masterKey, AUTH_KEY_INFO);
}

/**
 * Import the vault key as a non-extractable AES-256-GCM `CryptoKey`.
 *
 * `extractable: false` means the raw key material cannot be read back out of the
 * handle — it can only be used to encrypt/decrypt, limiting exposure if a key
 * handle leaks (CRYPTO.md §5).
 */
export async function importVaultKey(vaultKeyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    asBufferSource(vaultKeyBytes),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Convenience: derive MK's vault sub-key and import it as a usable AES key in
 * one step. The intermediate raw bytes are not retained by the returned handle.
 */
export async function deriveVaultCryptoKey(masterKey: Uint8Array): Promise<CryptoKey> {
  const bytes = await deriveVaultKeyBytes(masterKey);
  return importVaultKey(bytes);
}
