/**
 * AES-256-GCM item encryption (CRYPTO.md §3, §4).
 *
 * Each encryption uses a fresh 12-byte random IV and binds stable, non-secret
 * item metadata (id + userId) into the GCM AAD. The auth tag (128-bit) causes
 * decryption to fail closed if the ciphertext, IV, or AAD is tampered with, and
 * the AAD binding prevents an attacker from relocating a victim's ciphertext
 * under a different item id (CRYPTO.md §4.2).
 */
import { bytesToBase64, base64ToBytes, utf8ToBytes, asBufferSource } from "./encoding";
import { generateIv } from "./random";

const TAG_LENGTH_BITS = 128;

/** Stable, non-secret fields bound into the GCM AAD. */
export interface ItemAad {
  id: string;
  userId: string;
}

/** An encrypted item blob as stored / transmitted (CRYPTO.md §4.1). */
export interface EncryptedBlob {
  /** base64 AES-256-GCM ciphertext (auth tag appended by Web Crypto). */
  ciphertext: string;
  /** base64 of the 12-byte IV. */
  iv: string;
}

/**
 * Canonical AAD bytes for an item. Field order is fixed so encrypt and decrypt
 * always produce identical AAD; values are length-prefixed to avoid ambiguity
 * between e.g. `("ab", "c")` and `("a", "bc")`.
 */
export function buildAad(aad: ItemAad): Uint8Array {
  return utf8ToBytes(`v1|id:${aad.id.length}:${aad.id}|user:${aad.userId.length}:${aad.userId}`);
}

/**
 * Encrypt `plaintext` under `vaultKey`, binding `aad` into the GCM tag.
 *
 * A new random IV is generated for every call (never reuse an IV with the same
 * key — CRYPTO.md §3.1). The returned blob carries the IV so the caller can
 * decrypt later.
 *
 * @throws on an empty plaintext (callers should not store empty items).
 */
export async function encryptItem(
  vaultKey: CryptoKey,
  plaintext: string,
  aad: ItemAad,
): Promise<EncryptedBlob> {
  const iv = generateIv();
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asBufferSource(iv),
      additionalData: asBufferSource(buildAad(aad)),
      tagLength: TAG_LENGTH_BITS,
    },
    vaultKey,
    asBufferSource(utf8ToBytes(plaintext)),
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(ct)),
    iv: bytesToBase64(iv),
  };
}

/**
 * Decrypt an {@link EncryptedBlob} produced by {@link encryptItem}.
 *
 * Fails closed: if the ciphertext, IV, or AAD has been tampered with, the GCM
 * tag check fails and this throws — it never returns garbage plaintext.
 *
 * @throws Error("decryption failed") on any authentication or decoding failure.
 */
export async function decryptItem(
  vaultKey: CryptoKey,
  blob: EncryptedBlob,
  aad: ItemAad,
): Promise<string> {
  let plaintextBuf: ArrayBuffer;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asBufferSource(base64ToBytes(blob.iv)),
        additionalData: asBufferSource(buildAad(aad)),
        tagLength: TAG_LENGTH_BITS,
      },
      vaultKey,
      asBufferSource(base64ToBytes(blob.ciphertext)),
    );
  } catch {
    // Normalise every failure mode (bad tag, bad AAD, malformed base64) into a
    // single opaque error so callers cannot distinguish *why* it failed.
    throw new Error("decryption failed");
  }
  return new TextDecoder().decode(plaintextBuf);
}
