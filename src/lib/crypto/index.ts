/**
 * LockBox crypto core — public surface.
 *
 * The full zero-knowledge flow, composed from this module:
 *
 *   const salt = generateSalt();
 *   const mk   = await deriveMasterKey(masterPassword, salt);
 *   const vk   = await deriveVaultCryptoKey(mk);     // AES-256-GCM CryptoKey
 *   const ak   = await deriveAuthKeyBytes(mk);       // sent (as a verifier) to server
 *   const blob = await encryptItem(vk, JSON.stringify(item), { id, userId });
 *   const json = await decryptItem(vk, blob, { id, userId });
 *
 * See CRYPTO.md for the threat model, key hierarchy, and parameters.
 */
export { randomBytes, generateSalt, generateIv, SALT_BYTES, IV_BYTES } from './random';

export {
  utf8ToBytes,
  bytesToUtf8,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
} from './encoding';

export { deriveMasterKey, DEFAULT_ARGON2_PARAMS, type Argon2Params } from './kdf';

export {
  deriveVaultKeyBytes,
  deriveAuthKeyBytes,
  importVaultKey,
  deriveVaultCryptoKey,
  VAULT_KEY_INFO,
  AUTH_KEY_INFO,
} from './keys';

export { encryptItem, decryptItem, buildAad, type EncryptedBlob, type ItemAad } from './cipher';
