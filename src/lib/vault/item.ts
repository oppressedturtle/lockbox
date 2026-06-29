/**
 * Client-side vault item encryption (Phase 3 — CRYPTO.md §4).
 *
 * This is the bridge between the typed plaintext model ({@link VaultItem}) and
 * the opaque ciphertext the server stores. The full flow is:
 *
 *   const id   = newVaultItemId();                       // client-generated UUID
 *   const blob = await encryptVaultItem(vk, item, { id, userId });
 *   // POST { id, ...blob } → /api/vault
 *   ...
 *   const item = await decryptVaultItem(vk, blob, { id, userId });
 *
 * The item `id` is generated **on the client** and bound into the GCM AAD, so a
 * row's ciphertext can never be relocated under a different id (CRYPTO.md §4.2).
 * That binding is why the id must exist before encryption — the server accepts
 * the client's UUID rather than minting its own.
 */
import {
  encryptItem,
  decryptItem,
  utf8ToBytes,
  type EncryptedBlob,
  type ItemAad,
} from '@/lib/crypto';
import { vaultItemSchema, type VaultItem, type VaultItemInput } from './schema';

/**
 * The server caps a stored ciphertext at 64 KiB (see `server/vault-schemas.ts`,
 * `MAX_CIPHERTEXT_BYTES`). AES-256-GCM appends a 16-byte tag, so the plaintext
 * must stay under that cap minus the tag. We validate the plaintext size before
 * spending any crypto work, and so a too-large item fails with a clear message
 * rather than a 400 from the server.
 */
const GCM_TAG_BYTES = 16;
export const MAX_VAULT_ITEM_PLAINTEXT_BYTES = 64 * 1024 - GCM_TAG_BYTES;

/** Generate a fresh client-side UUID for a new vault item. */
export function newVaultItemId(): string {
  return crypto.randomUUID();
}

/**
 * Validate, serialise, and encrypt a vault item under `vaultKey`.
 *
 * The item is validated against {@link vaultItemSchema} first (applying per-kind
 * defaults), so malformed data never reaches the ciphertext. `aad.id` must be
 * the id the item will be stored under.
 *
 * @throws ZodError if the item is invalid.
 * @throws Error('vault item too large') if the serialised item exceeds the cap.
 */
export async function encryptVaultItem(
  vaultKey: CryptoKey,
  item: VaultItem | VaultItemInput,
  aad: ItemAad,
): Promise<EncryptedBlob> {
  const parsed = vaultItemSchema.parse(item);
  const plaintext = JSON.stringify(parsed);
  if (utf8ToBytes(plaintext).length > MAX_VAULT_ITEM_PLAINTEXT_BYTES) {
    throw new Error('vault item too large');
  }
  return encryptItem(vaultKey, plaintext, aad);
}

/**
 * Decrypt and parse a stored blob back into a typed {@link VaultItem}.
 *
 * Fails closed: a bad GCM tag (tampering, wrong key, or wrong AAD) throws from
 * {@link decryptItem}; a structurally invalid plaintext throws a uniform
 * 'vault item is corrupt' so a caller can't tell a tampered blob from a
 * legitimately-malformed one.
 *
 * @throws Error('decryption failed') on any authentication/decoding failure.
 * @throws Error('vault item is corrupt') if the decrypted JSON is not a valid item.
 */
export async function decryptVaultItem(
  vaultKey: CryptoKey,
  blob: EncryptedBlob,
  aad: ItemAad,
): Promise<VaultItem> {
  const plaintext = await decryptItem(vaultKey, blob, aad);

  let json: unknown;
  try {
    json = JSON.parse(plaintext);
  } catch {
    throw new Error('vault item is corrupt');
  }

  const result = vaultItemSchema.safeParse(json);
  if (!result.success) {
    throw new Error('vault item is corrupt');
  }
  return result.data;
}
