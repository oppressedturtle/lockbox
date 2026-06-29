/**
 * Shared serialisation for vault-item rows.
 *
 * Rows store `ciphertext`/`iv` as `Bytes` (Node `Buffer` at runtime). The wire
 * format is base64 (CRYPTO.md §4.1), so we convert on the way out. The server
 * only ever moves these opaque blobs around — it never decrypts them.
 */

/** A vault-item row as selected from Prisma (binary columns are `Buffer`). */
export interface VaultItemRow {
  id: string;
  ciphertext: Buffer | Uint8Array;
  iv: Buffer | Uint8Array;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

/** The JSON shape returned to the client for a single item. */
export interface VaultItemDto {
  id: string;
  ciphertext: string;
  iv: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

/** Convert a stored row to its base64 wire representation. */
export function serializeVaultItem(row: VaultItemRow): VaultItemDto {
  return {
    id: row.id,
    ciphertext: Buffer.from(row.ciphertext).toString('base64'),
    iv: Buffer.from(row.iv).toString('base64'),
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** Columns to select for the wire DTO — never selects more than the client needs. */
export const vaultItemSelect = {
  id: true,
  ciphertext: true,
  iv: true,
  version: true,
  createdAt: true,
  updatedAt: true,
} as const;
