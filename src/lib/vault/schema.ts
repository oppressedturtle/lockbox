/**
 * Vault item plaintext model (client-side only).
 *
 * This is the *decrypted* shape of a vault entry. It is assembled, validated, and
 * JSON-serialised entirely in the browser, then encrypted with the vault key
 * before it ever leaves the device (CRYPTO.md §4.1). The server never sees this
 * structure — not the kind, not the title, not the secrets. Even the metadata
 * (title, folder, tags) is part of the encrypted blob, so the server learns
 * nothing from a stored row beyond its size.
 *
 * The `v` field is an explicit schema version so future shape changes can be
 * migrated on decrypt without guessing.
 */
import { z } from 'zod';

/** Current plaintext schema version. Bump when the item shape changes. */
export const VAULT_ITEM_SCHEMA_VERSION = 1;

/** Discriminator for the kinds of secret a vault item can hold. */
export const VAULT_ITEM_KINDS = ['login', 'note', 'card'] as const;
export type VaultItemKind = (typeof VAULT_ITEM_KINDS)[number];

/**
 * Fields common to every item. These live encrypted alongside the secrets —
 * the zero-knowledge model means the server must not be able to read a title or
 * folder name any more than it can read a password.
 */
const baseShape = {
  v: z.literal(VAULT_ITEM_SCHEMA_VERSION),
  title: z.string().min(1, 'title is required').max(256),
  folder: z.string().max(256).optional(),
  tags: z.array(z.string().min(1).max(64)).max(64).optional(),
  /** Free-form notes attached to any item kind. */
  notes: z.string().max(16_384).optional(),
};

/** A website / app login: username, password, optional URL and TOTP secret. */
export const loginItemSchema = z.object({
  ...baseShape,
  kind: z.literal('login'),
  username: z.string().max(512).default(''),
  password: z.string().max(1024).default(''),
  url: z.string().max(2048).optional(),
  /** otpauth secret (base32) — full TOTP support lands in Phase 5. */
  totp: z.string().max(512).optional(),
});

/** A free-form secure note. The body carries the actual content. */
export const noteItemSchema = z.object({
  ...baseShape,
  kind: z.literal('note'),
  body: z.string().max(32_768).default(''),
});

/** A payment card. */
export const cardItemSchema = z.object({
  ...baseShape,
  kind: z.literal('card'),
  cardholderName: z.string().max(256).optional(),
  /** Digits (optionally space-grouped) — kept as a string to preserve grouping. */
  number: z.string().max(40).default(''),
  brand: z.string().max(40).optional(),
  expMonth: z.number().int().min(1).max(12).optional(),
  expYear: z.number().int().min(0).max(9999).optional(),
  cvv: z.string().max(8).optional(),
});

/**
 * Any vault item, discriminated on `kind`. Parsing applies the per-kind defaults
 * (e.g. empty `username`/`password`) so a partially-filled item round-trips to a
 * complete, well-typed object.
 */
export const vaultItemSchema = z.discriminatedUnion('kind', [
  loginItemSchema,
  noteItemSchema,
  cardItemSchema,
]);

export type LoginItem = z.infer<typeof loginItemSchema>;
export type NoteItem = z.infer<typeof noteItemSchema>;
export type CardItem = z.infer<typeof cardItemSchema>;
export type VaultItem = z.infer<typeof vaultItemSchema>;

/** Input accepted by {@link vaultItemSchema} before defaults are applied. */
export type VaultItemInput = z.input<typeof vaultItemSchema>;
