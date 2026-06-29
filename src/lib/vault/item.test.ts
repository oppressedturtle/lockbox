import { describe, expect, it } from 'vitest';

import { deriveMasterKey, type Argon2Params } from '@/lib/crypto/kdf';
import { deriveVaultCryptoKey } from '@/lib/crypto/keys';
import { hexToBytes } from '@/lib/crypto/encoding';
import {
  encryptVaultItem,
  decryptVaultItem,
  newVaultItemId,
  MAX_VAULT_ITEM_PLAINTEXT_BYTES,
} from './item';
import {
  vaultItemSchema,
  VAULT_ITEM_SCHEMA_VERSION,
  type LoginItem,
  type NoteItem,
  type CardItem,
} from './schema';

// Fast Argon2id params — we only need a real AES key, not KDF hardness here.
const TEST_PARAMS: Argon2Params = {
  memorySizeKiB: 8 * 1024,
  iterations: 2,
  parallelism: 1,
  keyLengthBytes: 32,
};

const AAD = { id: '11111111-1111-1111-1111-111111111111', userId: 'user-abc' };

async function vaultKey(password = 'correct horse battery staple'): Promise<CryptoKey> {
  const mk = await deriveMasterKey(
    password,
    hexToBytes('000102030405060708090a0b0c0d0e0f'),
    TEST_PARAMS,
  );
  return deriveVaultCryptoKey(mk);
}

const login: LoginItem = {
  v: VAULT_ITEM_SCHEMA_VERSION,
  kind: 'login',
  title: 'GitHub',
  username: 'octocat',
  password: 's3cr3t!',
  url: 'https://github.com',
  tags: ['dev', 'work'],
};

const note: NoteItem = {
  v: VAULT_ITEM_SCHEMA_VERSION,
  kind: 'note',
  title: 'Recovery codes',
  body: 'abc-123\ndef-456',
};

const card: CardItem = {
  v: VAULT_ITEM_SCHEMA_VERSION,
  kind: 'card',
  title: 'Visa',
  cardholderName: 'Yanis',
  number: '4111 1111 1111 1111',
  expMonth: 12,
  expYear: 2030,
  cvv: '123',
};

describe('newVaultItemId', () => {
  it('generates distinct, valid UUIDs', () => {
    const a = newVaultItemId();
    const b = newVaultItemId();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

describe('encryptVaultItem / decryptVaultItem', () => {
  it.each([
    ['login', login],
    ['note', note],
    ['card', card],
  ])('round-trips a %s item through encrypt → decrypt', async (_kind, item) => {
    const vk = await vaultKey();
    const blob = await encryptVaultItem(vk, item, AAD);
    // Server-shaped blob: base64 ciphertext + iv only.
    expect(typeof blob.ciphertext).toBe('string');
    expect(typeof blob.iv).toBe('string');

    const out = await decryptVaultItem(vk, blob, AAD);
    expect(out).toEqual(item);
  });

  it('never leaks plaintext into the ciphertext blob', async () => {
    const vk = await vaultKey();
    const blob = await encryptVaultItem(vk, login, AAD);
    const haystack = `${blob.ciphertext}|${blob.iv}`;
    for (const secret of ['octocat', 's3cr3t!', 'GitHub', 'github.com']) {
      expect(haystack).not.toContain(secret);
    }
  });

  it('uses a fresh IV per encryption (no IV reuse)', async () => {
    const vk = await vaultKey();
    const a = await encryptVaultItem(vk, login, AAD);
    const b = await encryptVaultItem(vk, login, AAD);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it('applies per-kind defaults so partial items round-trip complete', async () => {
    const vk = await vaultKey();
    const partial = { v: VAULT_ITEM_SCHEMA_VERSION, kind: 'login', title: 'Empty' } as const;
    const blob = await encryptVaultItem(vk, partial, AAD);
    const out = await decryptVaultItem(vk, blob, AAD);
    expect(out).toEqual({
      v: VAULT_ITEM_SCHEMA_VERSION,
      kind: 'login',
      title: 'Empty',
      username: '',
      password: '',
    });
  });

  it('rejects an invalid item before encrypting', async () => {
    const vk = await vaultKey();
    // Empty title violates the schema.
    await expect(
      encryptVaultItem(
        vk,
        { v: VAULT_ITEM_SCHEMA_VERSION, kind: 'note', title: '', body: 'x' },
        AAD,
      ),
    ).rejects.toThrow();
  });

  it('rejects an item whose plaintext exceeds the size cap', async () => {
    const vk = await vaultKey();
    const huge: NoteItem = {
      v: VAULT_ITEM_SCHEMA_VERSION,
      kind: 'note',
      title: 'big',
      body: 'x'.repeat(MAX_VAULT_ITEM_PLAINTEXT_BYTES + 1),
    };
    // Body alone is over cap, but it's also over the schema's 32 KiB body bound,
    // so schema validation rejects it first — either way it must throw.
    await expect(encryptVaultItem(vk, huge, AAD)).rejects.toThrow();
  });

  it('fails closed when the AAD (item id) does not match', async () => {
    const vk = await vaultKey();
    const blob = await encryptVaultItem(vk, login, AAD);
    await expect(
      decryptVaultItem(vk, blob, { ...AAD, id: '22222222-2222-2222-2222-222222222222' }),
    ).rejects.toThrow('decryption failed');
  });

  it('fails closed under the wrong key', async () => {
    const blob = await encryptVaultItem(await vaultKey('right'), login, AAD);
    await expect(decryptVaultItem(await vaultKey('wrong'), blob, AAD)).rejects.toThrow(
      'decryption failed',
    );
  });

  it('reports corrupt when the decrypted bytes are not a valid item', async () => {
    const vk = await vaultKey();
    // Encrypt valid JSON that is not a vault item, then decrypt through the typed layer.
    const { encryptItem } = await import('@/lib/crypto/cipher');
    const blob = await encryptItem(vk, JSON.stringify({ kind: 'unknown' }), AAD);
    await expect(decryptVaultItem(vk, blob, AAD)).rejects.toThrow('vault item is corrupt');
  });
});

describe('vaultItemSchema', () => {
  it('rejects an unknown kind', () => {
    expect(vaultItemSchema.safeParse({ v: 1, kind: 'wifi', title: 'x' }).success).toBe(false);
  });

  it('rejects an out-of-range card expiry month', () => {
    expect(vaultItemSchema.safeParse({ ...card, expMonth: 13 }).success).toBe(false);
  });
});
