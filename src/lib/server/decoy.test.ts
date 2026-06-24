import { describe, expect, it } from 'vitest';
import { deriveDecoySalt } from './decoy';
import { SALT_BYTES } from '@/lib/crypto/random';
import { bytesToHex } from '@/lib/crypto/encoding';

const SECRET = 'unit-test-session-secret-of-sufficient-length';

describe('deriveDecoySalt', () => {
  it('returns a SALT_BYTES-length salt', async () => {
    const salt = await deriveDecoySalt('nobody@example.com', SECRET);
    expect(salt.length).toBe(SALT_BYTES);
  });

  it('is deterministic for the same email + secret (stable across probes)', async () => {
    const a = await deriveDecoySalt('nobody@example.com', SECRET);
    const b = await deriveDecoySalt('nobody@example.com', SECRET);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it('differs per email and per secret', async () => {
    const base = bytesToHex(await deriveDecoySalt('a@example.com', SECRET));
    expect(bytesToHex(await deriveDecoySalt('b@example.com', SECRET))).not.toBe(base);
    expect(bytesToHex(await deriveDecoySalt('a@example.com', SECRET + '!'))).not.toBe(base);
  });
});
