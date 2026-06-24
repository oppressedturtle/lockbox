import { describe, expect, it } from 'vitest';
import { hashAuthValue, verifyAuthValue, spendVerifyTime } from './argon2';

const AK = new Uint8Array(32).fill(7);
const WRONG = new Uint8Array(32).fill(8);

describe('server AK verifier', () => {
  it('produces a PHC-encoded argon2id verifier', async () => {
    const verifier = await hashAuthValue(AK);
    expect(verifier.startsWith('$argon2id$')).toBe(true);
  });

  it('verifies the correct auth value and rejects a wrong one', async () => {
    const verifier = await hashAuthValue(AK);
    expect(await verifyAuthValue(verifier, AK)).toBe(true);
    expect(await verifyAuthValue(verifier, WRONG)).toBe(false);
  });

  it('uses a fresh salt so two verifiers of the same AK differ', async () => {
    const a = await hashAuthValue(AK);
    const b = await hashAuthValue(AK);
    expect(a).not.toBe(b);
    expect(await verifyAuthValue(a, AK)).toBe(true);
    expect(await verifyAuthValue(b, AK)).toBe(true);
  });

  it('verifyAuthValue returns false (never throws) on a malformed verifier', async () => {
    expect(await verifyAuthValue('not-a-phc-string', AK)).toBe(false);
  });

  it('spendVerifyTime always returns false', async () => {
    expect(await spendVerifyTime(AK)).toBe(false);
  });
});
