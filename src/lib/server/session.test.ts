import { describe, expect, it } from 'vitest';
import { createSessionToken, verifySessionToken, SESSION_TTL_MS } from './session';

const SECRET = 'unit-test-session-secret-of-sufficient-length';
const USER = '11111111-2222-3333-4444-555555555555';

describe('session tokens', () => {
  it('round-trips a freshly minted token', async () => {
    const now = 1_000_000_000_000;
    const token = await createSessionToken(USER, SECRET, SESSION_TTL_MS, now);
    const payload = await verifySessionToken(token, SECRET, now + 1000);
    expect(payload).not.toBeNull();
    expect(payload?.userId).toBe(USER);
    expect(payload?.expiresAt).toBe(now + SESSION_TTL_MS);
  });

  it('rejects a token signed under a different secret', async () => {
    const token = await createSessionToken(USER, SECRET);
    expect(await verifySessionToken(token, 'another-secret-of-sufficient-length!!')).toBeNull();
  });

  it('rejects a tampered payload', async () => {
    const now = 1_000_000_000_000;
    const token = await createSessionToken(USER, SECRET, SESSION_TTL_MS, now);
    const [, sig] = token.split('.');
    // Forge a payload that claims a different user but keeps the old signature.
    const forgedPayload = Buffer.from(
      `${'00000000-0000-0000-0000-000000000000'}:${now + SESSION_TTL_MS}`,
    ).toString('base64');
    const forged = `${forgedPayload}.${sig}`;
    expect(await verifySessionToken(forged, SECRET, now + 1000)).toBeNull();
  });

  it('rejects an expired token', async () => {
    const now = 1_000_000_000_000;
    const token = await createSessionToken(USER, SECRET, 1000, now);
    expect(await verifySessionToken(token, SECRET, now + 2000)).toBeNull();
  });

  it('rejects malformed tokens', async () => {
    expect(await verifySessionToken('', SECRET)).toBeNull();
    expect(await verifySessionToken('no-dot', SECRET)).toBeNull();
    expect(await verifySessionToken('.', SECRET)).toBeNull();
    expect(await verifySessionToken('abc.', SECRET)).toBeNull();
    expect(await verifySessionToken('.abc', SECRET)).toBeNull();
  });
});
