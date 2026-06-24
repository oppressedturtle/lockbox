import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';

const SECRET = 'x'.repeat(32);

describe('parseEnv', () => {
  it('accepts a valid configuration', () => {
    const env = parseEnv({
      DATABASE_URL: 'postgresql://lockbox:lockbox@localhost:5432/lockbox?schema=public',
      NODE_ENV: 'production',
      SESSION_SECRET: SECRET,
    });
    expect(env.DATABASE_URL).toContain('postgresql://');
    expect(env.NODE_ENV).toBe('production');
    expect(env.SESSION_SECRET).toBe(SECRET);
  });

  it('defaults NODE_ENV to development when omitted', () => {
    const env = parseEnv({
      DATABASE_URL: 'postgresql://lockbox:lockbox@localhost:5432/lockbox',
      SESSION_SECRET: SECRET,
    });
    expect(env.NODE_ENV).toBe('development');
  });

  it('throws a descriptive error when DATABASE_URL is missing', () => {
    expect(() => parseEnv({ SESSION_SECRET: SECRET })).toThrowError(/DATABASE_URL/);
  });

  it('rejects a non-URL DATABASE_URL', () => {
    expect(() => parseEnv({ DATABASE_URL: 'not-a-url', SESSION_SECRET: SECRET })).toThrowError(
      /Invalid environment configuration/,
    );
  });

  it('rejects an unknown NODE_ENV', () => {
    expect(() =>
      parseEnv({
        DATABASE_URL: 'postgresql://localhost:5432/lockbox',
        NODE_ENV: 'staging',
        SESSION_SECRET: SECRET,
      }),
    ).toThrowError(/NODE_ENV/);
  });

  it('rejects a too-short SESSION_SECRET', () => {
    expect(() =>
      parseEnv({
        DATABASE_URL: 'postgresql://localhost:5432/lockbox',
        SESSION_SECRET: 'short',
      }),
    ).toThrowError(/SESSION_SECRET/);
  });
});
