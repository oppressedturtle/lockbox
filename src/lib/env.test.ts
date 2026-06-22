import { describe, expect, it } from 'vitest';
import { parseEnv } from './env';

describe('parseEnv', () => {
  it('accepts a valid configuration', () => {
    const env = parseEnv({
      DATABASE_URL: 'postgresql://lockbox:lockbox@localhost:5432/lockbox?schema=public',
      NODE_ENV: 'production',
    });
    expect(env.DATABASE_URL).toContain('postgresql://');
    expect(env.NODE_ENV).toBe('production');
  });

  it('defaults NODE_ENV to development when omitted', () => {
    const env = parseEnv({
      DATABASE_URL: 'postgresql://lockbox:lockbox@localhost:5432/lockbox',
    });
    expect(env.NODE_ENV).toBe('development');
  });

  it('throws a descriptive error when DATABASE_URL is missing', () => {
    expect(() => parseEnv({})).toThrowError(/DATABASE_URL/);
  });

  it('rejects a non-URL DATABASE_URL', () => {
    expect(() => parseEnv({ DATABASE_URL: 'not-a-url' })).toThrowError(
      /Invalid environment configuration/,
    );
  });

  it('rejects an unknown NODE_ENV', () => {
    expect(() =>
      parseEnv({
        DATABASE_URL: 'postgresql://localhost:5432/lockbox',
        NODE_ENV: 'staging',
      }),
    ).toThrowError(/NODE_ENV/);
  });
});
