/**
 * Zod-validated environment configuration for LockBox.
 *
 * Reads `process.env` lazily on first `getEnv()` call (cached thereafter) and
 * throws a descriptive error if anything required is missing or malformed. All
 * server-side code must read env vars from this module rather than from raw
 * `process.env`.
 *
 * Note: this is server-only configuration. The zero-knowledge crypto runs in
 * the browser and needs none of these values.
 */
import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().url(),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
});

/** Parsed, validated environment. Parameterised for testability. */
export function parseEnv(source: Record<string, string | undefined> = process.env): Env {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(
      `Invalid environment configuration:\n${issues}\n` + `Check your .env against .env.example.`,
    );
  }
  return parsed.data;
}

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

/**
 * Lazily parsed, cached environment. Validation happens on first access (not at
 * import time), so importing this module never throws in tooling/tests that
 * don't set a full environment.
 */
export function getEnv(): Env {
  return (cached ??= parseEnv());
}
