/**
 * Prisma client singleton for LockBox.
 *
 * Prisma 7 requires an explicit driver adapter — we use @prisma/adapter-pg
 * backed by a `pg` Pool. A module-level global keeps Next.js dev hot-reloads
 * from exhausting the connection pool by spawning a new client per change.
 *
 * This module is server-only; the client never runs in the browser.
 */
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@/generated/prisma/client';
import { getEnv } from './env';

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

function createPrismaClient(): PrismaClient {
  const pool = new Pool({ connectionString: getEnv().DATABASE_URL });
  const adapter = new PrismaPg(pool);
  return new PrismaClient({
    adapter,
  } as ConstructorParameters<typeof PrismaClient>[0]);
}

/**
 * Resolve the singleton client, constructing it (and validating env) lazily on
 * first use. Deferring construction keeps module import side-effect-free, so
 * `next build` can import route handlers without a live DATABASE_URL present.
 */
function getClient(): PrismaClient {
  if (globalForPrisma.prisma) return globalForPrisma.prisma;
  const client = createPrismaClient();
  if (getEnv().NODE_ENV !== 'production') globalForPrisma.prisma = client;
  return client;
}

/**
 * Lazy proxy over the Prisma client. Property access (e.g. `db.user`) builds the
 * real client on demand and forwards to it; no DB connection or env read happens
 * until a query is actually issued.
 */
export const db: PrismaClient = new Proxy({} as PrismaClient, {
  get(_target, prop, receiver) {
    const client = getClient();
    const value = Reflect.get(client, prop, receiver);
    return typeof value === 'function' ? value.bind(client) : value;
  },
});
