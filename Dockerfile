# LockBox — Next.js (App Router) standalone production image.
# Multi-stage: deps → build (with prisma generate) → minimal non-root runtime.
FROM node:20-slim AS deps

WORKDIR /app

# openssl is required by Prisma's generator/runtime.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci


FROM node:20-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate the Prisma client (output: src/generated/prisma) before building, then
# emit the standalone server bundle. A build-time DATABASE_URL only lets
# prisma.config.ts load; no DB connection is opened during `next build`.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npx prisma generate \
    && npm run build


FROM node:20-slim AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 nodejs \
    && useradd --system --uid 1001 --gid nodejs nextjs

# Standalone output bundles only the traced files the server needs (incl. the
# generated Prisma client). Static assets sit alongside it as Next expects.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD node -e "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
