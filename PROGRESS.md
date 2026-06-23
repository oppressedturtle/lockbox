# LockBox — Progress Log

## 2026-06-23 — Phase 0 closed + Phase 1 crypto core (client-side, heavily tested)

Phase 0 was already effectively complete (README/LICENSE/.gitignore all present) — checked off
the last item. Then built the **entire Phase 1 crypto core** under `src/lib/crypto/`, the heart of
LockBox's zero-knowledge design (per `CRYPTO.md`):

- **`random.ts`** — CSPRNG helpers (`crypto.getRandomValues`): salts (16B) and GCM IVs (12B).
- **`encoding.ts`** — env-agnostic base64/hex/utf-8 (no Node `Buffer`, so it runs in the browser)
  + an `asBufferSource` shim for the TS 5.7 typed-array/`BufferSource` mismatch.
- **`kdf.ts`** — **Argon2id** (vetted `hash-wasm`) master-password → 256-bit master key;
  default params 64 MiB / t=3 / p=1 / 32B per `CRYPTO.md §3`.
- **`keys.ts`** — **HKDF-SHA256** key hierarchy: MK → independent vault key + auth key via
  distinct `info` labels; vault key imported as a **non-extractable** AES-256-GCM `CryptoKey`.
- **`cipher.ts`** — **AES-256-GCM** encrypt/decrypt: fresh random IV per op, 128-bit tag, and
  item metadata (id+userId) bound into the **AAD** (length-prefixed, unambiguous) so ciphertext
  can't be relocated under a different id. Decryption fails closed with an opaque error.
- **`index.ts`** — public barrel documenting the full register→derive→encrypt→decrypt flow.

**Tests (`crypto.test.ts`, 28 cases) — fulfils every `CRYPTO.md §7` obligation:** Argon2id
known-answer regression vector + determinism; **HKDF cross-checked against Node's independent
`crypto.hkdfSync`**; AES-GCM round-trip over empty/unicode/50KB inputs; **tamper detection** on
ciphertext / IV / AAD / wrong-key (all fail closed); **key independence** (VK≠AK); **IV
uniqueness** (10 encrypts → 10 distinct IVs & ciphertexts); and an end-to-end flow asserting no
plaintext leaks into the stored blob or auth key.

**Verification (all green):** vitest **33/33**; `tsc --noEmit` clean; `next lint` clean; `next build` succeeds.

**Next:** Phase 2 — zero-knowledge auth (registration/login with the auth-key verifier, session
management, auto-lock on idle, rate limiting/lockout on auth endpoints).


## 2026-06-22 — Phase 0 item 2: Postgres + Prisma data layer + Docker + CI

**Done (Phase 0 item 2):** the persistence layer, modelled to honour the zero-knowledge
guarantee from `CRYPTO.md §4` — the server stores **only ciphertext + an auth verifier**.

- **`prisma/schema.prisma`** (Prisma 7, `provider = "prisma-client"` + pg driver adapter):
  - **`User`** — `email`, `kdfSalt` (client Argon2id salt), per-user Argon2id params
    (`kdfMemoryKiB`/`kdfIterations`/`kdfParallelism`, for the §8 migration path), and
    `authVerifier` (a PHC string verifying the auth key AK). Never stores the master password
    or the vault key VK.
  - **`VaultItem`** — opaque `ciphertext` (AES-256-GCM blob, tag appended) + `iv` + `version`
    for optimistic concurrency. Deliberately **no** item-type/title/url columns: the server
    can't tell a login from a card. Cascade delete; `[userId, updatedAt]` hot-path index.
- **`prisma.config.ts`** — Prisma 7 config, `DATABASE_URL` injected here (not in schema).
- **`src/lib/env.ts`** — Zod-validated, **lazy** `getEnv()` (no import-time throw; testable
  `parseEnv`). **`src/lib/db.ts`** — `PrismaClient` singleton over a `pg` Pool + `PrismaPg`
  adapter (hot-reload safe). Env validator unit-tested (**vitest 5/5**).
- **`Dockerfile`** — multi-stage Next.js **standalone** (`output: "standalone"`): deps → build
  (`prisma generate` + `next build`) → minimal non-root runtime. **`docker-compose.yml`** —
  `web` + `postgres:16-alpine`, healthchecks, service-name wiring, named volume, env-overridable
  host ports. `+ .dockerignore`, `+ .env.example`, `+ .prettierignore` (excludes generated client).
- **`.github/workflows/ci.yml`** — **web** (npm ci → prisma generate → lint → typecheck →
  format → test → build) + **docker** (buildx, GHA cache) jobs; concurrency cancel-in-progress.
- Added deps: `@prisma/client`, `@prisma/adapter-pg`, `pg`, `zod`, `dotenv`, `vitest`, `@types/pg`.
- **Verified (all green):** `tsc --noEmit` ✓ · `next lint --max-warnings 0` ✓ · `prettier --check` ✓ ·
  `vitest` 5/5 ✓ · `next build` (standalone) ✓ · Docker image builds ✓ ·
  `docker compose up --wait` → postgres + web **healthy**, web returns HTTP 200. (No migration
  committed yet — generated on first DB-touching feature in Phase 2.)
- **Roadmap:** Phase 0 — 3/4. **Next:** Phase 0 item 3 — README + MIT LICENSE + .gitignore
  (LICENSE/.gitignore already present; finalize root README with architecture + run steps) →
  closes Phase 0, then Phase 1 crypto core.

## 2026-06-15 — Phase 0: Next.js + TypeScript + Tailwind app scaffold

**Done (Phase 0 item 1):** stood up the Next.js (App Router) application.

- **`package.json`** — Next 14.2.15 + React 18, strict TS, Tailwind 3, ESLint
  (`next/core-web-vitals` + `prettier`), Prettier with `prettier-plugin-tailwindcss`.
  Scripts: dev/build/start/lint (`--max-warnings 0`)/typecheck/format.
- **`tsconfig.json`** — strict mode incl. `noUncheckedIndexedAccess`, `@/*` path alias,
  Next plugin.
- **App shell:** `src/app/layout.tsx` (root layout + metadata), `src/app/page.tsx`
  (landing page describing the zero-knowledge model), `globals.css` (Tailwind layers,
  dark theme). `tailwind.config.ts` with a `brand` palette; `postcss.config.mjs`;
  `next.config.mjs` (strict mode, `poweredByHeader: false`).
- Config: `.eslintrc.json`, `.prettierrc.json`. Gitignored `next-env.d.ts` +
  `tsconfig.tsbuildinfo`.

**Verification (all green):** `next lint --max-warnings 0` clean · `tsc --noEmit` clean ·
`next build` succeeds (static `/` prerendered, 87.2 kB First Load JS) · `prettier --check` clean.

**Roadmap:** Phase 0 item 1 ✅ (CRYPTO.md already ✅). **Next:** Phase 0 item 2 — Postgres +
Prisma (users, encrypted vault items, auth verifiers), Docker, CI stub.


## 2026-06-11 — Phase 0: CRYPTO.md design doc

**Done:**
- Wrote `CRYPTO.md` — the authoritative cryptographic design for the
  zero-knowledge architecture, the crux of this project. Covers: threat model
  (what we defend vs. explicitly out-of-scope, incl. the served-JS limitation);
  the full key hierarchy (master password → Argon2id MK → HKDF-split into an
  independent vault key VK + auth key AK so the server's auth material can't
  decrypt data); algorithms + parameters (Argon2id 64 MiB/t=3, AES-256-GCM with
  per-item random 96-bit IV + AAD binding `id`/`userId`, HKDF-SHA256); exactly
  what is stored vs. what crosses the wire; session/auto-lock key lifetime;
  HIBP k-anonymity breach check; and the Phase 1/7 test obligations (KATs,
  round-trip, tamper-fails-closed, key independence, IV uniqueness, network
  no-plaintext assertion).

**Roadmap:** Phase 0 — CRYPTO.md design doc done (item 4/4). Remaining Phase 0:
Next.js/Tailwind app scaffold + Prisma/Postgres schema + Docker/CI stub.

**Next:** Scaffold the Next.js + TypeScript + Tailwind app (base layout,
ESLint/Prettier), then the Prisma schema (users, encrypted vault items, auth
verifiers) per CRYPTO.md §4.

## 2026-06-08 — Project kickoff
- Added to the autonomous build pipeline (security project, builds in rotation).
- Defined 8-phase roadmap with a zero-knowledge, client-side-crypto architecture.
- Foundation committed: README, MIT LICENSE, .gitignore. Public repo created.
- **Next:** Phase 0 — Next.js + Tailwind app, Postgres/Prisma, Docker, and the CRYPTO.md design doc (threat model + key hierarchy).
