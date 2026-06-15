# LockBox — Progress Log

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
