# LockBox — Progress Log

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
