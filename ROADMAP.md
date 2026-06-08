# LockBox — Roadmap

**Stack:** Next.js (App Router) · TypeScript · Tailwind · Web Crypto API (client-side crypto) · Postgres · Prisma · Docker
**Goal:** Production-grade **zero-knowledge** password manager. All encryption happens client-side; the server only ever stores ciphertext and never sees the master password or any plaintext. Portfolio-quality: crypto done correctly, tested, containerized, CI'd, deploy-ready.
**Repo visibility:** public — Yanis's portfolio.

> **Zero-knowledge architecture.** Master password → Argon2id-derived keys in the browser. Vault data encrypted with AES-256-GCM client-side. Server stores only encrypted blobs + an auth verifier (never the password). Getting the crypto right is the whole point of this project.

Each roadmap item is a self-contained increment completed in one session, then committed + pushed. Work in order; skip ahead only if blocked.

## Phase 0 — Foundation
- [ ] Next.js + TypeScript + Tailwind app, base layout, ESLint/Prettier
- [ ] Postgres + Prisma (users, encrypted vault items, auth verifiers), Docker, CI stub
- [ ] README, MIT LICENSE, .gitignore
- [ ] `CRYPTO.md` design doc: threat model, key hierarchy, algorithm choices

## Phase 1 — Crypto core (client-side, heavily tested)
- [ ] Argon2id KDF (master password → master key) with sane params + salt
- [ ] Key hierarchy: master key → vault (encryption) key + auth key (separate)
- [ ] AES-256-GCM encrypt/decrypt helpers (random IV per item, AAD where useful)
- [ ] Unit tests with known vectors; tamper/auth-tag failure tests

## Phase 2 — Zero-knowledge auth
- [ ] Registration/login using an auth key derived from master password (server stores a verifier, never the password)
- [ ] Session management, auto-lock on idle, re-auth to unlock vault
- [ ] Rate limiting + lockout on auth endpoints

## Phase 3 — Vault items
- [ ] CRUD for logins, secure notes, cards — all encrypted client-side before upload
- [ ] Folders/tags, client-side search over decrypted data, sort
- [ ] Optimistic UI, sync, conflict handling

## Phase 4 — Password tools
- [ ] Configurable password generator (length, char sets, passphrases)
- [ ] Strength meter (zxcvbn), reuse/weak/old-password audit
- [ ] Breach check via HIBP **k-anonymity** range API (only a hash prefix leaves the device)

## Phase 5 — TOTP & sharing
- [ ] Store TOTP secrets + generate 2FA codes in-app
- [ ] Optional encrypted item sharing (public-key wrapped), rev{ocation}

## Phase 6 — UX & safety
- [ ] Auto-lock, clipboard auto-clear, reveal/hide, import/export (encrypted)
- [ ] Responsive, accessible (keyboard nav, ARIA), empty/error/loading states

## Phase 7 — Hardening & Tests
- [ ] Extensive crypto tests, e2e (Playwright): register → add item → lock → unlock → decrypt
- [ ] Verify server never receives plaintext (network assertion tests)
- [ ] GitHub Actions CI: lint, typecheck, test, build

## Phase 8 — Deploy-Ready
- [ ] Multi-stage build, env docs, deploy guide, polished README w/ screenshots + architecture + threat model

## SECURITY PHASE
Crypto-focused audit: correct KDF params, no key/plaintext leakage to server or logs, proper IV/nonce usage, constant-time comparisons, secure session handling, CSP + security headers, XSS (critical — it handles secrets), CSRF, dependency CVEs, no secrets committed. Document in `SECURITY.md`.

## QA PHASE
Full stack up, run all tests + e2e, confirm via captured traffic that only ciphertext leaves the browser, verify auto-lock + breach check (k-anonymity) work. Log in `PROGRESS.md`.

## SHIP PHASE
Push final commits/tags to the **public** repo, verify CI, tag `v1.0.0`, notify Yanis.
