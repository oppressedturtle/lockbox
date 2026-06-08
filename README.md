# LockBox 🔐

A **zero-knowledge** password manager. Your master password never leaves your device, and the server only ever stores encrypted blobs — it cannot read your vault, ever.

> Portfolio project, work in progress. The point of this build is **getting the cryptography right.**

## How the zero-knowledge model works
- Master password → **Argon2id** derives your keys in the browser
- Vault items encrypted with **AES-256-GCM** client-side (random IV per item)
- Server stores only ciphertext + an auth **verifier** — never your password or plaintext
- Breach checks use **HIBP k-anonymity**: only a partial hash prefix ever leaves your device

## Features
- Vault for logins, secure notes, and cards — all encrypted client-side
- Password **generator**, strength meter, and reuse/weak/old audit
- **TOTP** 2FA code storage, optional encrypted sharing
- Auto-lock, clipboard auto-clear, encrypted import/export, folders/tags, client-side search

## Stack
Next.js (App Router) · TypeScript · Web Crypto API · Tailwind · Postgres + Prisma · Docker · GitHub Actions

## Status
See [`ROADMAP.md`](./ROADMAP.md), [`PROGRESS.md`](./PROGRESS.md), and the `CRYPTO.md` design doc (threat model + key hierarchy).

## License
MIT — see [`LICENSE`](./LICENSE).
