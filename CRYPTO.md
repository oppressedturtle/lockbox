# LockBox — Cryptographic Design

This document specifies LockBox's zero-knowledge architecture: the threat model,
the key hierarchy, the algorithms and parameters, and the exact data that
crosses the network. It is the authoritative reference for the crypto core
implemented in Phase 1. If code and this document disagree, that is a bug in one
of them — fix it, don't paper over it.

> **One-sentence guarantee:** the server stores only ciphertext and an
> authentication verifier; it never receives the master password, any key
> derived from it that could decrypt data, or any plaintext vault item.

---

## 1. Threat model

### 1.1 What we defend against

| Adversary | Capability | LockBox defense |
| --- | --- | --- |
| Curious/honest-but-curious server operator | Reads the entire database and server logs | Vault items are AES-256-GCM ciphertext; server holds only an auth verifier, never the master password or vault key |
| Database breach / stolen backup | Offline access to all stored rows | Same as above; cracking requires brute-forcing Argon2id over each user's master password |
| Network attacker (passive) | Observes TLS-protected traffic | Only ciphertext + verifier transit; TLS adds transport confidentiality on top |
| Stolen auth token | Replays a session token | Tokens authenticate the *account* but cannot decrypt the vault without the master password (auto-lock; vault key never leaves the device unencrypted) |
| Tampered ciphertext | Flips bits in stored blobs | AES-GCM auth tag + per-item AAD cause decryption to fail closed |

### 1.2 What is explicitly out of scope

- **Endpoint compromise.** If malware or a malicious browser extension runs in
  the user's session while the vault is unlocked, it can read decrypted data.
  No client-side crypto can prevent this; we mitigate with auto-lock + clipboard
  clearing, not eliminate.
- **A hostile server serving malicious JavaScript.** Browser-delivered crypto
  means the server *could* ship code that exfiltrates the master password. We
  treat the served app as trusted; this is the standard, acknowledged limitation
  of web-based zero-knowledge tools. Subresource Integrity + a strict CSP raise
  the bar (see Phase 7 SECURITY).
- **Rubber-hose / coercion, weak master passwords chosen by the user.** We
  surface a strength meter (Phase 4) but cannot prevent a user from choosing
  `password123`.

---

## 2. Key hierarchy

All derivation and encryption happen **in the browser** via the Web Crypto API
(`crypto.subtle`) plus an Argon2id WASM module. The master password is held in
memory only transiently during derivation and is never persisted or transmitted.

```
                       master password (user secret, never leaves device)
                                  │
                                  │  Argon2id(salt = userSalt, params)   ← 256-bit
                                  ▼
                            master key (MK)
                                  │
              ┌───────────────────┴───────────────────┐
              │ HKDF-SHA256(MK, info="lockbox:vault")  │ HKDF-SHA256(MK, info="lockbox:auth")
              ▼                                         ▼
        vault key (VK, 256-bit)                   auth key (AK, 256-bit)
        - AES-256-GCM key for items               - proves knowledge of MK to server
        - NEVER sent to the server                - server stores only a verifier of AK
```

### 2.1 Rationale for splitting VK and AK

Deriving two **independent** keys from the master key via HKDF with distinct
`info` labels means the value sent to the server for authentication (AK, or
rather a verifier of it) is cryptographically unrelated to the value that
decrypts the vault (VK). Even a malicious server that learns AK cannot derive VK
from it. This is the central property that makes the architecture
zero-knowledge.

### 2.2 userSalt

- 16 random bytes from `crypto.getRandomValues`, generated at registration.
- Stored server-side and returned at login so the client can re-derive MK.
- A salt is **not** a secret; its purpose is to make precomputation/rainbow
  tables across users useless and to ensure two users with the same master
  password derive different keys.

---

## 3. Algorithms & parameters

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Password-based key derivation | **Argon2id** | memory = 64 MiB, iterations = 3, parallelism = 1, output = 32 bytes. Tuned to ≈250–500 ms on a typical laptop; revisited as hardware improves. |
| Sub-key derivation | **HKDF-SHA256** | extract+expand from MK with per-purpose `info` labels (`lockbox:vault`, `lockbox:auth`); 32-byte outputs |
| Item encryption | **AES-256-GCM** | 96-bit (12-byte) random IV per encryption, 128-bit auth tag, AAD = item metadata (see §4) |
| Auth verifier | derived from **AK** | client sends AK (or a server-salted hash of AK); server stores only `Argon2id`/HMAC verifier of it — never AK in the clear at rest |
| Randomness | `crypto.getRandomValues` / WASM CSPRNG | all salts, IVs, generated passwords |

### 3.1 IV/nonce discipline

A fresh 12-byte random IV is generated for **every** encryption operation and
stored alongside the ciphertext. GCM is catastrophic under IV reuse with the
same key, so IVs are never derived deterministically and never reused. Re-saving
an item re-encrypts it with a new IV.

### 3.2 Why Argon2id (not PBKDF2/scrypt)

Argon2id is memory-hard and the current password-hashing competition winner,
resisting GPU/ASIC brute-forcing far better than PBKDF2. Web Crypto lacks a
native Argon2, so we ship a vetted, pinned WASM build and verify its behavior
against known test vectors in Phase 1.

---

## 4. What is stored and what crosses the wire

### 4.1 Per vault item (server-stored)

```jsonc
{
  "id": "uuid",
  "userId": "uuid",
  "ciphertext": "base64",   // AES-256-GCM output (the item JSON, encrypted)
  "iv": "base64",           // 12 random bytes, unique per encryption
  "authTag": "base64",      // 128-bit GCM tag (may be appended to ciphertext)
  "createdAt": "...",
  "updatedAt": "...",
  "version": 0              // optimistic-concurrency / conflict handling
}
```

The server sees **none** of: title, username, password, URL, notes, card
numbers, TOTP secrets. Those live only inside `ciphertext`.

### 4.2 AAD (additional authenticated data)

Stable, non-secret fields that must not be swapped between items are bound into
the GCM AAD — at minimum `id` and `userId`. This prevents an attacker who can
write to the database from relocating a victim's ciphertext under a different
item id without detection (the tag check fails).

### 4.3 Auth handshake (registration/login)

- **Register:** client generates `userSalt`, derives MK → AK, sends
  `{ email, userSalt, authVerifierInput }`. Server stores `userSalt` + a
  server-side verifier (e.g. Argon2id of the received auth value with its own
  salt). The master password and VK never leave the device.
- **Login:** client requests `userSalt` by email, re-derives MK → AK, proves
  knowledge of AK to the server. On success the server issues a session token.
  The vault key VK is re-derived locally to decrypt items; it is held in memory
  only while unlocked.

---

## 5. Session, auto-lock, and key lifetime in memory

- VK and MK exist only as non-extractable `CryptoKey` handles where the Web
  Crypto API allows; the raw master password string is zeroed/dropped as soon as
  derivation completes.
- **Auto-lock** (Phase 2/6): after an idle timeout the in-memory keys are
  discarded and the user must re-enter the master password to re-derive them. A
  session token alone cannot unlock the vault.
- **Clipboard auto-clear** (Phase 6): copied secrets are cleared after a short
  delay.

---

## 6. Breach check (HIBP) — privacy preserving

Password breach checks (Phase 4) use the **HaveIBeenPwned k-anonymity range
API**: the client SHA-1 hashes a password, sends only the **first 5 hex chars**
of the hash, and matches the returned suffix list locally. The full hash and the
password never leave the device.

---

## 7. Test obligations (Phase 1 & 7)

The crypto core is not "done" until these pass:

1. **Known-answer vectors** for Argon2id, HKDF, and AES-256-GCM.
2. **Round-trip**: encrypt → decrypt returns the original plaintext for varied
   inputs (empty, unicode, large).
3. **Tamper detection**: flipping any byte of ciphertext, IV, tag, or AAD makes
   decryption throw (fail closed) — never returns garbage plaintext.
4. **Key independence**: VK derived for vault and AK derived for auth differ and
   neither can be derived from the other without MK.
5. **IV uniqueness**: N encryptions of the same plaintext under the same key
   yield N distinct IVs and N distinct ciphertexts.
6. **Network assertion** (Phase 7 e2e): captured traffic during register → add
   item → sync contains no plaintext field values and no master password.

---

## 8. Open questions / future revisions

- Argon2id parameters will be re-tuned as a config constant with a migration
  path (re-derive on next login if params change).
- Consider an encrypted "protected key" scheme (random VK encrypted *by* a
  password-derived key) to enable master-password change without re-encrypting
  every item. Tracked for Phase 3/5; the current model re-derives VK directly
  from the master password.
