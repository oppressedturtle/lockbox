export default function Home(): JSX.Element {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col items-center justify-center gap-6 px-6 text-center">
      <h1 className="text-4xl font-bold tracking-tight">
        Lock<span className="text-brand">Box</span>
      </h1>
      <p className="text-lg text-neutral-400">
        A zero-knowledge password manager. Your master password never leaves your device — the
        server only ever stores ciphertext.
      </p>
      <ul className="grid gap-3 text-left text-sm text-neutral-300">
        <li className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3">
          🔐 Argon2id key derivation + AES-256-GCM encryption, all client-side
        </li>
        <li className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3">
          🚫 Server stores encrypted blobs and an auth verifier — never your password
        </li>
        <li className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3">
          🧪 Crypto correctness verified with known test vectors
        </li>
      </ul>
      <p className="text-xs text-neutral-600">Phase 0 — foundation scaffold. Vault coming soon.</p>
    </main>
  );
}
