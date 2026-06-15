import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'LockBox — Zero-Knowledge Password Manager',
  description:
    'A zero-knowledge password manager. All encryption happens in your browser; the server only ever stores ciphertext.',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>): JSX.Element {
  return (
    <html lang="en">
      <body className="font-sans">{children}</body>
    </html>
  );
}
