/**
 * Byte <-> string encoding helpers.
 *
 * The wire format and the database store binary crypto material as base64
 * (CRYPTO.md §4.1). These helpers are environment-agnostic — they avoid Node's
 * `Buffer` so the same code runs in the browser, where the crypto core lives.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Coerce a `Uint8Array` to `BufferSource` for the Web Crypto API.
 *
 * TS 5.7 made `Uint8Array` generic over its backing buffer
 * (`Uint8Array<ArrayBufferLike>`), which no longer structurally matches the DOM
 * lib's `BufferSource` (it excludes `SharedArrayBuffer`). Our buffers are always
 * plain `ArrayBuffer`-backed; this narrows the type at `crypto.subtle` call
 * sites without copying.
 */
export function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/** UTF-8 encode a string to bytes. */
export function utf8ToBytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/** UTF-8 decode bytes to a string. */
export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** Standard base64 encode (browser `btoa`-compatible, chunked for large inputs). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000; // avoid arg-count limits on String.fromCharCode
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * Decode a standard base64 string to bytes.
 *
 * @throws Error if the input is not valid base64.
 */
export function base64ToBytes(b64: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(b64);
  } catch {
    throw new Error('base64ToBytes: input is not valid base64');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Lowercase hex encode. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Decode a hex string to bytes.
 *
 * @throws Error if the input has odd length or contains non-hex characters.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hexToBytes: input must have an even number of characters');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('hexToBytes: input contains non-hex characters');
    }
    out[i] = byte;
  }
  return out;
}
