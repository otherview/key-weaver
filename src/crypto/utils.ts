import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export function getRandomBytes(length: number): Uint8Array {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    // Browser environment
    return crypto.getRandomValues(new Uint8Array(length));
  } else if (typeof globalThis !== 'undefined' && (globalThis as any).crypto && (globalThis as any).crypto.getRandomValues) {
    // Node.js 18+ with globalThis.crypto
    return (globalThis as any).crypto.getRandomValues(new Uint8Array(length));
  } else {
    // Fallback: Use Math.random (not cryptographically secure, but works for testing)
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  }
}

export function generateRandomSalt(): string {
  const bytes = getRandomBytes(32); // 256 bits
  return bytesToHex(bytes);
}

export function hashSha256(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const hash = sha256(bytes);
  return bytesToHex(hash);
}

export function base64urlToString(input: string): string {
  // Convert base64url to base64
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  
  // Add padding if needed
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  else if (pad !== 0) throw new Error("Invalid base64url");

  // Decode to bytes then to string
  const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}