import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import * as secp256k1 from '@noble/secp256k1';
import { bytesToHex, utf8ToBytes, hexToBytes } from '@noble/hashes/utils';

/**
 * Typed commitment from a specific identity provider
 */
export interface TypedCommitment {
  provider: string;
  commitment: string; // hex string
}

/**
 * Parameters for deterministic key derivation
 */
export interface KeyDerivationParams {
  commitments: TypedCommitment[];  // All registered commitments (N total)
  threshold: number;               // Minimum required for access (K value, policy only)
  salt: string;                   // Hex-encoded salt (64 chars = 32 bytes)
}

/**
 * Result of key derivation
 */
export interface DerivedKeyResult {
  privateKey: string; // hex string (64 chars, no 0x prefix)
  address: string;    // 0x-prefixed EVM address
}

/**
 * Key Derivation Semantics:
 * 
 * The private key is deterministically derived from:
 * 1. All registered identity commitments (canonicalized)  
 * 2. User-provided salt (hex-encoded 32 bytes)
 * 
 * The threshold is a POLICY parameter that controls access requirements
 * but does NOT affect the derived key. This means:
 * - Same identities + salt = same key regardless of threshold
 * - Threshold can be changed without changing the wallet address
 * - Recovery requires K-of-N identities but derives from ALL N commitments
 */

/**
 * Validate that salt is a proper hex-encoded 32-byte string
 */
function isValidHexSalt(salt: string): boolean {
  return typeof salt === 'string' && 
         salt.length === 64 && 
         /^[0-9a-fA-F]{64}$/.test(salt);
}

/**
 * Canonicalize commitments for deterministic ordering
 * 
 * @param commitments - Array of typed commitments
 * @returns Canonical string representation
 */
function canonicalizeCommitments(commitments: TypedCommitment[]): string {
  // Normalize provider names to lowercase before sorting
  const normalized = commitments.map(c => ({
    provider: c.provider.toLowerCase().trim(),
    commitment: c.commitment
  }));

  // Sort by provider name (lexicographic), then by commitment hex (lexicographic)
  const sorted = [...normalized].sort((a, b) => {
    const providerCompare = a.provider.localeCompare(b.provider);
    if (providerCompare !== 0) return providerCompare;
    return a.commitment.localeCompare(b.commitment);
  });
  
  // Serialize with explicit separators
  return sorted.map(c => `${c.provider}:${c.commitment}`).join('|');
}

/**
 * Derive wallet private key and address deterministically
 * 
 * @param params - Key derivation parameters
 * @returns Private key and address
 * @throws {Error} If insufficient commitments for threshold
 */
export function deriveWalletKey(params: KeyDerivationParams): DerivedKeyResult {
  const { commitments, threshold, salt } = params;
  
  // Validation: ensure we have enough commitments for the threshold
  if (commitments.length < threshold) {
    throw new Error(
      `Insufficient commitments: need at least ${threshold}, have ${commitments.length}`
    );
  }
  
  // Step 1: Canonicalize all commitments for deterministic ordering
  const canonicalCommitments = canonicalizeCommitments(commitments);
  
  // Step 2: Validate and parse hex salt
  if (!isValidHexSalt(salt)) {
    throw new Error(`Invalid salt format: expected 64-char hex string, got ${salt.length} chars`);
  }
  const saltBytes = hexToBytes(salt);
  
  // Step 3: Create seed from domain separator, commitments, and salt
  const seedInput = `key-weaver:v1|${canonicalCommitments}|${salt}`;
  const seed = sha256(utf8ToBytes(seedInput));
  
  // Step 4: Derive private key using HKDF with salt as additional entropy
  const info = utf8ToBytes("key-weaver-hkdf");
  const keyMaterial = hkdf(sha256, seed, saltBytes, info, 32);
  
  // Step 5: Ensure valid secp256k1 scalar
  // Use correct curve order for noble secp256k1 v2.3.0
  const CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  
  let scalar = BigInt('0x' + bytesToHex(keyMaterial));
  
  // Ensure scalar is non-zero and less than curve order
  if (scalar === 0n || scalar >= CURVE_ORDER) {
    scalar = scalar % CURVE_ORDER;
    if (scalar === 0n) scalar = 1n; // Fallback to 1 if still zero
  }
  
  const privateKey = scalar.toString(16).padStart(64, '0');
  
  // Step 6: Derive public key and Ethereum-style address
  const publicKeyPoint = secp256k1.getPublicKey(privateKey, false); // uncompressed format
  
  // Remove the 0x04 prefix from uncompressed public key (65 bytes -> 64 bytes)
  const publicKeyBytes = publicKeyPoint.slice(1);
  
  // Keccak256 hash of public key bytes, take last 20 bytes for address
  const addressHash = keccak_256(publicKeyBytes);
  const address = '0x' + bytesToHex(addressHash.slice(-20));
  
  return {
    privateKey,
    address
  };
}

/**
 * Validate that a set of commitments meets the threshold requirement
 * without deriving the actual key
 */
/**
 * Validate that a set of commitments meets the threshold requirement
 * without deriving the actual key
 */
export function validateThreshold(commitments: TypedCommitment[], threshold: number): boolean {
  return commitments.length >= threshold;
}

/**
 * Validate and normalize a salt string to hex format
 * Accepts hex strings or converts arbitrary strings to deterministic hex
 */
export function normalizeSalt(input: string): string {
  // If already valid hex salt, return as-is
  if (isValidHexSalt(input)) {
    return input.toLowerCase();
  }
  
  // Convert arbitrary string to deterministic hex salt
  // Use SHA256 to ensure exactly 32 bytes (64 hex chars)
  const saltBytes = sha256(utf8ToBytes(input));
  return bytesToHex(saltBytes);
}

/**
 * Check if a salt string is valid hex format
 */
export function isValidSalt(salt: string): boolean {
  return isValidHexSalt(salt);
}