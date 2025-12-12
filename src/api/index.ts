import type {
  KeyWeaverConfig,
  RegisterWalletParams,
  RegisterWalletResult,
  RecoverWalletParams,
  RecoverWalletResult,
  Wallet,
  Commitment
} from '../types/index.js';
import { extractIdentityClaim } from '../identity/index.js';
import { generateCommitments, createRandomSalt, validateCommitment } from '../commitments/index.js';
import { deriveWalletKey, normalizeSalt, TypedCommitment } from '../crypto/keyDerivation.js';
import { createWalletFromPrivateKey } from '../crypto/index.js';
import { 
  InsufficientIdentitiesError, 
  KeyDerivationError 
} from '../errors/index.js';
import { initializeKeyWeaver, getKeyWeaverConfig } from './state.js';

export async function initKeyWeaver(config: KeyWeaverConfig): Promise<void> {
  // Initialize Key Weaver system
  // No WASM or proving keys needed - just store config
  initializeKeyWeaver(config);
}

export async function registerWallet(params: RegisterWalletParams): Promise<RegisterWalletResult> {
  getKeyWeaverConfig(); // Ensure initialized
  
  const { identities, threshold, salt: providedSalt, exposePrivateKey = false } = params;

  // Validate minimum threshold
  if (identities.length < threshold) {
    throw new InsufficientIdentitiesError(identities.length, threshold);
  }

  try {
    // Step 1: Extract identity claims from authenticated identities
    const claims = identities.map(extractIdentityClaim);

    // Step 2: Use provided salt (normalized) or generate random one
    const rawSalt = providedSalt || createRandomSalt();
    const salt = normalizeSalt(rawSalt);

    // Step 3: Generate commitments for all identities
    const commitments = generateCommitments(claims, salt);

    // Step 4: Convert commitments to TypedCommitment format for key derivation
    const typedCommitments: TypedCommitment[] = commitments.map(c => ({
      provider: c.claim.provider.toLowerCase().trim(),
      commitment: c.commitment
    }));

    // Step 5: Derive wallet key using ALL commitments
    const { privateKey, address } = deriveWalletKey({
      commitments: typedCommitments,
      threshold,
      salt
    });

    // Step 6: Return registration result
    const result: RegisterWalletResult = {
      commitments,
      salt,
      address
    };

    if (exposePrivateKey) {
      result.privateKey = privateKey;
    }

    return result;
  } catch (error) {
    throw new KeyDerivationError(
      error instanceof Error ? error.message : 'Registration failed'
    );
  }
}

export async function recoverWallet(params: RecoverWalletParams): Promise<RecoverWalletResult> {
  getKeyWeaverConfig(); // Ensure initialized
  
  const { identities, commitments, salt: rawSalt, threshold, exposePrivateKey = false } = params;
  const salt = normalizeSalt(rawSalt); // Normalize salt for consistency

  try {
    // Step 1: Extract identity claims from provided identities
    const claims = identities.map(extractIdentityClaim);

    // Step 2: Match provided identities against stored commitments
    const matchedCommitments: Commitment[] = [];
    let matchedCount = 0;

    for (const claim of claims) {
      const matchingCommitment = commitments.find(stored => 
        validateCommitment(claim, salt, stored.commitment)
      );
      
      if (matchingCommitment) {
        matchedCommitments.push(matchingCommitment);
        matchedCount++;
      }
    }

    // Step 3: Check if we have sufficient matches for threshold
    const success = matchedCount >= threshold;
    
    if (!success) {
      return {
        wallet: {} as Wallet, // Empty wallet object
        matchedCount,
        success: false,
      };
    }

    // Step 4: Convert ALL stored commitments to TypedCommitment format
    // CRITICAL: Use all original commitments, not just matched ones
    // This ensures deterministic key derivation regardless of which K identities were used
    const allTypedCommitments: TypedCommitment[] = commitments.map(c => ({
      provider: c.claim.provider.toLowerCase().trim(),
      commitment: c.commitment
    }));

    // Step 5: Derive wallet key using ALL stored commitments
    const { privateKey, address } = deriveWalletKey({
      commitments: allTypedCommitments,
      threshold,
      salt
    });

    // Step 6: Create wallet from derived private key
    const wallet = createWalletFromPrivateKey(privateKey);

    // Step 7: Verify derived address matches expected address
    if (wallet.address.toLowerCase() !== address.toLowerCase()) {
      throw new KeyDerivationError('Address mismatch during recovery');
    }

    // Step 8: Return successful recovery result
    const result: RecoverWalletResult = {
      wallet,
      matchedCount,
      success: true
    };

    if (exposePrivateKey) {
      result.privateKey = privateKey;
    }

    return result;
  } catch (error) {
    throw new KeyDerivationError(
      error instanceof Error ? error.message : 'Recovery failed'
    );
  }
}

export function createSignerFromPrivateKey(
  privateKey: string,
  exposePrivateKey?: boolean
): { wallet: Wallet; privateKey?: string } {
  try {
    const wallet = createWalletFromPrivateKey(privateKey);

    const result: { wallet: Wallet; privateKey?: string } = { wallet };

    if (exposePrivateKey) {
      result.privateKey = privateKey;
    }

    return result;
  } catch (error) {
    throw new KeyDerivationError(
      error instanceof Error ? error.message : 'Failed to create signer from private key'
    );
  }
}