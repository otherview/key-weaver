import type { SupportedIdentity } from './identity.js';
import type { Commitment } from './commitment.js';
import type { Wallet } from './wallet.js';

export interface KeyWeaverConfig {
  /** Currently unused but reserved for future key derivation config */
  version?: string;
}

export interface RegisterWalletParams {
  identities: SupportedIdentity[];
  threshold: number;
  salt?: string; // Optional: if not provided, will be auto-generated
  exposePrivateKey?: boolean;
}

export interface RegisterWalletResult {
  commitments: Commitment[];
  salt: string;
  address: string;
  privateKey?: string;
}

export interface RecoverWalletParams {
  identities: SupportedIdentity[];
  commitments: Commitment[]; // Stored commitments from registration
  salt: string;
  threshold: number;
  exposePrivateKey?: boolean;
}

export interface RecoverWalletResult {
  wallet: Wallet;
  matchedCount: number; // Number of identities that matched stored commitments
  success: boolean;     // Whether recovery succeeded (matchedCount >= threshold)
  privateKey?: string;
}