import type {
  SupportedIdentity,
  Commitment,
  KeyWeaverConfig,
  RegisterWalletParams,
  RegisterWalletResult,
  RecoverWalletParams,
  RecoverWalletResult
} from '../../src/index.js';

export type Mode = 'demo' | 'live';
export type Provider = 'google' | 'github' | 'twitter' | 'passkey';

export interface AuthenticatedProvider {
  provider: Provider;
  displayName: string; // e.g., "user@gmail.com", "@user123"
  identity: SupportedIdentity;
}

// Wallet data interface (without mode tracking)
export interface WalletData {
  address: string;
  threshold: number;
  salt: string;
  commitments: Commitment[];
  privateKey?: string; // only in demo mode
}

export interface AppState {
  // UI Mode
  mode: Mode;
  
  // Demo Mode state
  selectedProviders: Provider[];
  
  // Live Mode state  
  authenticatedProviders: AuthenticatedProvider[];
  
  // Shared state
  threshold: number;
  isInitialized: boolean;
  
  // Mode-specific wallet state
  registeredWalletDemo?: WalletData;
  registeredWalletLive?: WalletData;
  
  // Derived convenience property (points to current mode's wallet)
  registeredWallet?: WalletData;
  
  // Recovery state
  latestRecoveryAttempt?: {
    usedProviders: Provider[];
    recoveredAddress?: string;
    matchesOriginal: boolean;
    success: boolean;
    error?: string;
    privateKey?: string; // only in demo mode
  };
  
  // Loading states
  isRegistering: boolean;
  isRecovering: boolean;
  isAuthenticating: Record<Provider, boolean>;
  
  // Live Mode session-only auth state
  liveAuthState: {
    mockProviderEmails: Record<'github' | 'twitter', string>;
    authErrors: Record<Provider, string | null>;
    googleAvailable: boolean;
    webAuthnAvailable: boolean;
  };
}

export interface StoredWalletData {
  address: string;
  threshold: number;
  salt: string;
  commitments: Commitment[];
  privateKey?: string;
  timestamp: number;
}

// Re-export library types for convenience
export type {
  SupportedIdentity,
  Commitment,
  KeyWeaverConfig,
  RegisterWalletParams,
  RegisterWalletResult,
  RecoverWalletParams,
  RecoverWalletResult
};