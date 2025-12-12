// Main API exports
export {
  initKeyWeaver,
  registerWallet,
  recoverWallet,
  createSignerFromPrivateKey
} from './api/index.js';

// Type exports
export type {
  PasskeyAssertion,
  GoogleIdentity,
  GitHubIdentity,
  TwitterIdentity,
  PasskeyIdentity,
  SupportedIdentity,
  IdentityClaim,
  Commitment,
  Wallet,
  KeyWeaverConfig,
  RegisterWalletParams,
  RegisterWalletResult,
  RecoverWalletParams,
  RecoverWalletResult
} from './types/index.js';

// Error exports
export {
  InvalidIdentityTokenError,
  InsufficientIdentitiesError,
  KeyDerivationError,
  KeyWeaverNotInitializedError
} from './errors/index.js';

// Utility exports (for advanced usage)
export {
  extractIdentityClaim
} from './identity/index.js';

export {
  generateCommitments,
  computeCommitment,
  createRandomSalt,
  validateCommitment
} from './commitments/index.js';

// Key derivation exports (for advanced usage)
export {
  deriveWalletKey,
  validateThreshold,
  normalizeSalt,
  isValidSalt
} from './crypto/keyDerivation.js';

export type {
  TypedCommitment,
  KeyDerivationParams,
  DerivedKeyResult
} from './crypto/keyDerivation.js';