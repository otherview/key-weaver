export class InvalidIdentityTokenError extends Error {
  readonly provider: string;
  
  constructor(provider: string, reason?: string) {
    super(`Invalid ${provider} token: ${reason || 'token validation failed'}`);
    this.name = 'InvalidIdentityTokenError';
    this.provider = provider;
  }
}

export class InsufficientIdentitiesError extends Error {
  readonly provided: number;
  readonly required: number;
  
  constructor(provided: number, required: number) {
    super(`Insufficient identities: provided ${provided}, required ${required}`);
    this.name = 'InsufficientIdentitiesError';
    this.provided = provided;
    this.required = required;
  }
}

export class KeyDerivationError extends Error {
  constructor(reason?: string) {
    super(`Key derivation failed: ${reason || 'unknown error'}`);
    this.name = 'KeyDerivationError';
  }
}

export class KeyWeaverNotInitializedError extends Error {
  constructor() {
    super('Key Weaver system not initialized. Call initKeyWeaver() first.');
    this.name = 'KeyWeaverNotInitializedError';
  }
}