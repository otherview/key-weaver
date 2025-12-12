import type { 
  Provider, 
  Mode,
  SupportedIdentity, 
  AuthenticatedProvider,
  StoredWalletData 
} from './types.js';

// Mode-specific localStorage keys for complete isolation
const STORAGE_KEY_DEMO = 'keyWeaverDemo_demo';
const STORAGE_KEY_LIVE = 'keyWeaverDemo_live';

// Create deterministic Google JWT (same sub every time)
function createDeterministicGoogleJWT(): string {
  // JWT format: header.payload.signature (all base64 encoded)
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  
  // Always same payload for deterministic behavior
  const payload = btoa(JSON.stringify({
    sub: 'google-user-123',
    email: 'demo@example.com',
    name: 'Demo User',
    iat: 1640000000, // Fixed timestamp
    exp: 2640000000  // Fixed expiration
  }));
  
  const signature = 'mock-signature-for-demo';
  return `${header}.${payload}.${signature}`;
}

// Demo Mode: deterministic identities (same across reloads)
export const DEMO_IDENTITIES: Record<Provider, SupportedIdentity> = {
  google: {
    provider: 'google',
    idToken: createDeterministicGoogleJWT()
  },
  github: {
    provider: 'github',
    accessToken: 'github-user-abc'
  },
  twitter: {
    provider: 'twitter',
    accessToken: 'twitter-user-xyz'
  },
  passkey: {
    provider: 'passkey',
    assertion: {
      credentialId: 'passkey-device-001',
      clientDataJSON: 'mock-client-data',
      authenticatorData: 'mock-auth-data',
      signature: 'mock-signature'
    }
  }
};

// Display names for UI
export const PROVIDER_DISPLAY_NAMES: Record<Provider, string> = {
  google: 'Google',
  github: 'GitHub',
  twitter: 'Twitter',
  passkey: 'Passkey'
};

// Demo mode mock display values
export const DEMO_DISPLAY_VALUES: Record<Provider, string> = {
  google: 'google-user-123',
  github: 'github-user-abc',
  twitter: 'twitter-user-xyz',
  passkey: 'passkey-device-001'
};

// Live Mode: stubbed authentication functions
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export const authProviders = {
  google: async (): Promise<{ identity: SupportedIdentity; displayName: string }> => {
    await delay(1000);
    return {
      identity: {
        provider: 'google',
        idToken: createDeterministicGoogleJWT() // Will be real JWT later
      },
      displayName: 'user@example.com' // Will extract from real JWT
    };
  },
  
  github: async (): Promise<{ identity: SupportedIdentity; displayName: string }> => {
    await delay(800);
    return {
      identity: {
        provider: 'github',
        accessToken: 'real-github-token-stub'
      },
      displayName: '@demouser' // Will extract from GitHub API
    };
  },
  
  twitter: async (): Promise<{ identity: SupportedIdentity; displayName: string }> => {
    await delay(1200);
    return {
      identity: {
        provider: 'twitter',
        accessToken: 'real-twitter-token-stub'
      },
      displayName: '@user123' // Will extract from Twitter API
    };
  },
  
  passkey: async (): Promise<{ identity: SupportedIdentity; displayName: string }> => {
    await delay(500);
    return {
      identity: {
        provider: 'passkey',
        assertion: {
          credentialId: 'real-passkey-cred-id-12345',
          clientDataJSON: 'real-client-data',
          authenticatorData: 'real-auth-data', 
          signature: 'real-signature'
        }
      },
      displayName: 'YubiKey-01' // Will extract from credentialId
    };
  }
};

// Extract meaningful display name from identity
export function extractDisplayName(identity: SupportedIdentity): string {
  switch (identity.provider) {
    case 'google':
      try {
        // For real JWT, extract email from token
        const payload = JSON.parse(atob(identity.idToken.split('.')[1]));
        return payload.email || payload.sub || 'Google User';
      } catch {
        return 'Google User';
      }
    
    case 'github':
      // For real GitHub, would extract username from API
      return '@githubuser';
    
    case 'twitter':
      // For real Twitter, would extract handle from API
      return '@twitteruser';
    
    case 'passkey':
      // Use last 8 chars of credentialId
      const credId = identity.assertion.credentialId;
      return `Device-${credId.slice(-8)}`;
    
    default:
      return 'Unknown';
  }
}

// Mode-specific localStorage utilities for complete isolation
export function saveToLocalStorage(mode: Mode, wallet: Omit<StoredWalletData, 'timestamp'>): void {
  const walletData: StoredWalletData = {
    ...wallet,
    timestamp: Date.now()
  };
  const storageKey = mode === 'demo' ? STORAGE_KEY_DEMO : STORAGE_KEY_LIVE;
  localStorage.setItem(storageKey, JSON.stringify(walletData));
}

export function loadFromLocalStorage(mode: Mode): StoredWalletData | null {
  try {
    const storageKey = mode === 'demo' ? STORAGE_KEY_DEMO : STORAGE_KEY_LIVE;
    const stored = localStorage.getItem(storageKey);
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
}

export function clearStoredWallet(mode: Mode): void {
  const storageKey = mode === 'demo' ? STORAGE_KEY_DEMO : STORAGE_KEY_LIVE;
  localStorage.removeItem(storageKey);
}

// Additional utilities for dev/debug purposes
export function clearAllWalletData(): void {
  localStorage.removeItem(STORAGE_KEY_DEMO);
  localStorage.removeItem(STORAGE_KEY_LIVE);
}

export function getAllWalletData(): { demo: StoredWalletData | null; live: StoredWalletData | null } {
  return {
    demo: loadFromLocalStorage('demo'),
    live: loadFromLocalStorage('live')
  };
}

// Helper functions
export function getAvailableIdentities(
  mode: Mode,
  selectedProviders: Provider[],
  authenticatedProviders: AuthenticatedProvider[]
): SupportedIdentity[] {
  if (mode === 'demo') {
    return selectedProviders.map(provider => DEMO_IDENTITIES[provider]);
  } else {
    return authenticatedProviders.map(auth => auth.identity);
  }
}

export function getCurrentProviders(
  mode: Mode,
  selectedProviders: Provider[],
  authenticatedProviders: AuthenticatedProvider[]
): Provider[] {
  if (mode === 'demo') {
    return selectedProviders;
  } else {
    return authenticatedProviders.map(auth => auth.provider);
  }
}

export function canRegister(
  mode: Mode,
  selectedProviders: Provider[],
  authenticatedProviders: AuthenticatedProvider[],
  threshold: number
): boolean {
  const availableCount = getAvailableIdentities(mode, selectedProviders, authenticatedProviders).length;
  return availableCount >= threshold && threshold >= 1;
}

export function getThresholdProgress(
  mode: Mode,
  selectedProviders: Provider[],
  authenticatedProviders: AuthenticatedProvider[],
  threshold: number
) {
  const available = getAvailableIdentities(mode, selectedProviders, authenticatedProviders).length;
  return { 
    current: available, 
    required: threshold, 
    total: 4 
  };
}

export function formatThreshold(threshold: number): string {
  const descriptions: Record<number, string> = {
    1: 'Weak',
    2: 'Balanced', 
    3: 'Strong',
    4: 'Extreme'
  };
  return descriptions[threshold] || '';
}

export function truncateAddress(address: string, length: number = 10): string {
  if (address.length <= length) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}