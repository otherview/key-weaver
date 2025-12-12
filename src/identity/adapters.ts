import type { 
  SupportedIdentity, 
  GoogleIdentity, 
  GitHubIdentity, 
  TwitterIdentity,
  PasskeyIdentity, 
  IdentityClaim 
} from '../types/index.js';
import { InvalidIdentityTokenError } from '../errors/index.js';
import { base64urlToString, hashSha256 } from '../crypto/index.js';

export function extractIdentityClaim(identity: SupportedIdentity): IdentityClaim {
  switch (identity.provider) {
    case 'google':
      return extractGoogleClaim(identity);
    case 'github':
      return extractGitHubClaim(identity);
    case 'twitter':
      return extractTwitterClaim(identity);
    case 'passkey':
      return extractPasskeyClaim(identity);
    default:
      // TypeScript exhaustiveness check
      const never: never = identity;
      throw new Error(`Unsupported provider: ${(never as any).provider}`);
  }
}

function extractGoogleClaim(identity: GoogleIdentity): IdentityClaim {
  try {
    // JWT format: header.payload.signature
    const parts = identity.idToken.split('.');
    if (parts.length !== 3) {
      throw new InvalidIdentityTokenError('google', 'malformed JWT - expected 3 parts');
    }

    // Decode payload (middle part)
    const payloadJson = base64urlToString(parts[1]!);
    const payload = JSON.parse(payloadJson);

    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new InvalidIdentityTokenError('google', 'missing or invalid sub claim');
    }

    return {
      provider: 'google',
      stableId: payload.sub
    };
  } catch (error) {
    if (error instanceof InvalidIdentityTokenError) {
      throw error;
    }
    throw new InvalidIdentityTokenError('google', `token decode failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

function extractGitHubClaim(identity: GitHubIdentity): IdentityClaim {
  if (!identity.accessToken || typeof identity.accessToken !== 'string') {
    throw new InvalidIdentityTokenError('github', 'missing or invalid accessToken');
  }

  // Generate deterministic pseudo-ID from access token (include provider for uniqueness)
  const stableId = hashSha256(`github:${identity.accessToken}`);

  return {
    provider: 'github',
    stableId
  };
}

function extractTwitterClaim(identity: TwitterIdentity): IdentityClaim {
  if (!identity.accessToken || typeof identity.accessToken !== 'string') {
    throw new InvalidIdentityTokenError('twitter', 'missing or invalid accessToken');
  }

  // Generate deterministic pseudo-ID from access token (include provider for uniqueness)
  const stableId = hashSha256(`twitter:${identity.accessToken}`);

  return {
    provider: 'twitter',
    stableId
  };
}

function extractPasskeyClaim(identity: PasskeyIdentity): IdentityClaim {
  const { assertion } = identity;
  
  if (!assertion.credentialId || typeof assertion.credentialId !== 'string') {
    throw new InvalidIdentityTokenError('passkey', 'missing or invalid credentialId');
  }

  return {
    provider: 'passkey',
    stableId: assertion.credentialId
  };
}