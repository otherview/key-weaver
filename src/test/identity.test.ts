import { test } from 'node:test';
import { strictEqual, throws } from 'node:assert';
import { extractIdentityClaim } from '../identity/adapters.js';
import { InvalidIdentityTokenError } from '../errors/index.js';
import type { GoogleIdentity, GitHubIdentity, TwitterIdentity, PasskeyIdentity } from '../types/index.js';

test('Google identity adapter', async (t) => {
  await t.test('should extract sub from valid JWT', () => {
    // Create a mock JWT: header.payload.signature
    // payload = {"sub":"google_user_123","email":"user@example.com","iat":1234567890}
    const mockPayload = btoa(JSON.stringify({
      sub: "google_user_123",
      email: "user@example.com", 
      iat: 1234567890
    }));
    
    const mockJwt = `eyJhbGciOiJSUzI1NiJ9.${mockPayload}.mock_signature`;
    
    const googleIdentity: GoogleIdentity = {
      provider: 'google',
      idToken: mockJwt
    };

    const claim = extractIdentityClaim(googleIdentity);
    
    strictEqual(claim.provider, 'google');
    strictEqual(claim.stableId, 'google_user_123');
  });

  await t.test('should throw on malformed JWT', () => {
    const googleIdentity: GoogleIdentity = {
      provider: 'google',
      idToken: 'invalid.jwt'
    };

    throws(() => extractIdentityClaim(googleIdentity), InvalidIdentityTokenError);
  });

  await t.test('should throw on missing sub claim', () => {
    const mockPayload = btoa(JSON.stringify({
      email: "user@example.com",
      iat: 1234567890
    }));
    
    const mockJwt = `eyJhbGciOiJSUzI1NiJ9.${mockPayload}.mock_signature`;
    
    const googleIdentity: GoogleIdentity = {
      provider: 'google',
      idToken: mockJwt
    };

    throws(() => extractIdentityClaim(googleIdentity), InvalidIdentityTokenError);
  });
});

test('GitHub identity adapter', async (t) => {
  await t.test('should generate deterministic pseudo-ID', () => {
    const githubIdentity: GitHubIdentity = {
      provider: 'github',
      accessToken: 'gho_test_token_123'
    };

    const claim1 = extractIdentityClaim(githubIdentity);
    const claim2 = extractIdentityClaim(githubIdentity);
    
    strictEqual(claim1.provider, 'github');
    strictEqual(claim1.stableId, claim2.stableId); // Deterministic
    strictEqual(claim1.stableId.length, 64); // SHA256 hex output
  });

  await t.test('should throw on missing access token', () => {
    const githubIdentity = {
      provider: 'github',
      accessToken: ''
    } as GitHubIdentity;

    throws(() => extractIdentityClaim(githubIdentity), InvalidIdentityTokenError);
  });
});

test('Twitter identity adapter', async (t) => {
  await t.test('should generate deterministic pseudo-ID', () => {
    const twitterIdentity: TwitterIdentity = {
      provider: 'twitter',
      accessToken: 'twitter_token_xyz_123'
    };

    const claim1 = extractIdentityClaim(twitterIdentity);
    const claim2 = extractIdentityClaim(twitterIdentity);
    
    strictEqual(claim1.provider, 'twitter');
    strictEqual(claim1.stableId, claim2.stableId); // Deterministic
    strictEqual(claim1.stableId.length, 64); // SHA256 hex output
  });

  await t.test('should throw on missing access token', () => {
    const twitterIdentity = {
      provider: 'twitter',
      accessToken: ''
    } as TwitterIdentity;

    throws(() => extractIdentityClaim(twitterIdentity), InvalidIdentityTokenError);
  });

  await t.test('should differ from GitHub with same token', () => {
    const token = 'same_token_123';
    
    const twitterIdentity: TwitterIdentity = {
      provider: 'twitter',
      accessToken: token
    };
    
    const githubIdentity: GitHubIdentity = {
      provider: 'github',
      accessToken: token
    };

    const twitterClaim = extractIdentityClaim(twitterIdentity);
    const githubClaim = extractIdentityClaim(githubIdentity);
    
    // Same token should produce different stableIds for different providers
    strictEqual(twitterClaim.stableId !== githubClaim.stableId, true);
    strictEqual(twitterClaim.provider, 'twitter');
    strictEqual(githubClaim.provider, 'github');
  });
});

test('Passkey identity adapter', async (t) => {
  await t.test('should use credentialId as stableId', () => {
    const passkeyIdentity: PasskeyIdentity = {
      provider: 'passkey',
      assertion: {
        credentialId: 'cred_123_abc',
        clientDataJSON: '{"type":"webauthn.get"}',
        authenticatorData: 'auth_data_123',
        signature: 'signature_123'
      }
    };

    const claim = extractIdentityClaim(passkeyIdentity);
    
    strictEqual(claim.provider, 'passkey');
    strictEqual(claim.stableId, 'cred_123_abc');
  });

  await t.test('should throw on missing credentialId', () => {
    const passkeyIdentity = {
      provider: 'passkey',
      assertion: {
        credentialId: '',
        clientDataJSON: '{"type":"webauthn.get"}',
        authenticatorData: 'auth_data_123',
        signature: 'signature_123'
      }
    } as PasskeyIdentity;

    throws(() => extractIdentityClaim(passkeyIdentity), InvalidIdentityTokenError);
  });
});