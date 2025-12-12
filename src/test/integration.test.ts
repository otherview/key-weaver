import { test } from 'node:test';
import { strictEqual, deepStrictEqual } from 'node:assert';
import { extractIdentityClaim } from '../identity/index.js';
import { generateCommitments, createRandomSalt } from '../commitments/index.js';
import type { SupportedIdentity, IdentityClaim, Commitment } from '../types/index.js';

test('Full pipeline: identities → claims → commitments', async (t) => {
  await t.test('should process mixed identities to deterministic commitments', () => {
    // Step 1: Create test identities
    const mockGooglePayload = btoa(JSON.stringify({
      sub: "google_user_123",
      email: "user@gmail.com"
    }));
    const mockGoogleJwt = `eyJhbGciOiJSUzI1NiJ9.${mockGooglePayload}.signature`;

    const identities: SupportedIdentity[] = [
      {
        provider: 'google',
        idToken: mockGoogleJwt
      },
      {
        provider: 'github', 
        accessToken: 'gho_test_token_456'
      },
      {
        provider: 'passkey',
        assertion: {
          credentialId: 'passkey_cred_789',
          clientDataJSON: '{"type":"webauthn.get"}',
          authenticatorData: 'auth_data',
          signature: 'sig_data'
        }
      }
    ];

    // Step 2: Extract identity claims
    const claims: IdentityClaim[] = identities.map(extractIdentityClaim);
    
    strictEqual(claims.length, 3);
    strictEqual(claims[0]!.provider, 'google');
    strictEqual(claims[0]!.stableId, 'google_user_123');
    strictEqual(claims[1]!.provider, 'github');
    strictEqual(claims[1]!.stableId.length, 64); // SHA256 of access token
    strictEqual(claims[2]!.provider, 'passkey');
    strictEqual(claims[2]!.stableId, 'passkey_cred_789');

    // Step 3: Generate commitments with fixed salt
    const salt = 'fixed_test_salt_for_determinism';
    const commitments: Commitment[] = generateCommitments(claims, salt);

    strictEqual(commitments.length, 3);
    
    // Each commitment should contain the claim and computed commitment
    strictEqual(commitments[0]!.claim.provider, 'google');
    strictEqual(commitments[0]!.commitment.length, 64); // SHA256 hex
    
    strictEqual(commitments[1]!.claim.provider, 'github');
    strictEqual(commitments[1]!.commitment.length, 64);
    
    strictEqual(commitments[2]!.claim.provider, 'passkey');
    strictEqual(commitments[2]!.commitment.length, 64);

    // Step 4: Verify determinism - same inputs should produce same outputs
    const claims2 = identities.map(extractIdentityClaim);
    const commitments2 = generateCommitments(claims2, salt);
    
    deepStrictEqual(commitments, commitments2);
  });

  await t.test('should demonstrate privacy: only commitments need to be stored', () => {
    const mockPayload = btoa(JSON.stringify({sub:"sensitive_user_id"}));
    const identities: SupportedIdentity[] = [
      {
        provider: 'google',
        idToken: `eyJhbGciOiJSUzI1NiJ9.${mockPayload}.sig`
      }
    ];

    const claims = identities.map(extractIdentityClaim);
    const salt = createRandomSalt();
    const commitments = generateCommitments(claims, salt);

    // For privacy, caller can extract just the commitment strings
    const commitmentStrings = commitments.map(c => c.commitment);
    
    strictEqual(commitmentStrings.length, 1);
    strictEqual(commitmentStrings[0]!.length, 64);
    
    // The commitment reveals nothing about the original identity
    strictEqual(commitmentStrings[0]!.includes('sensitive_user_id'), false);
    strictEqual(commitmentStrings[0]!.includes('google'), false);
  });

  await t.test('should generate unique commitments for different salts', () => {
    const mockPayload = btoa(JSON.stringify({sub:"user123"}));
    const identity: SupportedIdentity = {
      provider: 'google',
      idToken: `eyJhbGciOiJSUzI1NiJ9.${mockPayload}.sig`
    };

    const claim = extractIdentityClaim(identity);
    
    const salt1 = 'salt_1';
    const salt2 = 'salt_2';
    
    const commitments1 = generateCommitments([claim], salt1);
    const commitments2 = generateCommitments([claim], salt2);

    // Same identity, different salts → different commitments
    strictEqual(commitments1[0]!.commitment !== commitments2[0]!.commitment, true);
    
    // But same claim structure
    deepStrictEqual(commitments1[0]!.claim, commitments2[0]!.claim);
  });
});