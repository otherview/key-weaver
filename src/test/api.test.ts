import { test } from 'node:test';
import { strictEqual, rejects } from 'node:assert';
import { 
  initKeyWeaver, 
  registerWallet, 
  recoverWallet,
  createSignerFromPrivateKey,
  InsufficientIdentitiesError,
  deriveWalletKey,
  normalizeSalt,
  isValidSalt
} from '../index.js';
import type { SupportedIdentity, TypedCommitment } from '../index.js';

test('Full API Integration', async (t) => {
  // Initialize the system
  await initKeyWeaver({ version: 'v1' });

  await t.test('registerWallet → recoverWallet with same address', async () => {
    // Create test identities
    const mockGooglePayload = btoa(JSON.stringify({
      sub: "google_user_123",
      email: "user@example.com"
    }));

    const identities: SupportedIdentity[] = [
      {
        provider: 'google',
        idToken: `eyJhbGciOiJSUzI1NiJ9.${mockGooglePayload}.signature`
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

    // Register wallet
    const registration = await registerWallet({
      identities,
      threshold: 2
    });

    strictEqual(typeof registration.address, 'string');
    strictEqual(registration.address.startsWith('0x'), true);
    strictEqual(registration.address.length, 42);
    strictEqual(registration.commitments.length, 3);
    strictEqual(typeof registration.salt, 'string');
    strictEqual(registration.privateKey, undefined); // Not exposed by default

    // Recover with full identity set
    const recoveryFull = await recoverWallet({
      identities,
      commitments: registration.commitments,
      salt: registration.salt,
      threshold: 2
    });

    strictEqual(recoveryFull.success, true);
    strictEqual(recoveryFull.matchedCount, 3);
    strictEqual(recoveryFull.wallet.address, registration.address);
    strictEqual(recoveryFull.privateKey, undefined); // Not exposed by default

    // Recover with minimum threshold (2 out of 3)
    const recoveryMinimum = await recoverWallet({
      identities: identities.slice(0, 2), // Only first 2 identities
      commitments: registration.commitments,
      salt: registration.salt,
      threshold: 2
    });

    strictEqual(recoveryMinimum.success, true);
    strictEqual(recoveryMinimum.matchedCount, 2);
    strictEqual(recoveryMinimum.wallet.address, registration.address);

    // Try recovery with insufficient identities
    const recoveryInsufficient = await recoverWallet({
      identities: identities.slice(0, 1), // Only 1 identity
      commitments: registration.commitments,
      salt: registration.salt,
      threshold: 2
    });

    strictEqual(recoveryInsufficient.success, false);
    strictEqual(recoveryInsufficient.matchedCount, 1);
  });

  await t.test('private key exposure in demo mode', async () => {
    const identities: SupportedIdentity[] = [
      {
        provider: 'google',
        idToken: `eyJhbGciOiJSUzI1NiJ9.${btoa(JSON.stringify({ sub: "test_user" }))}.sig`
      },
      {
        provider: 'github',
        accessToken: 'test_token'
      }
    ];

    // Register with private key exposure
    const registration = await registerWallet({
      identities,
      threshold: 2,
      exposePrivateKey: true
    });

    strictEqual(typeof registration.privateKey, 'string');
    strictEqual(registration.privateKey!.length, 64); // 32 bytes = 64 hex chars

    // Recover with private key exposure
    const recovery = await recoverWallet({
      identities,
      commitments: registration.commitments,
      salt: registration.salt,
      threshold: 2,
      exposePrivateKey: true
    });

    strictEqual(recovery.privateKey, registration.privateKey);
  });

  await t.test('threshold validation', async () => {
    const identities: SupportedIdentity[] = [
      {
        provider: 'google',
        idToken: `eyJhbGciOiJSUzI1NiJ9.${btoa(JSON.stringify({ sub: "test" }))}.sig`
      }
    ];

    // Should reject if threshold > available identities
    await rejects(
      () => registerWallet({ identities, threshold: 2 }),
      InsufficientIdentitiesError
    );
  });

  await t.test('createSignerFromPrivateKey', async () => {
    const privateKey = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    
    const signer = createSignerFromPrivateKey(privateKey);
    
    strictEqual(typeof signer.wallet.address, 'string');
    strictEqual(signer.wallet.address.startsWith('0x'), true);
    strictEqual(signer.privateKey, undefined); // Not exposed by default
    
    // Test with key exposure
    const signerWithKey = createSignerFromPrivateKey(privateKey, true);
    strictEqual(signerWithKey.privateKey, privateKey);
  });
});

test('Key Derivation Determinism', async (t) => {
  await t.test('same inputs produce same address', async () => {
    const commitments: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' },
      { provider: 'github', commitment: 'def456' },
      { provider: 'passkey', commitment: 'ghi789' }
    ];
    
    const salt = normalizeSalt('test-salt-123');
    const threshold = 2;

    // Derive same key multiple times
    const result1 = deriveWalletKey({ commitments, threshold, salt });
    const result2 = deriveWalletKey({ commitments, threshold, salt });
    
    strictEqual(result1.address, result2.address);
    strictEqual(result1.privateKey, result2.privateKey);
  });

  await t.test('shuffled commitments produce same address', async () => {
    const commitments1: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' },
      { provider: 'github', commitment: 'def456' },
      { provider: 'passkey', commitment: 'ghi789' }
    ];
    
    // Shuffle the order
    const commitments2: TypedCommitment[] = [
      { provider: 'passkey', commitment: 'ghi789' },
      { provider: 'google', commitment: 'abc123' },
      { provider: 'github', commitment: 'def456' }
    ];
    
    const salt = normalizeSalt('test-salt-123');
    const threshold = 2;

    const result1 = deriveWalletKey({ commitments: commitments1, threshold, salt });
    const result2 = deriveWalletKey({ commitments: commitments2, threshold, salt });
    
    strictEqual(result1.address, result2.address);
    strictEqual(result1.privateKey, result2.privateKey);
  });

  await t.test('different salt produces different address', async () => {
    const commitments: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' },
      { provider: 'github', commitment: 'def456' }
    ];
    
    const threshold = 2;

    const result1 = deriveWalletKey({ commitments, threshold, salt: normalizeSalt('salt1') });
    const result2 = deriveWalletKey({ commitments, threshold, salt: normalizeSalt('salt2') });
    
    strictEqual(result1.address !== result2.address, true);
    strictEqual(result1.privateKey !== result2.privateKey, true);
  });

  await t.test('threshold does not affect key derivation', async () => {
    const commitments: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' },
      { provider: 'github', commitment: 'def456' },
      { provider: 'passkey', commitment: 'ghi789' }
    ];
    
    const salt = normalizeSalt('test-salt-123');

    // Same commitments and salt, different thresholds
    const result1 = deriveWalletKey({ commitments, threshold: 2, salt });
    const result2 = deriveWalletKey({ commitments, threshold: 3, salt });
    
    strictEqual(result1.address, result2.address);
    strictEqual(result1.privateKey, result2.privateKey);
  });

  await t.test('provider name normalization', async () => {
    const commitments1: TypedCommitment[] = [
      { provider: 'Google', commitment: 'abc123' }, // Uppercase
      { provider: 'github', commitment: 'def456' }
    ];
    
    const commitments2: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' }, // Lowercase
      { provider: 'GitHub', commitment: 'def456' }  // Uppercase
    ];
    
    const salt = normalizeSalt('test-salt');
    const threshold = 2;

    const result1 = deriveWalletKey({ commitments: commitments1, threshold, salt });
    const result2 = deriveWalletKey({ commitments: commitments2, threshold, salt });
    
    strictEqual(result1.address, result2.address);
    strictEqual(result1.privateKey, result2.privateKey);
  });

  await t.test('insufficient commitments for threshold', async () => {
    const commitments: TypedCommitment[] = [
      { provider: 'google', commitment: 'abc123' }
    ];
    
    const salt = normalizeSalt('test-salt');
    const threshold = 2; // More than available commitments

    try {
      deriveWalletKey({ commitments, threshold, salt });
      strictEqual(false, true, 'Should have thrown an error');
    } catch (error) {
      strictEqual(error instanceof Error, true);
      strictEqual((error as Error).message.includes('Insufficient commitments'), true);
    }
  });
});

test('Salt Normalization and Validation', async (t) => {
  await t.test('normalizeSalt handles hex salts correctly', async () => {
    const validHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const normalizedHex = normalizeSalt(validHex);
    
    strictEqual(normalizedHex, validHex);
    strictEqual(isValidSalt(normalizedHex), true);
  });
  
  await t.test('normalizeSalt converts arbitrary strings to hex', async () => {
    const arbitraryString = 'my-custom-salt-123';
    const normalizedHex = normalizeSalt(arbitraryString);
    
    strictEqual(normalizedHex.length, 64);
    strictEqual(isValidSalt(normalizedHex), true);
    strictEqual(/^[0-9a-f]{64}$/.test(normalizedHex), true);
  });
  
  await t.test('same arbitrary string produces same hex salt', async () => {
    const input = 'test-salt';
    const result1 = normalizeSalt(input);
    const result2 = normalizeSalt(input);
    
    strictEqual(result1, result2);
  });
  
  await t.test('different arbitrary strings produce different hex salts', async () => {
    const result1 = normalizeSalt('salt-1');
    const result2 = normalizeSalt('salt-2');
    
    strictEqual(result1 !== result2, true);
    strictEqual(isValidSalt(result1), true);
    strictEqual(isValidSalt(result2), true);
  });
  
  await t.test('registerWallet and recoverWallet work with arbitrary salt', async () => {
    const identities: SupportedIdentity[] = [
      { provider: 'google', idToken: `eyJhbGciOiJSUzI1NiJ9.${btoa(JSON.stringify({ sub: 'test' }))}.sig` },
      { provider: 'github', accessToken: 'test_token' }
    ];
    
    // Use arbitrary string salt
    const arbitrarySalt = 'my-user-chosen-password-123';
    
    const registration = await registerWallet({
      identities,
      threshold: 2,
      salt: arbitrarySalt
    });
    
    // Verify salt was normalized to hex
    strictEqual(registration.salt.length, 64);
    strictEqual(isValidSalt(registration.salt), true);
    
    // Recovery should work with the same arbitrary salt  
    const recovery = await recoverWallet({
      identities,
      commitments: registration.commitments,
      salt: arbitrarySalt, // Same arbitrary salt
      threshold: 2
    });
    
    strictEqual(recovery.success, true);
    strictEqual(recovery.wallet.address, registration.address);
  });
});