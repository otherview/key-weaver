import { test } from 'node:test';
import { strictEqual, deepStrictEqual, notStrictEqual } from 'node:assert';
import { 
  generateCommitments, 
  computeCommitment, 
  createRandomSalt, 
  validateCommitment 
} from '../commitments/index.js';
import { hashSha256 } from '../crypto/index.js';
import type { IdentityClaim } from '../types/index.js';

test('Commitment generation', async (t) => {
  await t.test('should generate deterministic commitments', () => {
    const claims: IdentityClaim[] = [
      { provider: 'google', stableId: 'google_user_123' },
      { provider: 'github', stableId: 'abcd1234...' }
    ];
    const salt = 'test_salt_123';

    const commitments1 = generateCommitments(claims, salt);
    const commitments2 = generateCommitments(claims, salt);

    deepStrictEqual(commitments1, commitments2);
    strictEqual(commitments1.length, 2);
    strictEqual(commitments1[0]!.claim.provider, 'google');
    strictEqual(commitments1[1]!.claim.provider, 'github');
  });

  await t.test('should generate different commitments for different salts', () => {
    const claim: IdentityClaim = { provider: 'google', stableId: 'user123' };
    
    const commitment1 = computeCommitment(claim, 'salt1');
    const commitment2 = computeCommitment(claim, 'salt2');

    notStrictEqual(commitment1, commitment2);
    strictEqual(commitment1.length, 64); // SHA256 hex
    strictEqual(commitment2.length, 64); // SHA256 hex
  });

  await t.test('should follow expected format: provider:stableId:salt', () => {
    const claim: IdentityClaim = { provider: 'test', stableId: 'id123' };
    const salt = 'salt456';
    
    const commitment = computeCommitment(claim, salt);
    
    // Verify it's deterministic by computing manually
    const expected = hashSha256('test:id123:salt456');
    strictEqual(commitment, expected);
  });
});

test('Salt generation', async (t) => {
  await t.test('should generate random salts', () => {
    const salt1 = createRandomSalt();
    const salt2 = createRandomSalt();

    notStrictEqual(salt1, salt2);
    strictEqual(salt1.length, 64); // 32 bytes * 2 hex chars
    strictEqual(salt2.length, 64);
    
    // Should be valid hex
    strictEqual(/^[0-9a-f]+$/i.test(salt1), true);
    strictEqual(/^[0-9a-f]+$/i.test(salt2), true);
  });
});

test('Commitment validation', async (t) => {
  await t.test('should validate correct commitments', () => {
    const claim: IdentityClaim = { provider: 'google', stableId: 'user123' };
    const salt = 'test_salt';
    const commitment = computeCommitment(claim, salt);

    const isValid = validateCommitment(claim, salt, commitment);
    strictEqual(isValid, true);
  });

  await t.test('should reject invalid commitments', () => {
    const claim: IdentityClaim = { provider: 'google', stableId: 'user123' };
    const salt = 'test_salt';
    const wrongCommitment = 'abc123wrong';

    const isValid = validateCommitment(claim, salt, wrongCommitment);
    strictEqual(isValid, false);
  });
});