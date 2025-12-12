import type { IdentityClaim, Commitment } from '../types/index.js';
import { hashSha256, generateRandomSalt } from '../crypto/index.js';

export function generateCommitments(claims: IdentityClaim[], salt: string): Commitment[] {
  return claims.map(claim => ({
    claim,
    commitment: computeCommitment(claim, salt)
  }));
}

export function computeCommitment(claim: IdentityClaim, salt: string): string {
  // C_i = SHA256(provider + ':' + stableId + ':' + salt)
  const input = `${claim.provider}:${claim.stableId}:${salt}`;
  return hashSha256(input);
}

export function createRandomSalt(): string {
  return generateRandomSalt();
}

export function validateCommitment(claim: IdentityClaim, salt: string, expectedCommitment: string): boolean {
  const actualCommitment = computeCommitment(claim, salt);
  return actualCommitment === expectedCommitment;
}