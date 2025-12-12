import type { IdentityClaim } from './identity.js';

export interface Commitment {
  claim: IdentityClaim;
  commitment: string;
}