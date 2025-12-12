import { test } from 'node:test';
import { strictEqual } from 'node:assert';
import type {
  GoogleIdentity,
  GitHubIdentity,
  PasskeyIdentity,
  SupportedIdentity,
  Commitment,
  Wallet
} from '../index.js';

test('types should compile correctly', () => {
  const googleIdentity: GoogleIdentity = {
    provider: 'google',
    idToken: 'eyJ...'
  };

  const githubIdentity: GitHubIdentity = {
    provider: 'github',
    accessToken: 'gho_...'
  };

  const passkeyIdentity: PasskeyIdentity = {
    provider: 'passkey',
    assertion: {
      credentialId: 'cred123',
      clientDataJSON: '{}',
      authenticatorData: 'auth123',
      signature: 'sig123'
    }
  };

  const supportedIdentities: SupportedIdentity[] = [
    googleIdentity,
    githubIdentity,
    passkeyIdentity
  ];

  const commitment: Commitment = {
    claim: {
      provider: 'google',
      stableId: 'user123'
    },
    commitment: '0xabc123...'
  };

  const wallet: Wallet = {
    address: '0x742d35cc6e7c67b9b8f8d6bac8f8b8f1c6e7c67b',
    signMessage: async (message: string) => `signature_of_${message}`,
    signTx: async (txData: any) => `signature_of_${JSON.stringify(txData)}`
  };

  strictEqual(supportedIdentities.length, 3);
  strictEqual(commitment.claim.provider, 'google');
  strictEqual(wallet.address.startsWith('0x'), true);
});