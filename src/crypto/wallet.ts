import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import type { Wallet } from '../types/index.js';

// Set up HMAC for secp256k1 (required for deterministic signatures)
// TODO: In production, this needs to be configured properly for signing
// For now, focus on key derivation and address generation

export function createWalletFromPrivateKey(privateKey: string): Wallet {
  // Derive address from private key
  const publicKeyPoint = secp256k1.getPublicKey(privateKey, false);
  const publicKeyBytes = publicKeyPoint.slice(1);
  
  // Use keccak256 for EVM-style address
  const addressHash = keccak_256(publicKeyBytes);
  const address = '0x' + bytesToHex(addressHash.slice(-20));

  return {
    address,

    async signMessage(message: string): Promise<string> {
      // Create message hash (EIP-191 personal sign format)
      const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
      const messageHash = sha256(utf8ToBytes(prefix + message));
      
      // TODO: Implement secp256k1 signing with proper HMAC setup
      // For now, return deterministic mock signature based on message + private key
      const mockSignature = sha256(utf8ToBytes(bytesToHex(messageHash) + privateKey));
      return bytesToHex(mockSignature) + '1b'; // Mock recovery byte
    },

    async signTx(txData: any): Promise<string> {
      // Stub implementation - in real usage this would serialize transaction
      // according to EIP-155 or EIP-1559 and sign the hash
      const txString = JSON.stringify(txData);
      const txHash = sha256(utf8ToBytes(txString));
      
      // TODO: Implement secp256k1 signing with proper HMAC setup
      // For now, return deterministic mock signature
      const mockSignature = sha256(utf8ToBytes(bytesToHex(txHash) + privateKey));
      return bytesToHex(mockSignature) + '1b'; // Mock recovery byte
    }
  };
}