import type { SupportedIdentity } from '../types.js';

interface PasskeyAuthResult {
  identity: SupportedIdentity;
  displayName: string;
}

// WebAuthn utility functions
function uint8ArrayToBase64url(uint8Array: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...uint8Array));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


class WebAuthnAuthService {
  private available = false;
  private initialized = false;

  constructor() {
    this.checkAvailability();
  }

  private checkAvailability(): void {
    this.available = !!(
      window.PublicKeyCredential && 
      navigator.credentials && 
      typeof navigator.credentials.create === 'function' &&
      typeof navigator.credentials.get === 'function'
    );
    this.initialized = true;
  }

  isAvailable(): boolean {
    if (!this.initialized) {
      this.checkAvailability();
    }
    return this.available;
  }

  async register(): Promise<PasskeyAuthResult> {
    if (!this.isAvailable()) {
      throw new Error('Passkeys are not supported in this browser');
    }

    try {
      // Generate random user ID and challenge
      const userId = crypto.getRandomValues(new Uint8Array(32));
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const createOptions: PublicKeyCredentialCreationOptions = {
        rp: {
          id: window.location.hostname,
          name: 'Key Weaver Demo',
        },
        user: {
          id: userId,
          name: 'passkey-user',
          displayName: 'Passkey User',
        },
        challenge: challenge,
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'preferred',
          residentKey: 'preferred',
        },
        attestation: 'none',
        timeout: 60000,
      };

      const credential = await navigator.credentials.create({
        publicKey: createOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Passkey registration was cancelled');
      }

      const response = credential.response as AuthenticatorAttestationResponse;
      
      // Create identity for SDK
      const identity: SupportedIdentity = {
        provider: 'passkey',
        assertion: {
          credentialId: credential.id,
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(response.clientDataJSON)),
          authenticatorData: uint8ArrayToBase64url(new Uint8Array(response.getAuthenticatorData())),
          signature: uint8ArrayToBase64url(new Uint8Array(response.attestationObject)), // Using attestationObject for registration
        },
      };

      // Create display name from credential ID (last 8 characters)
      const displayName = `...${credential.id.slice(-8)}`;

      return {
        identity,
        displayName,
      };
    } catch (error: any) {
      // Handle user cancellation silently
      if (error.name === 'NotAllowedError' || error.message?.includes('cancelled')) {
        throw new Error('Passkey registration was cancelled');
      }
      
      // Handle other WebAuthn errors
      if (error.name === 'InvalidStateError') {
        throw new Error('A passkey for this device already exists');
      }
      
      throw new Error(`Passkey registration failed: ${error.message || error}`);
    }
  }

  async authenticate(): Promise<PasskeyAuthResult> {
    if (!this.isAvailable()) {
      throw new Error('Passkeys are not supported in this browser');
    }

    try {
      // Generate random challenge
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const getOptions: PublicKeyCredentialRequestOptions = {
        challenge: challenge,
        timeout: 60000,
        userVerification: 'preferred',
        // No allowCredentials - let authenticator choose
      };

      const credential = await navigator.credentials.get({
        publicKey: getOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Passkey authentication was cancelled');
      }

      const response = credential.response as AuthenticatorAssertionResponse;
      
      // Create identity for SDK
      const identity: SupportedIdentity = {
        provider: 'passkey',
        assertion: {
          credentialId: credential.id,
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(response.clientDataJSON)),
          authenticatorData: uint8ArrayToBase64url(new Uint8Array(response.authenticatorData)),
          signature: uint8ArrayToBase64url(new Uint8Array(response.signature)),
        },
      };

      // Create display name from credential ID (last 8 characters)
      const displayName = `...${credential.id.slice(-8)}`;

      return {
        identity,
        displayName,
      };
    } catch (error: any) {
      // Handle user cancellation silently
      if (error.name === 'NotAllowedError' || error.message?.includes('cancelled')) {
        throw new Error('Passkey authentication was cancelled');
      }
      
      // Handle no credentials found
      if (error.name === 'InvalidStateError') {
        throw new Error('No passkeys found for this device');
      }
      
      throw new Error(`Passkey authentication failed: ${error.message || error}`);
    }
  }
}

// Export singleton instance
export const webAuthnAuthService = new WebAuthnAuthService();