import type { SupportedIdentity } from '../types.js';

// Google Identity Services types
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: any) => void;
          renderButton: (element: HTMLElement, config: any) => void;
          prompt: () => void;
        };
      };
    };
  }
}

interface GoogleCredentialResponse {
  credential: string; // JWT ID token
  select_by: string;
}

interface GoogleAuthResult {
  identity: SupportedIdentity;
  displayName: string;
}

// JWT payload interface (for decoding)
interface GoogleJWTPayload {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
  iat: number;
  exp: number;
}

class GoogleAuthService {
  private initialized = false;
  private available = false;
  private clientId: string;

  constructor() {
    this.clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';
  }

  async initialize(): Promise<boolean> {
    if (this.initialized) {
      return this.available;
    }

    try {
      // Check if client ID is configured
      if (!this.clientId) {
        console.warn('Google Auth: VITE_GOOGLE_CLIENT_ID not configured - Google Sign-In will be unavailable');
        console.info('Google Auth: To enable Google Sign-In, set VITE_GOOGLE_CLIENT_ID in .env.local (local) or GitHub secrets (production)');
        this.available = false;
        this.initialized = true;
        return false;
      }

      // Load Google Identity Services script if not already loaded
      if (!window.google) {
        await this.loadGoogleScript();
      }

      // Initialize Google Identity Services
      if (window.google?.accounts?.id) {
        window.google.accounts.id.initialize({
          client_id: this.clientId,
          callback: () => {}, // We'll handle callbacks per button
          auto_select: false,
          cancel_on_tap_outside: true,
        });

        this.available = true;
      } else {
        this.available = false;
      }
    } catch (error) {
      console.error('Google Auth initialization failed:', error);
      this.available = false;
    }

    this.initialized = true;
    return this.available;
  }

  private async loadGoogleScript(): Promise<void> {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Failed to load Google Identity Services'));
      
      document.head.appendChild(script);
    });
  }

  isAvailable(): boolean {
    return this.initialized && this.available;
  }

  // Note: This method is unused in current implementation
  // We use renderButton() directly for Google Sign-In button integration

  renderButton(element: HTMLElement, onSuccess: (result: GoogleAuthResult) => void, onError: (error: Error) => void): void {
    if (!this.isAvailable()) {
      onError(new Error('Google Authentication is not available'));
      return;
    }

    // Create callback function directly
    const callbackFunction = (response: GoogleCredentialResponse) => {
      try {
        const result = this.handleCredentialResponse(response);
        onSuccess(result);
      } catch (error) {
        onError(error as Error);
      }
    };

    // Initialize with button-specific callback
    window.google!.accounts.id.initialize({
      client_id: this.clientId,
      callback: callbackFunction,
    });

    // Render the button
    window.google!.accounts.id.renderButton(element, {
      theme: 'outline',
      size: 'large',
      width: 280,
      text: 'signin_with',
      shape: 'rectangular',
    });
  }

  private handleCredentialResponse(response: GoogleCredentialResponse): GoogleAuthResult {
    try {
      // Decode JWT (no signature verification in this phase)
      const payload = this.decodeJWT(response.credential);
      
      // Create identity for SDK
      const identity: SupportedIdentity = {
        provider: 'google',
        idToken: response.credential,
      };

      // Create display name (prefer email, fallback to sub)
      const displayName = payload.email || payload.sub || 'Google User';

      return {
        identity,
        displayName,
      };
    } catch (error) {
      throw new Error(`Failed to process Google credential: ${error}`);
    }
  }

  private decodeJWT(token: string): GoogleJWTPayload {
    try {
      // Split JWT into parts
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      // Decode payload (base64url)
      const payload = parts[1];
      // Add padding if needed
      const paddedPayload = payload + '='.repeat((4 - payload.length % 4) % 4);
      const decodedPayload = atob(paddedPayload.replace(/-/g, '+').replace(/_/g, '/'));
      
      return JSON.parse(decodedPayload) as GoogleJWTPayload;
    } catch (error) {
      throw new Error(`JWT decode failed: ${error}`);
    }
  }
}

// Export singleton instance
export const googleAuthService = new GoogleAuthService();