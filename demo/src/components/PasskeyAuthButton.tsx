import React, { useState, useEffect } from 'react';
import { webAuthnAuthService } from '../services/webAuthnAuth.js';

interface PasskeyAuthButtonProps {
  onSuccess: (displayName: string, identity: any) => void;
  onError: (error: string) => void;
  disabled?: boolean;
  mode: 'register' | 'authenticate';
}

export const PasskeyAuthButton: React.FC<PasskeyAuthButtonProps> = ({
  onSuccess,
  onError,
  disabled = false,
  mode,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [isAvailable, setIsAvailable] = useState(false);

  useEffect(() => {
    setIsAvailable(webAuthnAuthService.isAvailable());
  }, []);

  const handleClick = async () => {
    if (disabled || !isAvailable) return;

    // 🛡️ DEFENSIVE GUARD: Prevent silent misuse
    if (mode === 'authenticate') {
      console.warn('[PasskeyAuthButton] Attempting to authenticate - ensure passkey exists');
    } else {
      console.log('[PasskeyAuthButton] Registering new passkey');
    }

    setIsLoading(true);
    try {
      let result;
      
      if (mode === 'register') {
        result = await webAuthnAuthService.register();
        console.log('[PasskeyAuthButton] Registration successful:', result.displayName);
      } else {
        result = await webAuthnAuthService.authenticate();
        console.log('[PasskeyAuthButton] Authentication successful:', result.displayName);
      }

      onSuccess(result.displayName, result.identity);
    } catch (error: any) {
      // Enhanced error logging for debugging
      if (mode === 'authenticate' && (error.message?.includes('No') || error.message?.includes('not available'))) {
        console.error('[PasskeyAuthButton] Authentication failed - likely no credential stored:', error.message);
        console.error('[PasskeyAuthButton] This suggests UI state desync - passkey should not show "Use Passkey" without existing credential');
      } else if (mode === 'register') {
        console.error('[PasskeyAuthButton] Registration failed:', error.message);
      }
      
      // Handle cancellation silently (don't show error)
      if (error.message?.includes('cancelled')) {
        console.log('[PasskeyAuthButton] User cancelled WebAuthn operation');
        return;
      }
      
      onError(error.message || 'Passkey operation failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isAvailable) {
    return (
      <div className="passkey-unavailable">
        <div className="unavailable-icon">⚠️</div>
        <span>Passkeys are not supported in this browser</span>
      </div>
    );
  }

  const buttonText = mode === 'register' ? 'Register Passkey' : 'Use Passkey';
  const loadingText = mode === 'register' ? 'Registering...' : 'Authenticating...';

  return (
    <button
      className={`passkey-auth-button ${disabled ? 'disabled' : ''} ${isLoading ? 'loading' : ''}`}
      onClick={handleClick}
      disabled={disabled || isLoading}
    >
      <div className="passkey-button-content">
        <span className="passkey-icon">🔐</span>
        <span className="passkey-text">
          {isLoading ? loadingText : buttonText}
        </span>
        {isLoading && <span className="loading-spinner">⏳</span>}
      </div>
    </button>
  );
};