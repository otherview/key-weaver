import React, { useEffect, useRef, useState } from 'react';
import { googleAuthService } from '../services/googleAuth.js';

interface GoogleAuthButtonProps {
  onSuccess: (displayName: string, identity: any) => void;
  onError: (error: string) => void;
  disabled?: boolean;
}

export const GoogleAuthButton: React.FC<GoogleAuthButtonProps> = ({
  onSuccess,
  onError,
  disabled = false,
}) => {
  const buttonRef = useRef<HTMLDivElement>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAvailable, setIsAvailable] = useState(false);

  useEffect(() => {
    const initializeGoogle = async () => {
      try {
        const available = await googleAuthService.initialize();
        setIsAvailable(available);
        
        if (available && buttonRef.current) {
          // Clear any existing button content
          buttonRef.current.innerHTML = '';
          
          // Render the Google button
          googleAuthService.renderButton(
            buttonRef.current,
            (result) => {
              onSuccess(result.displayName, result.identity);
            },
            (error) => {
              onError(error.message);
            }
          );
        }
      } catch (error: any) {
        console.error('Google Auth initialization failed:', error);
        setIsAvailable(false);
        onError('Google Sign-In failed to load');
      } finally {
        setIsLoading(false);
      }
    };

    initializeGoogle();
  }, [onSuccess, onError]);

  if (isLoading) {
    return (
      <div className="google-auth-placeholder">
        <div className="loading-spinner">⏳</div>
        <span>Loading Google Sign-In...</span>
      </div>
    );
  }

  if (!isAvailable) {
    return (
      <div className="google-auth-unavailable">
        <div className="unavailable-icon">⚠️</div>
        <span>Google Sign-In is unavailable (blocked or failed to load)</span>
      </div>
    );
  }

  return (
    <div className={`google-auth-container ${disabled ? 'disabled' : ''}`}>
      <div ref={buttonRef} />
      {disabled && (
        <div className="google-auth-overlay">
          <span>Already authenticated</span>
        </div>
      )}
    </div>
  );
};