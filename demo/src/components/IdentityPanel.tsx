import React, { useState } from 'react';
import type { Mode, Provider, AuthenticatedProvider, AppState } from '../types.js';
import { 
  PROVIDER_DISPLAY_NAMES, 
  DEMO_DISPLAY_VALUES,
  getThresholdProgress
} from '../utils.js';
import { ProviderStatusBadge } from './ProviderStatusBadge.js';
import { GoogleAuthButton } from './GoogleAuthButton.js';
import { PasskeyAuthButton } from './PasskeyAuthButton.js';
import { MockProviderModal } from './MockProviderModal.js';

interface IdentityPanelProps {
  mode: Mode;
  selectedProviders: Provider[];
  authenticatedProviders: AuthenticatedProvider[];
  isAuthenticating: Record<Provider, boolean>;
  liveAuthState: AppState['liveAuthState'];
  onProviderToggle: (provider: Provider) => void;
  onAuthenticate: (provider: Provider, displayName: string, identity: any) => void;
  onRemoveAuth: (provider: Provider) => void;
  onAuthError: (provider: Provider, error: string) => void;
  onMockEmailUpdate: (provider: 'github' | 'twitter', email: string) => void;
  threshold: number;
}

const ALL_PROVIDERS: Provider[] = ['google', 'github', 'twitter', 'passkey'];

export const IdentityPanel: React.FC<IdentityPanelProps> = ({
  mode,
  selectedProviders,
  authenticatedProviders,
  isAuthenticating,
  liveAuthState,
  onProviderToggle,
  onAuthenticate,
  onRemoveAuth,
  onAuthError,
  onMockEmailUpdate,
  threshold
}) => {
  const [mockModal, setMockModal] = useState<{ provider: 'github' | 'twitter'; isOpen: boolean } | null>(null);
  
  const progress = getThresholdProgress(mode, selectedProviders, authenticatedProviders, threshold);
  
  const renderThresholdProgress = () => {
    const indicators = Array.from({ length: 4 }, (_, i) => (
      <span 
        key={i} 
        className={`progress-dot ${i < progress.current ? 'filled' : 'empty'}`}
      >
        {i < progress.current ? '●' : '○'}
      </span>
    ));
    
    return (
      <div className="threshold-progress">
        <div className="progress-indicators">
          {indicators}
        </div>
        <div className="progress-text">
          ({progress.current} / {progress.total})
        </div>
      </div>
    );
  };

  const renderDemoMode = () => (
    <div className="demo-identity-selector">
      <div className="identity-list">
        {ALL_PROVIDERS.map(provider => (
          <label key={provider} className="identity-item">
            <input
              type="checkbox"
              checked={selectedProviders.includes(provider)}
              onChange={() => onProviderToggle(provider)}
            />
            <div className="identity-info">
              <div className="identity-name">
                {PROVIDER_DISPLAY_NAMES[provider]}
              </div>
              <div className="identity-value">
                → {DEMO_DISPLAY_VALUES[provider]}
              </div>
            </div>
          </label>
        ))}
      </div>
    </div>
  );

  const getProviderType = (provider: Provider): { isReal: boolean } => {
    switch (provider) {
      case 'google':
      case 'passkey':
        return { isReal: true };
      case 'github':
      case 'twitter':
        return { isReal: false };
      default:
        return { isReal: false };
    }
  };

  const renderLiveProviderRow = (provider: Provider) => {
    const { isReal } = getProviderType(provider);
    const authenticated = authenticatedProviders.find(p => p.provider === provider);
    const isLoading = isAuthenticating[provider];
    const error = liveAuthState.authErrors[provider];

    return (
      <div key={provider} className={`live-provider-row ${authenticated ? 'authenticated' : ''}`}>
        <div className="provider-header">
          <div className="provider-title">
            <span className="provider-name">{PROVIDER_DISPLAY_NAMES[provider]}</span>
            <ProviderStatusBadge isReal={isReal} />
          </div>
          
          {authenticated && (
            <div className="provider-status authenticated">
              <span className="status-icon">✓</span>
              <span className="status-text">{authenticated.displayName}</span>
              <button 
                className="remove-button"
                onClick={() => onRemoveAuth(provider)}
                title="Remove authentication"
              >
                ✗
              </button>
            </div>
          )}
        </div>

        {!authenticated && (
          <div className="provider-auth-section">
            {isLoading && (
              <div className="provider-status loading">
                <span className="loading-spinner">⏳</span>
                <span className="status-text">Authenticating...</span>
              </div>
            )}
            
            {error && (
              <div className="provider-error">
                <span className="error-icon">⚠️</span>
                <span className="error-text">{error}</span>
              </div>
            )}
            
            {!isLoading && renderAuthButton(provider, authenticated)}
          </div>
        )}
      </div>
    );
  };

  const renderAuthButton = (provider: Provider, authenticated: AuthenticatedProvider | undefined) => {
    switch (provider) {
      case 'google':
        if (!liveAuthState.googleAvailable) {
          return (
            <div className="provider-unavailable">
              <span className="unavailable-icon">⚠️</span>
              <span>Google Sign-In is unavailable (blocked or failed to load)</span>
            </div>
          );
        }
        return (
          <GoogleAuthButton
            onSuccess={(displayName, identity) => {
              onAuthenticate(provider, displayName, identity);
            }}
            onError={(error) => {
              onAuthError(provider, error);
            }}
            disabled={isAuthenticating[provider]}
          />
        );

      case 'passkey':
        if (!liveAuthState.webAuthnAvailable) {
          return (
            <div className="provider-unavailable">
              <span className="unavailable-icon">⚠️</span>
              <span>Passkeys are not supported in this browser</span>
            </div>
          );
        }
        return (
          <PasskeyAuthButton
            onSuccess={(displayName, identity) => {
              onAuthenticate(provider, displayName, identity);
            }}
            onError={(error) => {
              onAuthError(provider, error);
            }}
            disabled={isAuthenticating[provider]}
            mode={authenticated ? 'authenticate' : 'register'}
          />
        );

      case 'github':
      case 'twitter':
        return (
          <button
            className="mock-auth-button"
            onClick={() => setMockModal({ provider, isOpen: true })}
            disabled={isAuthenticating[provider]}
          >
            <span className="mock-icon">📧</span>
            <span>Simulate {PROVIDER_DISPLAY_NAMES[provider]} Login</span>
          </button>
        );

      default:
        return null;
    }
  };

  const handleMockSignIn = (provider: 'github' | 'twitter', email: string) => {
    setMockModal(null);
    onMockEmailUpdate(provider, email);
    
    // Create mock identity (let SDK handle the hashing)
    const identity = {
      provider,
      accessToken: email
    };
    
    onAuthenticate(provider, email, identity);
  };

  const renderLiveMode = () => (
    <div className="live-identity-authenticator">
      <div className="provider-list">
        {ALL_PROVIDERS.map(renderLiveProviderRow)}
      </div>
      
      {/* Mock Provider Modal */}
      {mockModal && (
        <MockProviderModal
          provider={mockModal.provider}
          isOpen={mockModal.isOpen}
          initialEmail={liveAuthState.mockProviderEmails[mockModal.provider]}
          onClose={() => setMockModal(null)}
          onSignIn={(email) => handleMockSignIn(mockModal.provider, email)}
        />
      )}
    </div>
  );

  return (
    <div className="panel identity-panel">
      <h2>🔐 Identity Factors</h2>
      
      {mode === 'demo' ? (
        <p className="panel-description">
          Select which mock identities you "have" available:
        </p>
      ) : (
        <div className="panel-description">
          <p>Authenticate with real providers. Sessions reset on reload.</p>
          {authenticatedProviders.length < threshold && (
            <div className="recovery-hint">
              💡 To recover this wallet after reload, re-authenticate with at least {threshold} of the providers you originally used.
            </div>
          )}
        </div>
      )}
      
      {mode === 'demo' ? renderDemoMode() : renderLiveMode()}
      
      <div className="threshold-section">
        <div className="threshold-label">
          <strong>Threshold Progress:</strong>
        </div>
        {renderThresholdProgress()}
      </div>
    </div>
  );
};