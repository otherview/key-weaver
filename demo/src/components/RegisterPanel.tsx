import React from 'react';
import type { Mode, Provider, AuthenticatedProvider, AppState } from '../types.js';
import { 
  canRegister, 
  getAvailableIdentities,
  formatThreshold,
  truncateAddress,
  PROVIDER_DISPLAY_NAMES
} from '../utils.js';

interface RegisterPanelProps {
  mode: Mode;
  selectedProviders: Provider[];
  authenticatedProviders: AuthenticatedProvider[];
  threshold: number;
  registeredWallet?: AppState['registeredWallet'];
  isRegistering: boolean;
  onThresholdChange: (threshold: number) => void;
  onRegister: () => void;
}

export const RegisterPanel: React.FC<RegisterPanelProps> = ({
  mode,
  selectedProviders,
  authenticatedProviders,
  threshold,
  registeredWallet,
  isRegistering,
  onThresholdChange,
  onRegister
}) => {
  const canRegisterWallet = canRegister(mode, selectedProviders, authenticatedProviders, threshold);
  const availableIdentities = getAvailableIdentities(mode, selectedProviders, authenticatedProviders);
  const availableProviders = mode === 'demo' ? selectedProviders : authenticatedProviders.map(a => a.provider);
  
  const insufficientProviders = threshold > availableIdentities.length;

  return (
    <div className="panel register-panel">
      <h2>🧱 Register Wallet</h2>
      
      <div className="register-section">
        <div className="identities-available">
          <strong>Identities available:</strong>
          <div className="identity-status-list">
            {(['google', 'github', 'twitter', 'passkey'] as Provider[]).map(provider => {
              const isAvailable = availableProviders.includes(provider);
              return (
                <div key={provider} className={`identity-status ${isAvailable ? 'available' : 'unavailable'}`}>
                  <span className="status-icon">{isAvailable ? '✓' : '✗'}</span>
                  {PROVIDER_DISPLAY_NAMES[provider]}
                </div>
              );
            })}
          </div>
        </div>
        
        <div className="threshold-selector">
          <label htmlFor="threshold">
            <strong>Threshold:</strong>
          </label>
          <div className="threshold-input">
            <select
              id="threshold"
              value={threshold}
              onChange={(e) => onThresholdChange(Number(e.target.value))}
              disabled={isRegistering}
            >
              {[1, 2, 3, 4].map(k => (
                <option key={k} value={k}>
                  {k} of 4
                </option>
              ))}
            </select>
            <div className="threshold-description">
              {formatThreshold(threshold)}
            </div>
          </div>
        </div>

        {insufficientProviders && (
          <div className="validation-error">
            <span className="error-icon">❌</span>
            Need at least {threshold} identities. You have {availableIdentities.length}.
            {mode === 'demo' ? ' Select more checkboxes above.' : ' Authenticate with more providers above.'}
          </div>
        )}

        <button
          className="register-button"
          onClick={onRegister}
          disabled={!canRegisterWallet || isRegistering}
        >
          {isRegistering ? 'Registering...' : 'Register Wallet'}
        </button>
      </div>

      {registeredWallet && (
        <div className="wallet-result">
          <div className="result-header">
            <span className="success-icon">✔</span>
            Wallet Created
          </div>
          
          <div className="result-details">
            <div className="result-item">
              <strong>Address:</strong>
              <code title={registeredWallet.address}>
                {truncateAddress(registeredWallet.address)}
              </code>
            </div>
            
            <div className="result-item">
              <strong>Salt:</strong>
              <code title={registeredWallet.salt}>
                {truncateAddress(registeredWallet.salt, 16)}
              </code>
            </div>
            
            <div className="result-item">
              <strong>Commitments:</strong>
              <div className="commitments-list">
                {registeredWallet.commitments.map((commitment, idx) => (
                  <div key={idx} className="commitment-item">
                    <span className="provider-name">
                      {PROVIDER_DISPLAY_NAMES[commitment.claim.provider as Provider]}:
                    </span>
                    <code title={commitment.commitment}>
                      {truncateAddress(commitment.commitment, 12)}
                    </code>
                  </div>
                ))}
              </div>
            </div>
            
            {mode === 'demo' && registeredWallet.privateKey && (
              <div className="result-item private-key">
                <strong>Private Key (demo only):</strong>
                <code title={registeredWallet.privateKey}>
                  {truncateAddress(registeredWallet.privateKey, 16)}
                </code>
              </div>
            )}
            
            <div className="storage-note">
              💾 Saved to localStorage.
            </div>
          </div>
        </div>
      )}
    </div>
  );
};