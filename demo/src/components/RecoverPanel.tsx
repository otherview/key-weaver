import React from 'react';
import type { Mode, Provider, AuthenticatedProvider, AppState } from '../types.js';
import { 
  getAvailableIdentities,
  getThresholdProgress,
  truncateAddress,
  PROVIDER_DISPLAY_NAMES
} from '../utils.js';

interface RecoverPanelProps {
  mode: Mode;
  selectedProviders: Provider[];
  authenticatedProviders: AuthenticatedProvider[];
  registeredWallet?: AppState['registeredWallet'];
  latestRecoveryAttempt?: AppState['latestRecoveryAttempt'];
  isRecovering: boolean;
  onRecover: () => void;
}

export const RecoverPanel: React.FC<RecoverPanelProps> = ({
  mode,
  selectedProviders,
  authenticatedProviders,
  registeredWallet,
  latestRecoveryAttempt,
  isRecovering,
  onRecover
}) => {
  const canRecover = registeredWallet && getAvailableIdentities(mode, selectedProviders, authenticatedProviders).length > 0;
  const availableProviders = mode === 'demo' ? selectedProviders : authenticatedProviders.map(a => a.provider);
  
  const progress = registeredWallet 
    ? getThresholdProgress(mode, selectedProviders, authenticatedProviders, registeredWallet.threshold)
    : { current: 0, required: 0, total: 4 };

  const renderThresholdProgress = () => {
    if (!registeredWallet) return null;
    
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
        <div className="progress-label">Threshold Progress:</div>
        <div className="progress-indicators">
          {indicators}
        </div>
        <div className="progress-text">
          ({progress.current} / {progress.required})
        </div>
      </div>
    );
  };

  return (
    <div className="panel recover-panel">
      <h2>🔄 Recover Wallet</h2>
      
      <div className="wallet-info">
        {registeredWallet ? (
          <>
            <div className="info-item">
              <strong>Stored wallet:</strong>
              <code title={registeredWallet.address}>
                {truncateAddress(registeredWallet.address)}
              </code>
            </div>
            <div className="info-item">
              <strong>Threshold:</strong> {registeredWallet.threshold} of 4
            </div>
          </>
        ) : (
          <div className="no-wallet">
            No wallet registered yet.
          </div>
        )}
      </div>

      {registeredWallet && (
        <>
          <div className="available-identities">
            <strong>Available identities:</strong>
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
          
          {renderThresholdProgress()}
          
          {progress.current < progress.required && (
            <div className="insufficient-warning">
              <span className="warning-icon">⚠️</span>
              Need {progress.required - progress.current} more identities to attempt recovery.
              {mode === 'demo' ? ' Select more checkboxes in Identity panel.' : ' Authenticate with more providers in Identity panel.'}
            </div>
          )}
        </>
      )}

      <button
        className="recover-button"
        onClick={onRecover}
        disabled={!canRecover || isRecovering}
      >
        {isRecovering ? 'Recovering...' : 'Recover Wallet'}
      </button>

      {latestRecoveryAttempt && (
        <div className={`recovery-result ${latestRecoveryAttempt.success ? 'success' : 'failure'}`}>
          {latestRecoveryAttempt.success ? (
            <>
              <div className="result-header">
                <span className="success-icon">✔</span>
                Recovered
              </div>
              
              <div className="result-details">
                <div className="result-item">
                  <strong>Address:</strong>
                  <code title={latestRecoveryAttempt.recoveredAddress}>
                    {latestRecoveryAttempt.recoveredAddress && truncateAddress(latestRecoveryAttempt.recoveredAddress)}
                  </code>
                </div>
                
                <div className="result-item">
                  <strong>Status:</strong>
                  <span className={`match-status ${latestRecoveryAttempt.matchesOriginal ? 'matches' : 'no-match'}`}>
                    {latestRecoveryAttempt.matchesOriginal ? '✅ Matches original' : '❌ Does not match'}
                  </span>
                </div>
                
                <div className="result-item">
                  <strong>Used providers:</strong>
                  <span className="used-providers">
                    {latestRecoveryAttempt.usedProviders.map(p => PROVIDER_DISPLAY_NAMES[p]).join(', ')}
                  </span>
                </div>
                
                {mode === 'demo' && latestRecoveryAttempt.privateKey && (
                  <div className="result-item private-key">
                    <strong>Private Key (demo only):</strong>
                    <code title={latestRecoveryAttempt.privateKey}>
                      {truncateAddress(latestRecoveryAttempt.privateKey, 16)}
                    </code>
                  </div>
                )}
              </div>
            </>
          ) : (
            <>
              <div className="result-header">
                <span className="error-icon">❌</span>
                Recovery Failed
              </div>
              
              <div className="result-details">
                <div className="result-item">
                  <strong>Error:</strong>
                  <span className="error-message">{latestRecoveryAttempt.error}</span>
                </div>
                
                <div className="result-item">
                  <strong>Attempted with:</strong>
                  <span className="used-providers">
                    {latestRecoveryAttempt.usedProviders.map(p => PROVIDER_DISPLAY_NAMES[p]).join(', ')}
                  </span>
                </div>
                
                {registeredWallet && progress.current < progress.required && (
                  <div className="hint">
                    💡 <strong>Hint:</strong> Select at least {progress.required} identities and try again.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};