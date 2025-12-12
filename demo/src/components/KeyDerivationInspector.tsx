import React from 'react';
import type { Mode, Provider, AppState, WalletData } from '../types.js';
import { PROVIDER_DISPLAY_NAMES } from '../utils.js';

interface KeyDerivationInspectorProps {
  mode: Mode;
  registeredWallet?: WalletData;
  latestRecoveryAttempt?: AppState['latestRecoveryAttempt'];
}

export const KeyDerivationInspector: React.FC<KeyDerivationInspectorProps> = ({
  mode,
  registeredWallet,
  latestRecoveryAttempt
}) => {
  // Handle no wallet case
  if (!registeredWallet) {
    return (
      <div className="key-inspector-container">
        <div className="key-inspector-empty">
          No wallet exists in {mode === 'demo' ? 'Demo' : 'Live'} mode
        </div>
      </div>
    );
  }


  // Helper for address verification status
  const getVerificationStatus = () => {
    if (!latestRecoveryAttempt) {
      return { icon: '⏳', text: 'No recovery attempt yet', className: 'pending' };
    }
    
    if (!latestRecoveryAttempt.success) {
      return { icon: '❌', text: 'Recovery failed', className: 'error' };
    }
    
    const matches = latestRecoveryAttempt.recoveredAddress === registeredWallet.address;
    return {
      icon: matches ? '✅' : '❌',
      text: matches ? 'Derived address matches wallet' : 'Address mismatch',
      className: matches ? 'success' : 'error'
    };
  };

  // Helper for private key comparison (Demo mode only)
  const getPrivateKeyStatus = () => {
    if (mode !== 'demo' || !registeredWallet.privateKey || !latestRecoveryAttempt?.privateKey) {
      return null;
    }
    
    const matches = latestRecoveryAttempt.privateKey === registeredWallet.privateKey;
    return {
      icon: matches ? '✅' : '❌',
      text: matches ? 'Private keys match' : 'Private key mismatch',
      className: matches ? 'success' : 'error'
    };
  };

  // Helper for recovery status
  const getRecoveryStatus = () => {
    if (!latestRecoveryAttempt) return null;
    
    const { success } = latestRecoveryAttempt;
    // Note: matchedCount and threshold info not available in current recovery result
    return {
      icon: success ? '✅' : '❌',
      text: success ? 'Recovery successful' : 'Recovery failed',
      className: success ? 'success' : 'error'
    };
  };

  const verificationStatus = getVerificationStatus();
  const privateKeyStatus = getPrivateKeyStatus();
  const recoveryStatus = getRecoveryStatus();

  return (
    <div className="key-inspector-container">
      <div className="key-inspector">
        <div className="inspector-header">
          <div className="inspector-title">🔍 Key Derivation Inspector</div>
          <div className="inspector-subtitle">
            Deterministic key derivation from K-of-{registeredWallet.commitments.length} identity factors
          </div>
        </div>

        {/* Section 1: Identity Commitments */}
        <div className="inspector-section">
          <div className="inspector-section-title">1. IDENTITY COMMITMENTS</div>
          <div className="inspector-section-content">
            <div className="identity-list">
              {registeredWallet.commitments.map((c, i) => (
                <div key={i} className="identity-row">
                  <div className="identity-provider">
                    <span className="provider-badge">
                      {PROVIDER_DISPLAY_NAMES[c.claim.provider as Provider] || c.claim.provider}
                    </span>
                  </div>
                  <div className="identity-commitment">
                    <code>{c.commitment.slice(0, 12)}...{c.commitment.slice(-8)}</code>
                  </div>
                </div>
              ))}
            </div>
            <div className="commitment-note">
              <strong>Note:</strong> Commitments are computed as H(provider || stableId || salt)
            </div>
          </div>
        </div>

        {/* Section 2: Threshold Policy */}
        <div className="inspector-section">
          <div className="inspector-section-title">2. THRESHOLD POLICY</div>
          <div className="inspector-section-content">
            <div className="threshold-display">
              <span className="threshold-value">K = {registeredWallet.threshold}</span>
              <span className="threshold-total">N = {registeredWallet.commitments.length}</span>
            </div>
            <div className="threshold-note">
              <strong>Policy-only parameter:</strong> Threshold controls access but does NOT affect key derivation
            </div>
          </div>
        </div>

        {/* Section 3: Salt */}
        <div className="inspector-section">
          <div className="inspector-section-title">3. USER SALT</div>
          <div className="inspector-section-content">
            <div className="salt-value">
              <code>{registeredWallet.salt.slice(0, 16)}...{registeredWallet.salt.slice(-16)}</code>
            </div>
            <div className="salt-note">
              <strong>Entropy source:</strong> User-provided or randomly generated salt
            </div>
          </div>
        </div>

        {/* Section 4: Key Derivation Seed */}
        <div className="inspector-section">
          <div className="inspector-section-title">4. DETERMINISTIC SEED</div>
          <div className="inspector-section-content">
            <div className="seed-formula">
              <code>
                seed = SHA256("key-weaver:v1" || canonical_commitments || salt)
              </code>
            </div>
            <div className="seed-note">
              <strong>Canonical ordering:</strong> Commitments sorted by provider, then by commitment value
            </div>
          </div>
        </div>

        {/* Section 5: Derived Address */}
        <div className="inspector-section">
          <div className="inspector-section-title">5. DERIVED ADDRESS</div>
          <div className="inspector-section-content">
            <div className="address-display">
              <code className="address-value">{registeredWallet.address}</code>
              <div className={`address-status ${verificationStatus.className}`}>
                <span className="status-icon">{verificationStatus.icon}</span>
                <span className="status-text">{verificationStatus.text}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 6: Private Key (Demo mode only) */}
        {mode === 'demo' && registeredWallet.privateKey && (
          <div className="inspector-section">
            <div className="inspector-section-title">6. PRIVATE KEY (DEMO ONLY)</div>
            <div className="inspector-section-content">
              <div className="private-key-display">
                <code className="private-key-value">
                  {registeredWallet.privateKey.slice(0, 8)}...{registeredWallet.privateKey.slice(-8)}
                </code>
                {privateKeyStatus && (
                  <div className={`private-key-status ${privateKeyStatus.className}`}>
                    <span className="status-icon">{privateKeyStatus.icon}</span>
                    <span className="status-text">{privateKeyStatus.text}</span>
                  </div>
                )}
              </div>
              <div className="private-key-warning">
                <strong>Warning:</strong> Private keys are never exposed in Live mode
              </div>
            </div>
          </div>
        )}

        {/* Section 7: Recovery Status */}
        {latestRecoveryAttempt && (
          <div className="inspector-section">
            <div className="inspector-section-title">7. RECOVERY STATUS</div>
            <div className="inspector-section-content">
              {recoveryStatus && (
                <div className={`recovery-status ${recoveryStatus.className}`}>
                  <span className="status-icon">{recoveryStatus.icon}</span>
                  <span className="status-text">{recoveryStatus.text}</span>
                </div>
              )}
              {latestRecoveryAttempt.usedProviders && (
                <div className="recovery-providers">
                  <strong>Attempted with:</strong>{' '}
                  {latestRecoveryAttempt.usedProviders.map(p => 
                    PROVIDER_DISPLAY_NAMES[p] || p
                  ).join(', ')}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Key Properties Summary */}
        <div className="inspector-section">
          <div className="inspector-section-title">KEY PROPERTIES</div>
          <div className="inspector-section-content">
            <div className="properties-list">
              <div className="property">
                <span className="property-icon">🔄</span>
                <span className="property-text">Deterministic: Same inputs always produce same key</span>
              </div>
              <div className="property">
                <span className="property-icon">🌐</span>
                <span className="property-text">Cross-device: Recoverable on any device with K identities</span>
              </div>
              <div className="property">
                <span className="property-icon">🔒</span>
                <span className="property-text">Policy-independent: Threshold doesn't affect key derivation</span>
              </div>
              <div className="property">
                <span className="property-icon">⚡</span>
                <span className="property-text">No ZK: Pure deterministic cryptography, no proofs needed</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};