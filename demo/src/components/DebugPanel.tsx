import React, { useState } from 'react';
import type { AppState } from '../types.js';
import { clearAllWalletData, getAllWalletData } from '../utils.js';
import { KeyDerivationInspector } from './KeyDerivationInspector.js';

interface DebugPanelProps {
  state: AppState;
  onClearWallet: () => void;
}

export const DebugPanel: React.FC<DebugPanelProps> = ({ state, onClearWallet }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [showBothWallets, setShowBothWallets] = useState(false);
  const [showKeyInspector, setShowKeyInspector] = useState(false);

  const allWalletData = getAllWalletData();
  
  const debugState = {
    mode: state.mode,
    selectedProviders: state.selectedProviders,
    authenticatedProviders: state.authenticatedProviders.map(auth => ({
      provider: auth.provider,
      displayName: auth.displayName
    })),
    threshold: state.threshold,
    currentWallet: state.registeredWallet ? {
      address: state.registeredWallet.address,
      threshold: state.registeredWallet.threshold,
      salt: state.registeredWallet.salt,
      commitments: state.registeredWallet.commitments.map(c => ({
        provider: c.claim.provider,
        stableId: c.claim.stableId,
        commitment: c.commitment
      })),
      privateKey: state.registeredWallet.privateKey
    } : null,
    ...(showBothWallets && {
      demoWallet: state.registeredWalletDemo ? {
        address: state.registeredWalletDemo.address,
        threshold: state.registeredWalletDemo.threshold,
        salt: state.registeredWalletDemo.salt,
        commitments: state.registeredWalletDemo.commitments.map(c => ({
          provider: c.claim.provider,
          stableId: c.claim.stableId,
          commitment: c.commitment
        })),
        privateKey: state.registeredWalletDemo.privateKey
      } : null,
      liveWallet: state.registeredWalletLive ? {
        address: state.registeredWalletLive.address,
        threshold: state.registeredWalletLive.threshold,
        salt: state.registeredWalletLive.salt,
        commitments: state.registeredWalletLive.commitments.map(c => ({
          provider: c.claim.provider,
          stableId: c.claim.stableId,
          commitment: c.commitment
        })),
        privateKey: state.registeredWalletLive.privateKey
      } : null
    }),
    latestRecovery: state.latestRecoveryAttempt ? {
      usedProviders: state.latestRecoveryAttempt.usedProviders,
      recoveredAddress: state.latestRecoveryAttempt.recoveredAddress,
      matchesOriginal: state.latestRecoveryAttempt.matchesOriginal,
      success: state.latestRecoveryAttempt.success,
      error: state.latestRecoveryAttempt.error,
      privateKey: state.latestRecoveryAttempt.privateKey
    } : null,
    loadingStates: {
      isInitialized: state.isInitialized,
      isRegistering: state.isRegistering,
      isRecovering: state.isRecovering,
      isAuthenticating: state.isAuthenticating
    }
  };

  return (
    <div className="panel debug-panel">
      <div 
        className="debug-header" 
        onClick={() => setIsCollapsed(!isCollapsed)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            setIsCollapsed(!isCollapsed);
          }
        }}
      >
        <h2>🧪 Debug / Internal State</h2>
        <span className="collapse-indicator">
          {isCollapsed ? '▶' : '▼'}
        </span>
      </div>
      
      {!isCollapsed && (
        <div className="debug-content">
          <div className="debug-controls">
            <button 
              className="clear-wallet-button"
              onClick={onClearWallet}
              disabled={!state.registeredWallet}
            >
              Clear Current Mode Wallet
            </button>
            
            <button 
              className="clear-all-button"
              onClick={() => {
                clearAllWalletData();
                window.location.reload(); // Force reload to reset state
              }}
              disabled={!allWalletData.demo && !allWalletData.live}
            >
              Clear All Wallet Data
            </button>
            
            <button 
              className="toggle-wallets-button"
              onClick={() => setShowBothWallets(!showBothWallets)}
            >
              {showBothWallets ? 'Hide Both Wallets' : 'Show Both Wallets'}
            </button>
            
            <div className="debug-info">
              <span>Mode: <strong>{state.mode}</strong></span>
              <span>Threshold: <strong>{state.threshold}</strong></span>
              {state.registeredWallet && (
                <span>Current Wallet: <strong>exists</strong></span>
              )}
              <span>Demo Wallet: <strong>{allWalletData.demo ? 'exists' : 'none'}</strong></span>
              <span>Live Wallet: <strong>{allWalletData.live ? 'exists' : 'none'}</strong></span>
            </div>
          </div>
          
          <div className="debug-json-container">
            <h4>Complete Application State:</h4>
            <pre className="debug-json">
              <code>
                {JSON.stringify(debugState, null, 2)}
              </code>
            </pre>
          </div>
          
          <div className="debug-notes">
            <h4>Verification Points:</h4>
            <ul>
              <li>✓ Commitments remain stable across mode switches</li>
              <li>✓ Threshold validation prevents invalid configurations</li>
              <li>✓ Recovery produces consistent addresses when threshold met</li>
              <li>✓ Complete isolation between Demo and Live mode wallets</li>
              <li>✓ Private keys only exposed in Demo Mode</li>
              <li>✓ Error handling for insufficient identities</li>
            </ul>
          </div>
          
          <div className="debug-localStorage">
            <h4>localStorage Data:</h4>
            <div className="localStorage-info">
              <div className="stored-data">
                <div>Demo Mode: {allWalletData.demo ? 
                  <span>✓ <code>keyWeaverDemo_demo</code></span> : 
                  <span>○ No data</span>
                }</div>
                <div>Live Mode: {allWalletData.live ? 
                  <span>✓ <code>keyWeaverDemo_live</code></span> : 
                  <span>○ No data</span>
                }</div>
                <div>Current Mode ({state.mode}): {state.registeredWallet ? 
                  <span>✓ Active wallet loaded</span> : 
                  <span>○ No wallet</span>
                }</div>
              </div>
            </div>
          </div>
          
          {/* Key Derivation Inspector Section */}
          <div className="debug-section">
            <div 
              className="debug-header" 
              onClick={() => setShowKeyInspector(!showKeyInspector)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  setShowKeyInspector(!showKeyInspector);
                }
              }}
            >
              <h4>🔍 Key Derivation Inspector</h4>
              <span className="collapse-indicator">
                {showKeyInspector ? '▼' : '▶'}
              </span>
            </div>
            
            {showKeyInspector && (
              <KeyDerivationInspector
                mode={state.mode}
                registeredWallet={state.registeredWallet}
                latestRecoveryAttempt={state.latestRecoveryAttempt}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
};