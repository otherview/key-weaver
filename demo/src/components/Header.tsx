import React from 'react';
import type { Mode } from '../types.js';

interface HeaderProps {
  mode: Mode;
  onModeSwitch: (mode: Mode) => void;
}

export const Header: React.FC<HeaderProps> = ({ mode, onModeSwitch }) => {
  return (
    <header className="header">
      <div className="header-content">
        <h1 className="title">🔐 Key Weaver Wallet Demo</h1>
        <p className="subtitle">
          Seedless EOA wallet derived from K-of-N identity factors
        </p>
        
        <div className="mode-selector">
          <button 
            className={`mode-button ${mode === 'demo' ? 'active' : ''}`}
            onClick={() => onModeSwitch('demo')}
          >
            DEMO MODE
          </button>
          <button 
            className={`mode-button ${mode === 'live' ? 'active' : ''}`}
            onClick={() => onModeSwitch('live')}
          >
            LIVE MODE
          </button>
        </div>
        
        <div className={`warning-banner ${mode}`}>
          {mode === 'demo' ? (
            <div className="demo-warning">
              <span className="warning-icon">⚠️</span>
              <strong>Demo Mode:</strong> Mock identities only. Wallets created here CANNOT be recovered via real providers.
            </div>
          ) : (
            <div className="live-warning">
              <span className="warning-icon">🟢</span>
              <strong>Live Mode:</strong> Real authentication with Google, GitHub, Twitter, and Passkeys.
            </div>
          )}
        </div>
      </div>
    </header>
  );
};