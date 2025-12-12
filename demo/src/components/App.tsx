import React, { useState, useEffect } from 'react';
import { initKeyWeaver, registerWallet, recoverWallet, InsufficientIdentitiesError } from '../../../src/index.js';
import type { 
  Mode, 
  Provider, 
  AppState
} from '../types.js';
import {
  authProviders,
  getAvailableIdentities,
  getCurrentProviders,
  canRegister,
  saveToLocalStorage,
  loadFromLocalStorage,
  clearStoredWallet
} from '../utils.js';
import { googleAuthService } from '../services/googleAuth.js';
import { webAuthnAuthService } from '../services/webAuthnAuth.js';

import { Header } from './Header.js';
import { IdentityPanel } from './IdentityPanel.js';
import { RegisterPanel } from './RegisterPanel.js';
import { RecoverPanel } from './RecoverPanel.js';
import { DebugPanel } from './DebugPanel.js';

export const App: React.FC = () => {
  const [state, setState] = useState<AppState>({
    mode: 'demo',
    selectedProviders: [],
    authenticatedProviders: [],
    threshold: 2,
    isInitialized: false,
    registeredWalletDemo: undefined,
    registeredWalletLive: undefined,
    registeredWallet: undefined, // Will be derived
    latestRecoveryAttempt: undefined,
    isRegistering: false,
    isRecovering: false,
    isAuthenticating: {
      google: false,
      github: false,
      twitter: false,
      passkey: false
    },
    liveAuthState: {
      mockProviderEmails: {
        github: '',
        twitter: ''
      },
      authErrors: {
        google: null,
        github: null,
        twitter: null,
        passkey: null
      },
      googleAvailable: false,
      webAuthnAvailable: false
    }
  });

  // Initialize app and load mode-specific wallet data
  useEffect(() => {
    const initializeApp = async () => {
      try {
        // Initialize key-weaver SDK
        await initKeyWeaver({ version: 'v1' });
        
        // Initialize auth services for Live Mode
        const googleAvailable = await googleAuthService.initialize();
        const webAuthnAvailable = webAuthnAuthService.isAvailable();
        
        // Load persisted wallet data for both modes
        const storedWalletDemo = loadFromLocalStorage('demo');
        const storedWalletLive = loadFromLocalStorage('live');
        
        setState(prev => ({
          ...prev,
          registeredWalletDemo: storedWalletDemo ? {
            address: storedWalletDemo.address,
            threshold: storedWalletDemo.threshold,
            salt: storedWalletDemo.salt,
            commitments: storedWalletDemo.commitments,
            privateKey: storedWalletDemo.privateKey
          } : undefined,
          registeredWalletLive: storedWalletLive ? {
            address: storedWalletLive.address,
            threshold: storedWalletLive.threshold,
            salt: storedWalletLive.salt,
            commitments: storedWalletLive.commitments,
            privateKey: storedWalletLive.privateKey
          } : undefined,
          liveAuthState: {
            ...prev.liveAuthState,
            googleAvailable,
            webAuthnAvailable
          },
          isInitialized: true
        }));
      } catch (error) {
        console.error('Failed to initialize app:', error);
        setState(prev => ({ ...prev, isInitialized: true }));
      }
    };

    initializeApp();
  }, []);

  // Effect to derive registeredWallet from current mode
  useEffect(() => {
    setState(prev => ({
      ...prev,
      registeredWallet: prev.mode === 'demo' ? prev.registeredWalletDemo : prev.registeredWalletLive
    }));
  }, [state.mode, state.registeredWalletDemo, state.registeredWalletLive]);

  // Mode switching handler with complete state cleanup
  const handleModeSwitch = (newMode: Mode) => {
    setState(prev => ({
      ...prev,
      mode: newMode,
      // Reset selections and clear state for clean isolation
      selectedProviders: [],
      authenticatedProviders: [],
      latestRecoveryAttempt: undefined
    }));
  };

  // Demo mode: toggle provider selection
  const handleProviderToggle = (provider: Provider) => {
    setState(prev => ({
      ...prev,
      selectedProviders: prev.selectedProviders.includes(provider)
        ? prev.selectedProviders.filter(p => p !== provider)
        : [...prev.selectedProviders, provider],
      latestRecoveryAttempt: undefined // Clear previous recovery attempts
    }));
  };

  // Live mode: authenticate with provider (updated for new auth system)
  const handleAuthenticate = async (provider: Provider, displayName?: string, identity?: any) => {
    // If called with new signature (from new auth components)
    if (displayName && identity) {
      setState(prev => ({
        ...prev,
        authenticatedProviders: [
          ...prev.authenticatedProviders.filter(p => p.provider !== provider),
          { provider, displayName, identity }
        ],
        liveAuthState: {
          ...prev.liveAuthState,
          authErrors: { ...prev.liveAuthState.authErrors, [provider]: null }
        },
        latestRecoveryAttempt: undefined
      }));
      return;
    }

    // Legacy authentication for old auth system (keep for compatibility)
    setState(prev => ({
      ...prev,
      isAuthenticating: { ...prev.isAuthenticating, [provider]: true }
    }));

    try {
      const result = await authProviders[provider]();
      
      setState(prev => ({
        ...prev,
        authenticatedProviders: [
          ...prev.authenticatedProviders.filter(p => p.provider !== provider),
          {
            provider,
            displayName: result.displayName,
            identity: result.identity
          }
        ],
        isAuthenticating: { ...prev.isAuthenticating, [provider]: false },
        latestRecoveryAttempt: undefined
      }));
    } catch (error) {
      console.error(`Authentication failed for ${provider}:`, error);
      setState(prev => ({
        ...prev,
        isAuthenticating: { ...prev.isAuthenticating, [provider]: false }
      }));
    }
  };

  // Live mode: remove authenticated provider
  const handleRemoveAuth = (provider: Provider) => {
    setState(prev => ({
      ...prev,
      authenticatedProviders: prev.authenticatedProviders.filter(p => p.provider !== provider),
      latestRecoveryAttempt: undefined
    }));
  };

  // Handle authentication errors
  const handleAuthError = (provider: Provider, error: string) => {
    setState(prev => ({
      ...prev,
      liveAuthState: {
        ...prev.liveAuthState,
        authErrors: { ...prev.liveAuthState.authErrors, [provider]: error }
      }
    }));
  };

  // Handle mock provider email updates
  const handleMockEmailUpdate = (provider: 'github' | 'twitter', email: string) => {
    setState(prev => ({
      ...prev,
      liveAuthState: {
        ...prev.liveAuthState,
        mockProviderEmails: { ...prev.liveAuthState.mockProviderEmails, [provider]: email }
      }
    }));
  };

  // Threshold change handler
  const handleThresholdChange = (threshold: number) => {
    setState(prev => ({ ...prev, threshold }));
  };

  // Registration handler
  const handleRegister = async () => {
    const identities = getAvailableIdentities(
      state.mode, 
      state.selectedProviders, 
      state.authenticatedProviders
    );
    
    if (!canRegister(state.mode, state.selectedProviders, state.authenticatedProviders, state.threshold)) {
      return; // Should be disabled
    }
    
    setState(prev => ({ ...prev, isRegistering: true }));
    
    try {
      const result = await registerWallet({
        identities,
        threshold: state.threshold,
        exposePrivateKey: state.mode === 'demo'
      });
      
      const walletData = {
        address: result.address,
        threshold: state.threshold,
        salt: result.salt,
        commitments: result.commitments,
        privateKey: state.mode === 'demo' ? result.privateKey : undefined
      };
      
      setState(prev => ({
        ...prev,
        [state.mode === 'demo' ? 'registeredWalletDemo' : 'registeredWalletLive']: walletData,
        isRegistering: false,
        latestRecoveryAttempt: undefined
      }));
      
      saveToLocalStorage(state.mode, walletData);
      
    } catch (error: any) {
      console.error('Registration failed:', error);
      setState(prev => ({ ...prev, isRegistering: false }));
      // TODO: Show error in UI
    }
  };

  // Recovery handler  
  const handleRecover = async () => {
    const { registeredWallet } = state;
    if (!registeredWallet) return;
    
    const identities = getAvailableIdentities(
      state.mode,
      state.selectedProviders, 
      state.authenticatedProviders
    );
    
    const usedProviders = getCurrentProviders(
      state.mode,
      state.selectedProviders,
      state.authenticatedProviders  
    );
    
    setState(prev => ({ ...prev, isRecovering: true }));
    
    try {
      const result = await recoverWallet({
        identities,
        commitments: registeredWallet.commitments,
        salt: registeredWallet.salt,
        threshold: registeredWallet.threshold,
        exposePrivateKey: state.mode === 'demo'
      });
      
      const recoveryAttempt = {
        usedProviders,
        recoveredAddress: result.wallet.address,
        matchesOriginal: result.wallet.address === registeredWallet.address,
        success: true,
        privateKey: state.mode === 'demo' ? result.privateKey : undefined,
        error: undefined
      };
      
      setState(prev => ({
        ...prev,
        latestRecoveryAttempt: recoveryAttempt,
        isRecovering: false
      }));
      
    } catch (error: any) {
      console.error('Recovery failed:', error);
      
      let errorMessage: string;
      if (error instanceof InsufficientIdentitiesError || error.name === 'InsufficientIdentitiesError') {
        const providedCount = identities.length;
        const requiredCount = registeredWallet.threshold;
        errorMessage = `Provided: ${providedCount}, Required: ${requiredCount}`;
      } else {
        errorMessage = error.message || 'Unknown error occurred';
      }
      
      const recoveryAttempt = {
        usedProviders,
        success: false,
        matchesOriginal: false,
        error: errorMessage
      };
      
      setState(prev => ({
        ...prev,
        latestRecoveryAttempt: recoveryAttempt,
        isRecovering: false
      }));
    }
  };

  // Clear current mode's wallet data
  const handleClearWallet = () => {
    clearStoredWallet(state.mode);
    setState(prev => ({
      ...prev,
      [state.mode === 'demo' ? 'registeredWalletDemo' : 'registeredWalletLive']: undefined,
      latestRecoveryAttempt: undefined
    }));
  };

  // Loading state
  if (!state.isInitialized) {
    return (
      <div className="loading">
        <div className="loading-spinner">⏳</div>
        <div>Initializing Key Weaver Demo...</div>
      </div>
    );
  }

  return (
    <div className="app">
      <Header 
        mode={state.mode}
        onModeSwitch={handleModeSwitch}
      />
      
      <div className="main-grid">
        <IdentityPanel
          mode={state.mode}
          selectedProviders={state.selectedProviders}
          authenticatedProviders={state.authenticatedProviders}
          isAuthenticating={state.isAuthenticating}
          liveAuthState={state.liveAuthState}
          onProviderToggle={handleProviderToggle}
          onAuthenticate={handleAuthenticate}
          onRemoveAuth={handleRemoveAuth}
          onAuthError={handleAuthError}
          onMockEmailUpdate={handleMockEmailUpdate}
          threshold={state.threshold}
        />
        
        <RegisterPanel
          mode={state.mode}
          selectedProviders={state.selectedProviders}
          authenticatedProviders={state.authenticatedProviders}
          threshold={state.threshold}
          registeredWallet={state.registeredWallet}
          isRegistering={state.isRegistering}
          onThresholdChange={handleThresholdChange}
          onRegister={handleRegister}
        />
        
        <RecoverPanel
          mode={state.mode}
          selectedProviders={state.selectedProviders}
          authenticatedProviders={state.authenticatedProviders}
          registeredWallet={state.registeredWallet}
          latestRecoveryAttempt={state.latestRecoveryAttempt}
          isRecovering={state.isRecovering}
          onRecover={handleRecover}
        />
      </div>
      
      <DebugPanel 
        state={state}
        onClearWallet={handleClearWallet}
      />
    </div>
  );
};