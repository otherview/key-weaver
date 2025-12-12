import React, { useState, useEffect } from 'react';
import { isValidEmail } from '../services/mockAuth.js';

interface MockProviderModalProps {
  provider: 'github' | 'twitter';
  isOpen: boolean;
  initialEmail?: string;
  onClose: () => void;
  onSignIn: (email: string) => void;
}

export const MockProviderModal: React.FC<MockProviderModalProps> = ({
  provider,
  isOpen,
  initialEmail = '',
  onClose,
  onSignIn,
}) => {
  const [email, setEmail] = useState(initialEmail);
  const [error, setError] = useState('');

  // Reset form when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      setEmail(initialEmail);
      setError('');
    }
  }, [isOpen, initialEmail]);

  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const trimmedEmail = email.trim();
    
    if (!isValidEmail(trimmedEmail)) {
      setError('Please enter a valid email address');
      return;
    }
    
    setError('');
    onSignIn(trimmedEmail);
  };

  // Handle backdrop click
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Handle escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const providerName = provider === 'github' ? 'GitHub' : 'Twitter';

  return (
    <div className="modal-backdrop" onClick={handleBackdropClick}>
      <div className="modal-container">
        <div className="modal-header">
          <h3>{providerName} Login (MOCK Mode)</h3>
          <button 
            className="modal-close-button"
            onClick={onClose}
            aria-label="Close modal"
          >
            ×
          </button>
        </div>
        
        <div className="modal-body">
          <p className="modal-description">
            This provider is currently running in MOCK mode. Enter a fake email to simulate login.
          </p>
          
          <form onSubmit={handleSubmit}>
            <div className="modal-form-group">
              <label htmlFor="mock-email">Email:</label>
              <input
                id="mock-email"
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (error) setError(''); // Clear error when user types
                }}
                placeholder="fake@example.com"
                className={`modal-input ${error ? 'modal-input-error' : ''}`}
                autoFocus
                required
              />
              {error && (
                <div className="modal-error">
                  {error}
                </div>
              )}
            </div>
            
            <div className="modal-actions">
              <button
                type="button"
                className="modal-button modal-button-secondary"
                onClick={onClose}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="modal-button modal-button-primary"
                disabled={!email.trim()}
              >
                Sign In
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};