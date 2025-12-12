import type { SupportedIdentity } from '../types.js';

interface MockAuthResult {
  identity: SupportedIdentity;
  displayName: string;
}

// Email validation helper
export function isValidEmail(email: string): boolean {
  if (!email || email.trim().length === 0) {
    return false;
  }
  
  // Basic email format check (contains @ and has characters before/after)
  const emailRegex = /^[^\s@]+@[^\s@]+$/;
  return emailRegex.test(email.trim());
}

// Mock authentication for GitHub and Twitter
export function createMockAuth(provider: 'github' | 'twitter', email: string): MockAuthResult {
  const trimmedEmail = email.trim();
  
  if (!isValidEmail(trimmedEmail)) {
    throw new Error('Please enter a valid email address');
  }

  // Create identity for SDK (SDK will handle hashing internally)
  const identity: SupportedIdentity = {
    provider,
    accessToken: trimmedEmail, // SDK will hash this to create stable ID
  };

  // Display name is the fake email
  const displayName = trimmedEmail;

  return {
    identity,
    displayName,
  };
}

// Session storage for mock provider emails (non-persistent)
class MockAuthSessionStorage {
  private emails: Record<'github' | 'twitter', string> = {
    github: '',
    twitter: '',
  };

  setEmail(provider: 'github' | 'twitter', email: string): void {
    this.emails[provider] = email;
  }

  getEmail(provider: 'github' | 'twitter'): string {
    return this.emails[provider];
  }

  clearEmail(provider: 'github' | 'twitter'): void {
    this.emails[provider] = '';
  }

  clearAll(): void {
    this.emails.github = '';
    this.emails.twitter = '';
  }
}

// Export singleton instance
export const mockAuthStorage = new MockAuthSessionStorage();