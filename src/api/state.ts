import type { KeyWeaverConfig } from '../types/index.js';
import { KeyWeaverNotInitializedError } from '../errors/index.js';

interface KeyWeaverState {
  initialized: boolean;
  config: KeyWeaverConfig | null;
}

const state: KeyWeaverState = {
  initialized: false,
  config: null
};

export function initializeKeyWeaver(config: KeyWeaverConfig): void {
  state.config = config;
  state.initialized = true;
}

export function getKeyWeaverConfig(): KeyWeaverConfig {
  if (!state.initialized || !state.config) {
    throw new KeyWeaverNotInitializedError();
  }
  return state.config;
}

export function isInitialized(): boolean {
  return state.initialized;
}