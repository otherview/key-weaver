# Key Weaver Wallet Demo

A single-page React demo showcasing seedless EOA wallet creation and recovery using K-of-N identity factors through deterministic key derivation.

## Features

- **Identity Factors**: Select from Google, GitHub, Twitter, and Passkey identities (mocked for demo)
- **K-of-N Threshold**: Configure wallet security with 1-of-4, 2-of-4, 3-of-4, or 4-of-4 threshold
- **Wallet Registration**: Create deterministic wallets from selected identities
- **Wallet Recovery**: Recover wallets using different subsets of identities
- **Address Consistency**: Verify same EVM address across registration and recovery
- **Debug Panel**: Internal state visualization for verification

## Demo Flow

1. **Select Identity Factors** (left panel): Choose which identities are "available"
2. **Register Wallet** (middle panel): Set threshold and create wallet
3. **Recover Wallet** (right panel): Use different identity combinations to recover
4. **Debug State** (bottom panel): View internal commitments and proofs

## Key Demonstrations

- ✅ 2-of-4 threshold works when 2+ identities selected
- ❌ Recovery fails with insufficient identities (shows helpful errors)
- 🔄 Same address recovered regardless of identity combination (when threshold met)
- 💾 Wallet state persists in localStorage across browser sessions

## Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Technical Notes

- **Mock Identities**: Uses deterministic fake tokens (no real OAuth/passkeys)
- **State Management**: React hooks with localStorage persistence  
- **Styling**: Clean CSS Grid layout with responsive design
- **TypeScript**: Fully typed with proper Key Weaver library integration

## Security Warning

🔐 **Demo Mode**: Private keys are exposed for testing purposes only. This does not represent real wallet security practices.