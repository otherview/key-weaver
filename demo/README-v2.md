# Key Weaver Dual-Mode Wallet Demo

A next-generation React demo showcasing **TWO MODES** of Key Weaver wallet functionality:

- **🧪 Demo Mode**: Mock identities with checkbox selection (deterministic)
- **🟢 Live Mode**: Real provider authentication (OAuth + WebAuthn - currently stubbed)

## 🚀 Quick Start

```bash
# From the demo directory
npm install
npm run dev
```

The app will open at `http://localhost:3000` using the new dual-mode interface.

## 🎯 Demo Features

### 🔐 Two Distinct Modes

**Demo Mode:**
- ✅ Checkbox-based identity selection
- ✅ Deterministic mock tokens (same across reloads)
- ✅ Private keys exposed for debugging
- ⚠️ Mock identities cannot be recovered via real providers

**Live Mode:**
- ✅ Authentication buttons for each provider
- ✅ Simulated OAuth flows (1-2 second delays)
- ✅ Session reset on page reload
- 🔒 Private keys hidden for security

### 🧱 Core Functionality

**K-of-4 Threshold Support:**
- All 4 providers: Google, GitHub, Twitter, Passkey
- Threshold options: 1/2/3/4 of 4
- Visual progress indicators (●●○○)
- Smart validation and error handling

**Wallet Lifecycle:**
- Register wallets with selected identities
- Recover using different identity combinations  
- Cross-mode wallet visibility with warnings
- localStorage persistence across sessions

**Error Handling:**
- `InsufficientIdentitiesError` with clear guidance
- Mode mismatch warnings
- Threshold validation before submission
- User-friendly error messages

## 🔍 Testing Scenarios

### Demo Mode Testing
1. **Select 2-3 identities** → Set threshold to 2 → Register wallet
2. **Change selections** → Try recovery with different combinations
3. **Insufficient identities** → Try recovery with only 1 selected
4. **Switch to Live Mode** → See mode warning on existing wallet

### Live Mode Testing
1. **Authenticate with 2+ providers** → Register wallet with threshold 2
2. **Remove one authentication** → Try recovery (should fail)
3. **Re-authenticate** → Try recovery again (should succeed)
4. **Switch to Demo Mode** → See mode warning on Live wallet

### Cross-Mode Testing
1. Create wallet in Demo Mode → Switch to Live → See warnings
2. Create wallet in Live Mode → Switch to Demo → See warnings
3. **Clear wallet** in Debug panel → Start fresh

## 🏗️ Architecture

### Component Structure
```
App
├── Header (mode toggle + warnings)
├── MainGrid
│   ├── IdentityPanel (Demo/Live variants)
│   ├── RegisterPanel (threshold validation)
│   └── RecoverPanel (with mode warnings)
└── DebugPanel (state + clear wallet)
```

### Key Features
- **CSS Grid Layout**: Responsive 3-column → 1-column mobile
- **TypeScript**: Fully typed with proper error handling
- **State Management**: Single React state with proper loading states
- **SDK Integration**: Real Key Weaver calls (no mocking at crypto level)
- **Persistence**: localStorage with timestamps and mode tracking

## 🔧 Technical Details

### Mock Identity Values (Demo Mode)
- **Google**: Deterministic JWT with `sub: "google-user-123"`
- **GitHub**: `accessToken: "github-user-abc"`  
- **Twitter**: `accessToken: "twitter-user-xyz"`
- **Passkey**: Mock assertion with `credentialId: "passkey-device-001"`

### Live Mode Authentication (Stubbed)
- **Google**: Simulates OAuth 2.0 flow (1s delay)
- **GitHub**: Simulates OAuth 2.0 flow (0.8s delay)  
- **Twitter**: Simulates OAuth 2.0 flow (1.2s delay)
- **Passkey**: Simulates WebAuthn flow (0.5s delay)

### State Persistence
```typescript
// localStorage schema
{
  "address": "0x...",
  "threshold": 2,
  "salt": "...", 
  "commitments": [...],
  "privateKey": "0x..." // only in demo mode,
  "createdInMode": "demo" | "live",
  "timestamp": 1640000000000
}
```

## 🧪 Debug Features

The Debug Panel provides:
- **Complete state visualization** (JSON format)
- **Clear wallet button** (removes localStorage)
- **Mode tracking** (which mode created the wallet)
- **Verification checklist** (threshold logic, commitments, etc.)

## 📱 Responsive Design

- **Desktop**: 3-column grid layout
- **Tablet**: 2-column adaptive layout  
- **Mobile**: Single column with optimized controls

## 🎨 Visual Design

- **Mode Toggle**: Clear DEMO/LIVE button selection
- **Warning Banners**: Color-coded mode warnings
- **Progress Indicators**: Visual threshold progress (●●○○)
- **Status Icons**: ✓/✗/⏳ for authentication states
- **Result Boxes**: Success (green) / Error (red) feedback

## 🔮 Future Enhancements

The stubbed authentication can be replaced with:
- **Google**: Real OAuth 2.0 with Google Identity Services
- **GitHub**: GitHub OAuth Apps integration
- **Twitter**: Twitter API v2 OAuth 2.0
- **Passkey**: Real WebAuthn with `navigator.credentials`

All the UI infrastructure is already built to handle real authentication flows!

---

This demo provides a comprehensive testing environment for both mock and real Key Weaver wallet scenarios, with clear separation between deterministic testing and live authentication flows.