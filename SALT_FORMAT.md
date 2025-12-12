# Salt Format Specification

## Overview

Key Weaver uses **deterministic key derivation** from identity commitments and a user-provided salt. To ensure **cross-platform/cross-browser compatibility**, the salt format is **strictly defined** and **automatically normalized**.

## Salt Format Definition

### Internal Format
- **Type**: Hex-encoded string
- **Length**: Exactly 64 characters (32 bytes)
- **Pattern**: `^[0-9a-f]{64}$` (lowercase hexadecimal)
- **Example**: `8191e1cdea74f80bf4e95b6d6ef9a6b115187abf232f7b8bcd8f37ee753509a6`

### User Input Handling
Key Weaver accepts **any string** as salt input and automatically normalizes it:

1. **Valid Hex Salt**: Used as-is (converted to lowercase)
   ```typescript
   const salt = normalizeSalt('0123456789abcdef...'); // Returns same value
   ```

2. **Arbitrary String**: Converted to deterministic hex via SHA256
   ```typescript
   const salt = normalizeSalt('my-password-123'); 
   // Returns: SHA256('my-password-123') as hex string
   ```

## Key Derivation Process

```typescript
// Step 1: Normalize salt to hex format
const hexSalt = normalizeSalt(userProvidedSalt);

// Step 2: Create seed
const seedInput = `key-weaver:v1|${canonicalizedCommitments}|${hexSalt}`;
const seed = SHA256(seedInput);

// Step 3: Derive key with HKDF
const saltBytes = hexToBytes(hexSalt);
const privateKey = HKDF(seed, saltBytes, "key-weaver-hkdf", 32);
```

## Cross-Platform Guarantees

### ✅ Consistent Behavior
- Same arbitrary string → same hex salt across all platforms
- Same hex salt → same derived keys across all browsers/devices
- UTF-8 encoding handled consistently via SHA256 normalization

### ✅ Validation
```typescript
import { isValidSalt, normalizeSalt } from 'key-weaver';

// Check if salt is valid hex format
const isValid = isValidSalt(salt); // boolean

// Normalize any string to valid hex salt
const normalized = normalizeSalt(userInput); // always 64-char hex
```

## API Usage

### Registration
```typescript
await registerWallet({
  identities,
  threshold: 2,
  salt: 'my-custom-password' // Automatically normalized
});
```

### Recovery
```typescript
await recoverWallet({
  identities,
  commitments,
  salt: 'my-custom-password', // Same input → same normalized salt
  threshold: 2
});
```

## Security Properties

1. **Deterministic**: Same input always produces same output
2. **One-way**: Cannot reverse SHA256 to get original arbitrary string
3. **Collision-resistant**: Different inputs produce different hex salts
4. **Platform-independent**: Consistent across all environments

## Migration Notes

If you have existing salts in different formats:
1. Use `normalizeSalt(existingSalt)` to convert to standard format
2. Store the normalized hex salt for future use
3. Users can continue using their original arbitrary strings - they will be normalized automatically

## Testing

```typescript
import { normalizeSalt, isValidSalt } from 'key-weaver';

// Test arbitrary string normalization
const salt1 = normalizeSalt('password123');
const salt2 = normalizeSalt('password123');
console.assert(salt1 === salt2); // ✅ Deterministic

// Test hex salt validation  
console.assert(isValidSalt(salt1)); // ✅ Valid hex format
console.assert(salt1.length === 64); // ✅ Correct length
```