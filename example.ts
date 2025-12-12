// Example: identities → claims → commitments pipeline
import { 
  extractIdentityClaim, 
  generateCommitments, 
  createRandomSalt 
} from './src/index.js';
import type { SupportedIdentity } from './src/index.js';

// Example usage
async function example() {
  console.log('🚀 Key Weaver: Identity → Commitments Example\n');
  
  // Step 1: Simulate identity inputs (tokens/assertions from OAuth/WebAuthn)
  const mockGoogleJwt = `eyJhbGciOiJSUzI1NiJ9.${btoa(JSON.stringify({
    sub: "google_user_12345",
    email: "user@example.com"
  }))}.mock_signature`;

  const identities: SupportedIdentity[] = [
    {
      provider: 'google',
      idToken: mockGoogleJwt
    },
    {
      provider: 'github', 
      accessToken: 'gho_example_access_token_xyz789'
    },
    {
      provider: 'passkey',
      assertion: {
        credentialId: 'passkey_credential_abc123',
        clientDataJSON: '{"type":"webauthn.get","challenge":"..."}',
        authenticatorData: 'authenticator_data_here',
        signature: 'signature_bytes_here'
      }
    }
  ];

  // Step 2: Extract canonical identity claims
  console.log('📋 Extracting identity claims...');
  const claims = identities.map(extractIdentityClaim);
  claims.forEach(claim => {
    console.log(`  ${claim.provider}: ${claim.stableId}`);
  });

  // Step 3: Generate commitments with random salt
  console.log('\n🔒 Generating commitments...');
  const salt = createRandomSalt();
  console.log(`Salt: ${salt}`);
  
  const commitments = generateCommitments(claims, salt);
  commitments.forEach((commitment, i) => {
    console.log(`  Commitment ${i + 1}: ${commitment.commitment}`);
    console.log(`    (for ${commitment.claim.provider})`);
  });

  // Step 4: Show what gets stored vs what stays private
  console.log('\n💾 Storage considerations:');
  const commitmentStrings = commitments.map(c => c.commitment);
  console.log('Commitments to store (privacy-preserving):', commitmentStrings);
  console.log('Salt to store:', salt);
  console.log('\n✅ Original identity data (tokens/assertions) can be discarded!');
  console.log('   Commitments reveal nothing about the original identities.');

  return { commitments, salt };
}

// Run example if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  example().catch(console.error);
}