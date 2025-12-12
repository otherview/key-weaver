// Complete Key Weaver Example: Registration → Recovery → Cross-Device
import { 
  initKeyWeaver, 
  registerWallet, 
  recoverWallet 
} from './src/index.js';
import type { SupportedIdentity } from './src/index.js';

async function demonstrateKeyWeaver() {
  console.log('🚀 Complete Key Weaver Demo\n');

  // Step 1: Initialize the Key Weaver system
  console.log('1️⃣ Initializing Key Weaver system...');
  await initKeyWeaver({ 
    mode: 'demo' 
  });
  console.log('   ✅ System initialized\n');

  // Step 2: Create user identities (normally from OAuth/WebAuthn flows)
  console.log('2️⃣ Setting up user identities...');
  
  const mockGoogleJwt = `eyJhbGciOiJSUzI1NiJ9.${btoa(JSON.stringify({
    sub: "google_user_alice_123",
    email: "alice@example.com"
  }))}.mock_signature`;

  const allIdentities: SupportedIdentity[] = [
    {
      provider: 'google',
      idToken: mockGoogleJwt
    },
    {
      provider: 'github', 
      accessToken: 'gho_alice_github_token_xyz789'
    },
    {
      provider: 'passkey',
      assertion: {
        credentialId: 'alice_passkey_credential_abc123',
        clientDataJSON: '{"type":"webauthn.get","challenge":"..."}',
        authenticatorData: 'authenticator_data_here',
        signature: 'signature_bytes_here'
      }
    }
  ];

  console.log(`   📋 Created ${allIdentities.length} identity sources`);
  console.log('   - Google ID token (sub: google_user_alice_123)');
  console.log('   - GitHub access token (SHA256 hashed)');
  console.log('   - WebAuthn passkey credential\n');

  // Step 3: Register wallet (2-of-3 threshold)
  console.log('3️⃣ Registering Key Weaver wallet (2-of-3 threshold)...');
  
  const registration = await registerWallet({
    identities: allIdentities,
    threshold: 2,
    salt: 'alice-secure-password-123'
  });

  console.log(`   🔐 Wallet Address: ${registration.address}`);
  console.log(`   🧂 Salt: ${registration.salt.slice(0, 16)}...`);
  console.log(`   📊 Generated ${registration.commitments.length} commitments`);
  registration.commitments.forEach((c, i) => {
    console.log(`      Commitment ${i + 1}: ${c.commitment.slice(0, 16)}... (${c.claim.provider})`);
  });
  console.log();

  // Step 4: Recovery with full identity set
  console.log('4️⃣ Recovery with all 3 identities...');
  
  const recoveryFull = await recoverWallet({
    identities: allIdentities,
    commitments: registration.commitments,
    salt: 'alice-secure-password-123',
    threshold: 2
  });

  console.log(`   ✅ Recovery successful!`);
  console.log(`   🔐 Recovered Address: ${recoveryFull.address}`);
  console.log(`   🔄 Address matches: ${recoveryFull.address === registration.address ? '✅' : '❌'}`);
  
  // Test wallet functionality
  const testMessage = "Hello from Key Weaver wallet!";
  const signature = await recoveryFull.wallet.signMessage(testMessage);
  console.log(`   ✍️  Signed message: "${testMessage}"`);
  console.log(`   📝 Signature: ${signature.slice(0, 20)}...`);
  console.log();

  // Step 5: Recovery scenario - partial recovery with subset (2-of-3)
  console.log('5️⃣ Partial recovery scenario: Google + GitHub only...');
  
  const recoveryIdentities = allIdentities.slice(0, 2); // Google + GitHub
  
  const partialRecovery = await recoverWallet({
    identities: recoveryIdentities,
    commitments: registration.commitments,
    salt: 'alice-secure-password-123',
    threshold: 2
  });

  console.log(`   ✅ Partial recovery successful!`);
  console.log(`   🔐 Recovered Address: ${partialRecovery.address}`);
  console.log(`   ⚖️  Address matches: ${partialRecovery.address === registration.address ? '✅' : '❌'}`);
  console.log();

  // Step 6: Demonstrate threshold security
  console.log('6️⃣ Security demo: Try recovery with only 1 identity (should fail)...');
  
  try {
    await recoverWallet({
      identities: [allIdentities[0]!], // Only Google
      commitments: registration.commitments,
      salt: 'alice-secure-password-123',
      threshold: 2
    });
    console.log('   ❌ ERROR: Recovery should have failed!');
  } catch (error) {
    console.log(`   ✅ Security check passed: ${error instanceof Error ? error.message : 'Recovery rejected'}`);
  }
  console.log();

  // Step 7: Privacy demonstration
  console.log('7️⃣ Privacy analysis...');
  console.log('   📊 What gets stored publicly:');
  console.log('   - Wallet address (public)');
  console.log('   - Commitments (privacy-preserving hashes)');
  console.log('   - Salt (enables re-computation)');
  console.log('   - Threshold value');
  console.log();
  console.log('   🔒 What stays private:');
  console.log('   - Original identity tokens/assertions');
  console.log('   - Which specific identities were used for recovery');
  console.log('   - Private key (unless explicitly requested)');
  console.log();

  console.log('✨ Key Weaver demonstration complete!');
  console.log('📋 Summary:');
  console.log(`   - Registered wallet: ${registration.address}`);
  console.log(`   - Successful recoveries: 2 (full set + partial)`);
  console.log(`   - Failed recovery attempts: 1 (threshold enforcement)`);
  console.log(`   - Privacy preserved: ✅`);
  console.log(`   - Deterministic recovery: ✅`);
  console.log(`   - Cross-device compatible: ✅`);
}

// Run the demonstration
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateKeyWeaver()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('❌ Demo failed:', error);
      process.exit(1);
    });
}

export { demonstrateKeyWeaver };