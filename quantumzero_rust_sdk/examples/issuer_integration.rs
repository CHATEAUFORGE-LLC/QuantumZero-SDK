/// Example demonstrating issuer integration with QuantumZero service
/// 
/// This example shows how an issuer can:
/// 1. Generate a DID-compliant key pair for registration
/// 2. Sign credential data for issuance
/// 3. Verify signatures from credential holders

use quantumzero_rust_sdk::CryptoCore;

fn main() {
    println!("=== QuantumZero Issuer Integration Example ===\n");
    
    // Initialize the crypto core
    let crypto = CryptoCore::new();
    
    // Step 1: Generate issuer DID key pair
    println!("1. Generating issuer DID key pair...");
    let issuer_key_pair = crypto.generate_key_pair();
    println!("   Public Key: {}", hex::encode(issuer_key_pair.verifying_key.to_bytes()));
    println!("   ✓ Key pair generated\n");
    
    // Step 2: Sign a credential schema definition
    println!("2. Signing credential schema...");
    let schema_data = b"{ \"type\": \"EducationCredential\", \"properties\": [...] }";
    let schema_signature = crypto.sign_data(schema_data, &issuer_key_pair);
    println!("   Schema hash: {}", hex::encode(crypto.hash_data(schema_data)));
    println!("   Signature: {}", hex::encode(schema_signature.to_bytes()));
    println!("   ✓ Schema signed\n");
    
    // Step 3: Issue a credential
    println!("3. Issuing a credential...");
    let credential_data = b"{\"holder\":\"did:key:abc123\",\"degree\":\"Bachelor of Science\"}";
    let credential_hash = crypto.hash_data(credential_data);
    let credential_signature = crypto.sign_data(&credential_hash, &issuer_key_pair);
    println!("   Credential hash: {}", hex::encode(&credential_hash));
    println!("   Issuer signature: {}", hex::encode(credential_signature.to_bytes()));
    println!("   ✓ Credential issued\n");
    
    // Step 4: Verify the credential signature (as a verifier would)
    println!("4. Verifying credential signature...");
    let is_valid = crypto.verify_signature(
        &credential_hash,
        &credential_signature,
        &issuer_key_pair.verifying_key,
    );
    println!("   Signature valid: {}", is_valid);
    println!("   ✓ Verification complete\n");
    
    // Step 5: Demonstrate interoperability with holder signature
    println!("5. Simulating holder signature (mobile app)...");
    let holder_key_pair = crypto.generate_key_pair();
    let presentation_data = b"I present this credential to the verifier";
    let holder_signature = crypto.sign_data(presentation_data, &holder_key_pair);
    println!("   Holder public key: {}", hex::encode(holder_key_pair.verifying_key.to_bytes()));
    println!("   Holder signature: {}", hex::encode(holder_signature.to_bytes()));
    
    let holder_valid = crypto.verify_signature(
        presentation_data,
        &holder_signature,
        &holder_key_pair.verifying_key,
    );
    println!("   Holder signature valid: {}", holder_valid);
    println!("   ✓ Holder authentication verified\n");
    
    println!("=== Integration Example Complete ===");
    println!("\nNext Steps:");
    println!("- Register this issuer DID with QuantumZero service");
    println!("- Define credential schemas using the issuer key");
    println!("- Issue credentials to mobile app holders");
    println!("- Verify holder presentations using their public keys");
}
