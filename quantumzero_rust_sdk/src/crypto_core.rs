use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature, SecretKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use p256::ecdsa::{signature::Verifier as P256Verifier, Signature as P256Signature, VerifyingKey as P256VerifyingKey};

/// Core cryptographic operations for QuantumZero identity platform
/// Provides W3C DID-compliant Ed25519 key generation, signing, and verification
pub struct CryptoCore;

#[derive(Debug)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl CryptoCore {
    /// Creates a new instance of CryptoCore
    pub fn new() -> Self {
        Self
    }

    /// Generates a new Ed25519 key pair compliant with W3C DID standards
    /// 
    /// This method generates cryptographic keys in software memory, which is appropriate for:
    /// - Server-side issuer operations
    /// - Testing and development
    /// - Ephemeral session keys
    /// 
    /// # Example
    /// ```
    /// use quantumzero_rust_sdk::CryptoCore;
    /// 
    /// let crypto = CryptoCore::new();
    /// let key_pair = crypto.generate_key_pair();
    /// ```
    pub fn generate_key_pair(&self) -> KeyPair {
        use rand::RngCore;
        let mut csprng = OsRng;
        // Generate 32 random bytes for the secret key
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        KeyPair {
            signing_key,
            verifying_key,
        }
    }

    /// Hashes data using SHA-256
    /// 
    /// # Arguments
    /// * `data` - The data to hash
    /// 
    /// # Returns
    /// A 32-byte hash
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Signs data using the private key
    /// 
    /// # Arguments
    /// * `data` - The data to sign
    /// * `key_pair` - The key pair containing the signing key
    /// 
    /// # Returns
    /// A 64-byte signature
    pub fn sign_data(&self, data: &[u8], key_pair: &KeyPair) -> Signature {
        key_pair.signing_key.sign(data)
    }

    /// Verifies a signature using the public key
    /// 
    /// # Arguments
    /// * `data` - The original data that was signed
    /// * `signature` - The signature to verify
    /// * `verifying_key` - The public key to verify against
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
        verifying_key: &VerifyingKey,
    ) -> bool {
        verifying_key.verify(data, signature).is_ok()
    }

    /// Verifies a NIST P-256 signature (Used for Android StrongBox Keys)
    pub fn verify_hardware_signature(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> bool {
        // Parse the public key (SEC1 encoded)
        if let Ok(verifying_key) = P256VerifyingKey::from_sec1_bytes(public_key_bytes) {
            // Parse the signature (ASN.1 DER or Fixed size - Android usually returns DER)
            if let Ok(signature) = P256Signature::from_der(signature_bytes) {
                return verifying_key.verify(data, &signature).is_ok();
            }
        }
        false
    }
}

impl Default for CryptoCore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        
        // Verify key pair is valid
        assert_eq!(key_pair.signing_key.verifying_key().to_bytes(), key_pair.verifying_key.to_bytes());
    }

    #[test]
    fn test_key_generation_produces_unique_keys() {
        let crypto = CryptoCore::new();
        let key_pair1 = crypto.generate_key_pair();
        let key_pair2 = crypto.generate_key_pair();
        
        // Each generation should produce unique keys
        assert_ne!(key_pair1.signing_key.to_bytes(), key_pair2.signing_key.to_bytes());
        assert_ne!(key_pair1.verifying_key.to_bytes(), key_pair2.verifying_key.to_bytes());
    }

    #[test]
    fn test_key_pair_consistency() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        
        // Signing key should derive the same verifying key
        let derived_verifying = key_pair.signing_key.verifying_key();
        assert_eq!(derived_verifying.to_bytes(), key_pair.verifying_key.to_bytes());
    }

    #[test]
    fn test_verifying_key_size() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        
        // Ed25519 public keys are 32 bytes
        assert_eq!(key_pair.verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_signing_key_size() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        
        // Ed25519 secret keys are 32 bytes
        assert_eq!(key_pair.signing_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_hashing() {
        let crypto = CryptoCore::new();
        let data = b"test data";
        let hash = crypto.hash_data(data);
        
        // SHA-256 produces 32 bytes
        assert_eq!(hash.len(), 32);
        
        // Same data produces same hash
        let hash2 = crypto.hash_data(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hashing_empty_data() {
        let crypto = CryptoCore::new();
        let hash = crypto.hash_data(b"");
        
        // SHA-256 of empty data is still 32 bytes
        assert_eq!(hash.len(), 32);
        
        // Known SHA-256 hash of empty string
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hashing_different_data_produces_different_hashes() {
        let crypto = CryptoCore::new();
        let hash1 = crypto.hash_data(b"data1");
        let hash2 = crypto.hash_data(b"data2");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hashing_deterministic() {
        let crypto = CryptoCore::new();
        let data = b"consistent data";
        
        // Hash the same data multiple times
        let hashes: Vec<_> = (0..10).map(|_| crypto.hash_data(data)).collect();
        
        // All hashes should be identical
        for hash in &hashes[1..] {
            assert_eq!(&hashes[0], hash);
        }
    }

    #[test]
    fn test_hashing_large_data() {
        let crypto = CryptoCore::new();
        let large_data = vec![0u8; 1_000_000]; // 1 MB of zeros
        let hash = crypto.hash_data(&large_data);
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signing_and_verification() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let data = b"test message";
        
        // Sign the data
        let signature = crypto.sign_data(data, &key_pair);
        
        // Verify with correct public key
        assert!(crypto.verify_signature(data, &signature, &key_pair.verifying_key));
        
        // Verify fails with wrong data
        let wrong_data = b"different message";
        assert!(!crypto.verify_signature(wrong_data, &signature, &key_pair.verifying_key));
    }

    #[test]
    fn test_signature_size() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let data = b"test";
        
        let signature = crypto.sign_data(data, &key_pair);
        
        // Ed25519 signatures are 64 bytes
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_signature_with_different_keypair() {
        let crypto = CryptoCore::new();
        let key_pair1 = crypto.generate_key_pair();
        let key_pair2 = crypto.generate_key_pair();
        let data = b"test message";
        
        let signature = crypto.sign_data(data, &key_pair1);
        
        // Verification should fail with different public key
        assert!(!crypto.verify_signature(data, &signature, &key_pair2.verifying_key));
    }

    #[test]
    fn test_signature_deterministic() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let data = b"deterministic test";
        
        // Sign the same data multiple times with the same key
        let sig1 = crypto.sign_data(data, &key_pair);
        let sig2 = crypto.sign_data(data, &key_pair);
        
        // Ed25519 signatures should be deterministic
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_signature_with_empty_data() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let data = b"";
        
        let signature = crypto.sign_data(data, &key_pair);
        assert!(crypto.verify_signature(data, &signature, &key_pair.verifying_key));
    }

    #[test]
    fn test_signature_with_large_data() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let large_data = vec![0xAB; 10_000];
        
        let signature = crypto.sign_data(&large_data, &key_pair);
        assert!(crypto.verify_signature(&large_data, &signature, &key_pair.verifying_key));
    }

    #[test]
    fn test_signature_modified_data_fails() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let mut data = b"original data".to_vec();
        
        let signature = crypto.sign_data(&data, &key_pair);
        
        // Modify the data slightly
        data[0] = b'X';
        
        // Verification should fail
        assert!(!crypto.verify_signature(&data, &signature, &key_pair.verifying_key));
    }

    #[test]
    fn test_signature_tampered_signature_fails() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        let data = b"test data";
        
        let mut signature = crypto.sign_data(data, &key_pair);
        
        // Tamper with signature bytes
        let mut sig_bytes = signature.to_bytes();
        sig_bytes[0] ^= 0xFF; // Flip bits
        
        let tampered_sig = Signature::from_bytes(&sig_bytes);
        
        // Verification should fail
        assert!(!crypto.verify_signature(data, &tampered_sig, &key_pair.verifying_key));
    }

    #[test]
    fn test_multiple_signatures_same_key() {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();
        
        // Sign multiple different messages
        let messages = [b"msg1", b"msg2", b"msg3", b"msg4"];
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| crypto.sign_data(*msg, &key_pair))
            .collect();
        
        // Each signature should verify with its corresponding message
        for (msg, sig) in messages.iter().zip(signatures.iter()) {
            assert!(crypto.verify_signature(*msg, sig, &key_pair.verifying_key));
        }
        
        // Each signature should NOT verify with different messages
        for (i, msg) in messages.iter().enumerate() {
            for (j, sig) in signatures.iter().enumerate() {
                if i != j {
                    assert!(!crypto.verify_signature(*msg, sig, &key_pair.verifying_key));
                }
            }
        }
    }

    #[test]
    fn test_verify_hardware_signature_with_invalid_key() {
        let crypto = CryptoCore::new();
        let data = b"test data";
        let signature = vec![0u8; 64];
        let invalid_key = vec![0u8; 10]; // Invalid key length
        
        // Should return false for invalid key
        assert!(!crypto.verify_hardware_signature(data, &signature, &invalid_key));
    }

    #[test]
    fn test_verify_hardware_signature_with_invalid_signature() {
        let crypto = CryptoCore::new();
        let data = b"test data";
        let invalid_signature = vec![0u8; 10]; // Invalid signature
        
        // Generate a valid P256 key for testing (33 bytes compressed)
        let valid_p256_key = vec![
            0x03, // Compression byte
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        
        // Should return false for invalid signature format
        assert!(!crypto.verify_hardware_signature(data, &invalid_signature, &valid_p256_key));
    }

    #[test]
    fn test_default_trait() {
        let crypto1 = CryptoCore::new();
        let crypto2 = CryptoCore::default();
        
        // Both should produce valid key pairs
        let key1 = crypto1.generate_key_pair();
        let key2 = crypto2.generate_key_pair();
        
        assert_eq!(key1.verifying_key.to_bytes().len(), 32);
        assert_eq!(key2.verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_cross_verification_workflow() {
        let crypto = CryptoCore::new();
        
        // Simulate issuer workflow
        let issuer_key = crypto.generate_key_pair();
        let credential_data = serde_json::json!({
            "holder": "did:key:z123",
            "degree": "Bachelor of Science"
        });
        let credential_bytes = credential_data.to_string().into_bytes();
        
        // Issuer signs credential
        let signature = crypto.sign_data(&credential_bytes, &issuer_key);
        
        // Verifier can verify using issuer's public key
        assert!(crypto.verify_signature(&credential_bytes, &signature, &issuer_key.verifying_key));
        
        // Modified credential fails verification
        let tampered_data = serde_json::json!({
            "holder": "did:key:z456",  // Changed holder
            "degree": "Bachelor of Science"
        });
        let tampered_bytes = tampered_data.to_string().into_bytes();
        assert!(!crypto.verify_signature(&tampered_bytes, &signature, &issuer_key.verifying_key));
    }
}
