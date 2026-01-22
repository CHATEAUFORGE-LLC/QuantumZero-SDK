use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

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
    /// # ⚠️ SECURITY WARNING
    /// **Generates a SOFTWARE key in memory.**
    /// - **DO NOT USE** for Root Identity on Mobile (Task #32 requires Hardware Keys).
    /// - Use this only for testing, server-side operations, or ephemeral session keys.
    /// - For mobile apps, integrate with platform-specific secure key storage (e.g., Android StrongBox, iOS Secure Enclave).
    ///
    /// # Example
    /// ```
    /// use quantumzero_rust_sdk::CryptoCore;
    /// 
    /// let crypto = CryptoCore::new();
    /// let key_pair = crypto.generate_key_pair();
    /// ```
    pub fn generate_key_pair(&self) -> KeyPair {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
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
    fn test_signature_with_different_keypair() {
        let crypto = CryptoCore::new();
        let key_pair1 = crypto.generate_key_pair();
        let key_pair2 = crypto.generate_key_pair();
        let data = b"test message";
        
        let signature = crypto.sign_data(data, &key_pair1);
        
        // Verification should fail with different public key
        assert!(!crypto.verify_signature(data, &signature, &key_pair2.verifying_key));
    }
}
