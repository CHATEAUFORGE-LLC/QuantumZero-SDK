mod crypto_core;
pub mod anoncreds_ffi;

pub use crypto_core::{CryptoCore, KeyPair};

// Re-export key types for convenience
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
