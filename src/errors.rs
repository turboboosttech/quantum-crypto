/*
 * Business Source License 1.1
 *
 * Licensor: TurboBoostTechnologies
 * Licensed Work: quantum-crypto 2026.s.3.0.0
 * Change Date: 2030-07-23
 * Change License: Apache License, Version 2.0
 *
 * See the LICENSE file for full text.
 */

use pqcrypto_traits::Error as PqcryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Invalid signature format")]
    InvalidFormat,
    #[error("Message too long: {size} bytes exceeds {max} byte limit")]
    MessageTooLong { size: usize, max: usize },
    #[error("Cryptographic operation failed")]
    CryptoError(#[from] PqcryptoError),
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Failed to deserialize key")]
    DeserializationError,
    #[error("Invalid key format")]
    InvalidFormat,
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
    #[error("Message too long: {size} bytes exceeds {max} byte limit")]
    MessageTooLong { size: usize, max: usize },
    #[error("Random number generation failed")]
    RngError,
    #[error("Cryptographic operation failed")]
    CryptoError(#[from] PqcryptoError),
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Signing key not available")]
    SigningKeyNotAvailable,
    #[error("Verification key not available")]
    VerificationKeyNotAvailable,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid ciphertext or authentication tag")]
    InvalidCiphertext,
    #[error("Message too small: {size} bytes is less than minimum {min} bytes")]
    MessageTooSmall { size: usize, min: usize },
    #[error("Message too large: {size} bytes exceeds {max} byte limit")]
    MessageTooLarge { size: usize, max: usize },
    #[error("Resource exhaustion: {size} bytes exceeds {max} byte limit")]
    ResourceExhaustion { size: usize, max: usize },
    #[error("Cryptographic operation failed")]
    CryptoError(#[from] PqcryptoError),
    #[error("Nonce generation failed: {0}")]
    NonceGenerationFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Operation cancelled by user")]
    Cancelled,
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Buffer overflow: buffer limit of {limit} bytes exceeded")]
    BufferOverflow { limit: usize },
    #[error("Stream chunk counter overflow")]
    StreamCounterOverflow,
}

#[derive(Debug, Error)]
pub enum StreamingError {
    #[error("Invalid domain")]
    InvalidDomain,
    #[error("Associated data too large")]
    AssociatedDataTooLarge,
    #[error("Invalid chunk size")]
    InvalidChunkSize,
    #[error("Invalid stream header")]
    InvalidHeader,
    #[error("Unsupported stream format")]
    UnsupportedFormat,
    #[error("Unsupported stream suite")]
    UnsupportedSuite,
    #[error("Invalid stream record")]
    InvalidRecord,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Record sequence mismatch")]
    SequenceMismatch,
    #[error("Counter overflow")]
    CounterOverflow,
    #[error("Random number generation failed")]
    RngError,
    #[error("Stream key derivation failed")]
    KeyDerivationFailed,
    #[error("Declared length exceeded")]
    LengthExceeded,
    #[error("Length mismatch")]
    LengthMismatch,
    #[error("Truncated stream")]
    Truncated,
    #[error("Trailing stream data")]
    TrailingData,
    #[error("Operation cancelled")]
    Cancelled,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum GeneratorError {
    #[error("Requested password length ({requested}) is smaller than the minimum ({minimum})")]
    LengthTooSmall { requested: usize, minimum: usize },
    #[error("Requested password length ({requested}) exceeds the maximum ({maximum})")]
    LengthTooLarge { requested: usize, maximum: usize },
    #[error("No character sets selected for password generation")]
    NoCharacterSetSelected,
    #[error("Internal generation error: {0}")]
    GenerationFailed(String),
}
