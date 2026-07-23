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
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::EncryptionError;

pub const XCHACHA20_KEY_LENGTH: usize = 32;
pub const XCHACHA20_NONCE_LENGTH: usize = 24;
pub const XCHACHA20_TAG_LENGTH: usize = 16;

pub const MAX_MESSAGE_SIZE: usize = 10_000_000;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct XChaChaNonce([u8; XCHACHA20_NONCE_LENGTH]);

impl XChaChaNonce {
    pub fn generate() -> Result<Self, EncryptionError> {
        let mut nonce = [0u8; XCHACHA20_NONCE_LENGTH];

        let mut rng = rand_core::OsRng;
        while nonce == [0; XCHACHA20_NONCE_LENGTH] {
            rng.try_fill_bytes(&mut nonce)
                .map_err(|_| EncryptionError::NonceGenerationFailed("OS RNG failure".into()))?;
        }

        Ok(Self(nonce))
    }

    pub fn as_bytes(&self) -> &[u8; XCHACHA20_NONCE_LENGTH] {
        &self.0
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != XCHACHA20_NONCE_LENGTH {
            return None;
        }

        if slice.iter().all(|&b| b == 0) {
            return None;
        }

        let mut nonce = [0u8; XCHACHA20_NONCE_LENGTH];
        nonce.copy_from_slice(slice);
        Some(Self(nonce))
    }
}

pub fn encrypt_data(
    key: &[u8],
    nonce: &XChaChaNonce,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, EncryptionError> {
    if plaintext.len() > MAX_MESSAGE_SIZE {
        return Err(EncryptionError::MessageTooLarge {
            size: plaintext.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    if key.len() != XCHACHA20_KEY_LENGTH {
        return Err(EncryptionError::InvalidKeyLength {
            expected: XCHACHA20_KEY_LENGTH,
            actual: key.len(),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| {
        EncryptionError::EncryptionFailed(format!(
            "Failed to create XChaCha20Poly1305 cipher: {}",
            e
        ))
    })?;

    let aad_len = associated_data.map_or(0, |data| data.len());
    let payload = Payload {
        msg: plaintext,
        aad: associated_data.unwrap_or(&[]),
    };

    cipher
        .encrypt(XNonce::from_slice(nonce.as_bytes()), payload)
        .map_err(|e| {
            EncryptionError::EncryptionFailed(format!(
                "XChaCha20Poly1305 encryption failed: {}. Plaintext length: {}, AAD length: {}",
                e,
                plaintext.len(),
                aad_len
            ))
        })
}

pub fn decrypt_data(
    key: &[u8],
    nonce: &XChaChaNonce,
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    if ciphertext.is_empty() {
        return Err(EncryptionError::InvalidCiphertext);
    }

    if ciphertext.len() < XCHACHA20_TAG_LENGTH {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let plaintext_size = ciphertext.len().saturating_sub(XCHACHA20_TAG_LENGTH);

    if plaintext_size > MAX_MESSAGE_SIZE {
        return Err(EncryptionError::MessageTooLarge {
            size: plaintext_size,
            max: MAX_MESSAGE_SIZE,
        });
    }

    if key.len() != XCHACHA20_KEY_LENGTH {
        return Err(EncryptionError::InvalidKeyLength {
            expected: XCHACHA20_KEY_LENGTH,
            actual: key.len(),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| {
        EncryptionError::DecryptionFailed(format!(
            "Failed to create XChaCha20Poly1305 cipher: {}",
            e
        ))
    })?;

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data.unwrap_or(&[]),
    };

    cipher
        .decrypt(XNonce::from_slice(nonce.as_bytes()), payload)
        .map(Zeroizing::new)
        .map_err(|_| EncryptionError::InvalidCiphertext)
}

pub fn generate_xchacha_nonce() -> Result<XChaChaNonce, EncryptionError> {
    XChaChaNonce::generate()
}
