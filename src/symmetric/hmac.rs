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
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::EncryptionError;

pub type HmacSha256 = Hmac<Sha256>;

pub const HMAC_SHA256_TAG_LENGTH: usize = 32;
pub const MIN_HMAC_KEY_LENGTH: usize = 32;

pub fn compute_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if key.len() < MIN_HMAC_KEY_LENGTH {
        return Err(EncryptionError::InvalidKeyLength {
            expected: MIN_HMAC_KEY_LENGTH,
            actual: key.len(),
        });
    }

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| EncryptionError::EncryptionFailed("Invalid HMAC key length".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), EncryptionError> {
    if key.len() < MIN_HMAC_KEY_LENGTH {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| EncryptionError::InvalidCiphertext)?;
    mac.update(data);
    mac.verify_slice(tag)
        .map_err(|_| EncryptionError::InvalidCiphertext)
}
