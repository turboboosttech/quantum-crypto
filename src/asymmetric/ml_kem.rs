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
use pqcrypto_mlkem::mlkem1024::Ciphertext as KemCiphertext;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{CombinedPublicKey, CombinedSecretKey, KeyError};

pub const MLKEM1024_PUBLIC_KEY_LENGTH: usize = 1568;
pub const MLKEM1024_SECRET_KEY_LENGTH: usize = 3168;
pub const MLKEM1024_CIPHERTEXT_LENGTH: usize = 1568;
pub const MLKEM1024_SHARED_SECRET_LENGTH: usize = 32;

#[deprecated(note = "Use MLKEM1024_PUBLIC_KEY_LENGTH")]
pub const KYBER1024_PUBLIC_KEY_LENGTH: usize = MLKEM1024_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLKEM1024_SECRET_KEY_LENGTH")]
pub const KYBER1024_SECRET_KEY_LENGTH: usize = MLKEM1024_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLKEM1024_CIPHERTEXT_LENGTH")]
pub const KYBER1024_CIPHERTEXT_LENGTH: usize = MLKEM1024_CIPHERTEXT_LENGTH;
#[deprecated(note = "Use MLKEM1024_SHARED_SECRET_LENGTH")]
pub const KYBER1024_SHARED_SECRET_LENGTH: usize = MLKEM1024_SHARED_SECRET_LENGTH;

#[derive(Clone, ZeroizeOnDrop)]
pub struct EncapsulationResult {
    ciphertext: Zeroizing<Vec<u8>>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl EncapsulationResult {
    pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Result<Self, KeyError> {
        if ciphertext.len() != MLKEM1024_CIPHERTEXT_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_CIPHERTEXT_LENGTH,
                actual: ciphertext.len(),
            });
        }

        if shared_secret.len() != MLKEM1024_SHARED_SECRET_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_SHARED_SECRET_LENGTH,
                actual: shared_secret.len(),
            });
        }

        if ciphertext.iter().all(|&b| b == 0) || shared_secret.iter().all(|&b| b == 0) {
            return Err(KeyError::InvalidFormat);
        }

        Ok(Self {
            ciphertext: Zeroizing::new(ciphertext),
            shared_secret: Zeroizing::new(shared_secret),
        })
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

pub fn encapsulate_key(public_key: &CombinedPublicKey) -> Result<EncapsulationResult, KeyError> {
    let ml_kem_pk = public_key.ml_kem()?;
    let (shared_secret, ciphertext) = pqcrypto_mlkem::mlkem1024::encapsulate(&ml_kem_pk);

    EncapsulationResult::new(
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    )
}

pub fn decapsulate_key(
    secret_key: &CombinedSecretKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if ciphertext.is_empty() {
        return Err(KeyError::InvalidFormat);
    }

    if ciphertext.len() != MLKEM1024_CIPHERTEXT_LENGTH {
        return Err(KeyError::InvalidLength {
            expected: MLKEM1024_CIPHERTEXT_LENGTH,
            actual: ciphertext.len(),
        });
    }

    let ciphertext = KemCiphertext::from_bytes(ciphertext)?;
    let shared_secret = {
        let ml_kem_sk = secret_key.ml_kem()?;
        pqcrypto_mlkem::mlkem1024::decapsulate(&ciphertext, &ml_kem_sk)
    };

    Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
}
