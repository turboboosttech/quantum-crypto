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
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_traits::sign::DetachedSignature;

use crate::{
    CombinedPublicKey, CombinedSecretKey,
    errors::KeyError,
    types::{DilithiumPublicKey, DilithiumSecretKey},
};

pub const MLDSA44_PUBLIC_KEY_LENGTH: usize = 1312;
pub const MLDSA44_SECRET_KEY_LENGTH: usize = 2560;
pub const MLDSA44_SIGNATURE_LENGTH: usize = 2420;

pub const MLDSA65_PUBLIC_KEY_LENGTH: usize = 1952;
pub const MLDSA65_SECRET_KEY_LENGTH: usize = 4032;
pub const MLDSA65_SIGNATURE_LENGTH: usize = 3309;

pub const MLDSA87_PUBLIC_KEY_LENGTH: usize = 2592;
pub const MLDSA87_SECRET_KEY_LENGTH: usize = 4896;
pub const MLDSA87_SIGNATURE_LENGTH: usize = 4627;

#[deprecated(note = "Use MLDSA44_PUBLIC_KEY_LENGTH")]
pub const DILITHIUM2_PUBLIC_KEY_LENGTH: usize = MLDSA44_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA44_SECRET_KEY_LENGTH")]
pub const DILITHIUM2_SECRET_KEY_LENGTH: usize = MLDSA44_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA44_SIGNATURE_LENGTH")]
pub const DILITHIUM2_SIGNATURE_LENGTH: usize = MLDSA44_SIGNATURE_LENGTH;
#[deprecated(note = "Use MLDSA65_PUBLIC_KEY_LENGTH")]
pub const DILITHIUM3_PUBLIC_KEY_LENGTH: usize = MLDSA65_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA65_SECRET_KEY_LENGTH")]
pub const DILITHIUM3_SECRET_KEY_LENGTH: usize = MLDSA65_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA65_SIGNATURE_LENGTH")]
pub const DILITHIUM3_SIGNATURE_LENGTH: usize = MLDSA65_SIGNATURE_LENGTH;
#[deprecated(note = "Use MLDSA87_PUBLIC_KEY_LENGTH")]
pub const DILITHIUM5_PUBLIC_KEY_LENGTH: usize = MLDSA87_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA87_SECRET_KEY_LENGTH")]
pub const DILITHIUM5_SECRET_KEY_LENGTH: usize = MLDSA87_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA87_SIGNATURE_LENGTH")]
pub const DILITHIUM5_SIGNATURE_LENGTH: usize = MLDSA87_SIGNATURE_LENGTH;

pub const MAX_SIGNABLE_SIZE: usize = 100_000_000;

pub const SIGN_CONTEXT_SYNC_CHALLENGE: &[u8] = b"9s.sync.challenge.v1";
pub const SIGN_CONTEXT_PAIRING: &[u8] = b"9s.pairing.v1";

fn validate_message_size(message: &[u8]) -> Result<(), KeyError> {
    if message.len() > MAX_SIGNABLE_SIZE {
        return Err(KeyError::MessageTooLong {
            size: message.len(),
            max: MAX_SIGNABLE_SIZE,
        });
    }
    Ok(())
}

fn sign_message_raw(secret_key: &CombinedSecretKey, message: &[u8]) -> Result<Vec<u8>, KeyError> {
    validate_message_size(message)?;

    let signature = {
        let dilithium_sk = secret_key
            .ml_dsa()?
            .ok_or(KeyError::SigningKeyNotAvailable)?;

        match dilithium_sk {
            DilithiumSecretKey::V2(ref sk) => {
                let sig = mldsa44::detached_sign(message, sk);
                if sig.as_bytes().len() != MLDSA44_SIGNATURE_LENGTH {
                    return Err(KeyError::InvalidLength {
                        expected: MLDSA44_SIGNATURE_LENGTH,
                        actual: sig.as_bytes().len(),
                    });
                }
                sig.as_bytes().to_vec()
            }
            DilithiumSecretKey::V3(ref sk) => {
                let sig = mldsa65::detached_sign(message, sk);
                if sig.as_bytes().len() != MLDSA65_SIGNATURE_LENGTH {
                    return Err(KeyError::InvalidLength {
                        expected: MLDSA65_SIGNATURE_LENGTH,
                        actual: sig.as_bytes().len(),
                    });
                }
                sig.as_bytes().to_vec()
            }
            DilithiumSecretKey::V5(ref sk) => {
                let sig = mldsa87::detached_sign(message, sk);
                if sig.as_bytes().len() != MLDSA87_SIGNATURE_LENGTH {
                    return Err(KeyError::InvalidLength {
                        expected: MLDSA87_SIGNATURE_LENGTH,
                        actual: sig.as_bytes().len(),
                    });
                }
                sig.as_bytes().to_vec()
            }
        }
    };

    Ok(signature)
}

fn verify_signature_raw(
    public_key: &CombinedPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), KeyError> {
    let dilithium_pk = match public_key.ml_dsa()? {
        Some(pk) => pk,
        None => return Err(KeyError::VerificationKeyNotAvailable),
    };

    let expected_len = match &dilithium_pk {
        DilithiumPublicKey::V2(_) => MLDSA44_SIGNATURE_LENGTH,
        DilithiumPublicKey::V3(_) => MLDSA65_SIGNATURE_LENGTH,
        DilithiumPublicKey::V5(_) => MLDSA87_SIGNATURE_LENGTH,
    };

    if signature.len() != expected_len {
        return Err(KeyError::InvalidLength {
            expected: expected_len,
            actual: signature.len(),
        });
    }

    let result = match dilithium_pk {
        DilithiumPublicKey::V2(pk) => {
            let sig = mldsa44::DetachedSignature::from_bytes(signature)
                .map_err(|_| KeyError::DeserializationError)?;
            mldsa44::verify_detached_signature(&sig, message, &pk)
        }
        DilithiumPublicKey::V3(pk) => {
            let sig = mldsa65::DetachedSignature::from_bytes(signature)
                .map_err(|_| KeyError::DeserializationError)?;
            mldsa65::verify_detached_signature(&sig, message, &pk)
        }
        DilithiumPublicKey::V5(pk) => {
            let sig = mldsa87::DetachedSignature::from_bytes(signature)
                .map_err(|_| KeyError::DeserializationError)?;
            mldsa87::verify_detached_signature(&sig, message, &pk)
        }
    };

    result.map_err(|_| KeyError::SignatureVerificationFailed)
}

pub fn sign_message_enhanced(
    secret_key: &CombinedSecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, KeyError> {
    validate_message_size(message)?;

    let message_digest = enhanced_message_digest(message, context);
    sign_message_raw(secret_key, message_digest.as_bytes())
}

pub fn verify_signature_enhanced(
    public_key: &CombinedPublicKey,
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<(), KeyError> {
    validate_message_size(message)?;

    let message_digest = enhanced_message_digest(message, context);
    verify_signature_raw(public_key, message_digest.as_bytes(), signature)
}

fn enhanced_message_digest(message: &[u8], context: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ENHANCED-SIGNATURE-v2");
    hasher.update(&(context.len() as u64).to_le_bytes());
    hasher.update(context);
    hasher.update(&(message.len() as u64).to_le_bytes());
    hasher.update(message);
    hasher.finalize()
}
