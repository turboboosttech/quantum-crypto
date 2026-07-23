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
use crate::{
    Argon2idKeyResult, Argon2idPreset, CombinedPublicKey, CombinedSecretKey, KeyError,
    asymmetric::ml_kem::{MLKEM1024_CIPHERTEXT_LENGTH, decapsulate_key, encapsulate_key},
    kdf::argon2id::{derive_key_argon2id, reconstruct_key_argon2id as argon2id_reconstruct},
};
use zeroize::Zeroizing;

pub fn generate_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    preset: Argon2idPreset,
    key_length: usize,
) -> Result<Argon2idKeyResult, KeyError> {
    derive_key_argon2id(password, secret, preset, key_length)
}

pub fn reconstruct_key_argon2id_internal(
    password: &[u8],
    secret: Option<&[u8]>,
    salt: &[u8],
    params_bytes: &[u8],
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    argon2id_reconstruct(password, secret, salt, params_bytes, key_length)
}

pub fn generate_root_key_ml_kem_internal(
    public_key: &CombinedPublicKey,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), KeyError> {
    let encap = encapsulate_key(public_key)?;

    Ok((
        Zeroizing::new(encap.shared_secret().to_vec()),
        encap.ciphertext().to_vec(),
    ))
}

pub fn decapsulate_root_key_internal(
    secret_key: &CombinedSecretKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if ciphertext.len() != MLKEM1024_CIPHERTEXT_LENGTH {
        return Err(KeyError::InvalidLength {
            expected: MLKEM1024_CIPHERTEXT_LENGTH,
            actual: ciphertext.len(),
        });
    }

    let shared_secret = decapsulate_key(secret_key, ciphertext)?;
    Ok(shared_secret)
}
