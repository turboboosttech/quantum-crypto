/*
 * Business Source License 1.1
 *
 * Licensor: TurboBoostTechnologies
 * Licensed Work: quantum-crypto 2026.s.3.0.2
 * Change Date: 2030-10-28
 * Change License: Apache License, Version 2.0
 *
 * See the LICENSE file for full text.
 */
use zeroize::Zeroizing;

use crate::{
    Argon2idPreset, CombinedPublicKey, CombinedSecretKey, KeyError, XCHACHA20_KEY_LENGTH,
    asymmetric::ml_kem::{decapsulate_key, encapsulate_key},
    kdf::argon2id::{derive_key_argon2id, reconstruct_key_argon2id},
    types::{RootKeyResult, RootKeySource},
};

pub fn generate_root_key_ml_kem(public_key: &CombinedPublicKey) -> Result<RootKeyResult, KeyError> {
    let encapsulation = encapsulate_key(public_key)?;

    Ok(RootKeyResult {
        key: Zeroizing::new(encapsulation.shared_secret().to_vec()),
        source: RootKeySource::MlKem {
            ciphertext: encapsulation.ciphertext().to_vec(),
        },
    })
}

pub fn derive_root_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    preset: Argon2idPreset,
) -> Result<RootKeyResult, KeyError> {
    let result = derive_key_argon2id(password, secret, preset, XCHACHA20_KEY_LENGTH)?;

    Ok(RootKeyResult {
        key: result.key,
        source: RootKeySource::Argon2id {
            salt: result.salt,
            params: result.params,
        },
    })
}

pub fn reconstruct_root_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    salt: &[u8],
    params_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    reconstruct_key_argon2id(password, secret, salt, params_bytes, XCHACHA20_KEY_LENGTH)
}

pub fn decapsulate_root_key(
    secret_key: &CombinedSecretKey,
    source: &RootKeySource,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    match source {
        RootKeySource::MlKem { ciphertext } => decapsulate_key(secret_key, ciphertext),
        RootKeySource::Argon2id { .. } => Err(KeyError::GenerationFailed(
            "Use reconstruct_root_key_argon2id for password-based keys".into(),
        )),
    }
}
