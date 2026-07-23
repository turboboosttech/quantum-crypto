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
use zeroize::Zeroizing;

use crate::{
    Argon2idPreset, CombinedPublicKey, CombinedSecretKey, KeyError, XCHACHA20_KEY_LENGTH,
    types::{RootKeyResult, RootKeySource},
};

use super::keys::{
    decapsulate_root_key_internal, generate_key_argon2id, generate_root_key_ml_kem_internal,
    reconstruct_key_argon2id_internal,
};

pub fn generate_root_key_ml_kem(public_key: &CombinedPublicKey) -> Result<RootKeyResult, KeyError> {
    let (key, ciphertext) = generate_root_key_ml_kem_internal(public_key)?;

    Ok(RootKeyResult {
        key,
        source: RootKeySource::MlKem { ciphertext },
    })
}

pub fn derive_root_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    preset: Argon2idPreset,
) -> Result<RootKeyResult, KeyError> {
    let result = generate_key_argon2id(password, secret, preset, XCHACHA20_KEY_LENGTH)?;

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
    reconstruct_key_argon2id_internal(password, secret, salt, params_bytes, XCHACHA20_KEY_LENGTH)
}

pub fn decapsulate_root_key(
    secret_key: &CombinedSecretKey,
    source: &RootKeySource,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    match source {
        RootKeySource::MlKem { ciphertext } => {
            decapsulate_root_key_internal(secret_key, ciphertext)
        }
        RootKeySource::Argon2id { .. } => Err(KeyError::GenerationFailed(
            "Use reconstruct_root_key_argon2id for password-based keys".into(),
        )),
    }
}
