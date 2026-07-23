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
use argon2::{Argon2, Params};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    Argon2idParams, Argon2idPreset, KeyError,
    types::{Argon2idKeyResult, Argon2idPresetInfo},
};

pub const ARGON2ID_SALT_LENGTH: usize = 16;

pub fn argon2id_preset_info() -> [Argon2idPresetInfo; 4] {
    [
        Argon2idPresetInfo {
            preset: Argon2idPreset::Low,
            name: "Low",
            memory: "19 MiB",
            memory_mib: 19,
            params: Argon2idParams {
                m_cost: 19_456,
                t_cost: 2,
                p_cost: 1,
            },
            target_use_case: "For low-memory and older devices.",
        },
        Argon2idPresetInfo {
            preset: Argon2idPreset::Medium,
            name: "Medium",
            memory: "64 MiB",
            memory_mib: 64,
            params: Argon2idParams {
                m_cost: 65_536,
                t_cost: 3,
                p_cost: 4,
            },
            target_use_case: "Maximum for mobile devices.",
        },
        Argon2idPresetInfo {
            preset: Argon2idPreset::High,
            name: "High",
            memory: "256 MiB",
            memory_mib: 256,
            params: Argon2idParams {
                m_cost: 262_144,
                t_cost: 3,
                p_cost: 4,
            },
            target_use_case: "Recommended for desktops and laptops.",
        },
        Argon2idPresetInfo {
            preset: Argon2idPreset::Maximum,
            name: "Maximum",
            memory: "1 GiB",
            memory_mib: 1024,
            params: Argon2idParams {
                m_cost: 1_048_576,
                t_cost: 3,
                p_cost: 4,
            },
            target_use_case: "Maximum security for powerful systems.",
        },
    ]
}

pub fn argon2id_params_for_preset(preset: &Argon2idPreset) -> Argon2idParams {
    match preset {
        Argon2idPreset::Low => argon2id_preset_info()[0].params,
        Argon2idPreset::Medium => argon2id_preset_info()[1].params,
        Argon2idPreset::High => argon2id_preset_info()[2].params,
        Argon2idPreset::Maximum => argon2id_preset_info()[3].params,
        Argon2idPreset::Custom(params) => *params,
    }
}

pub fn derive_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    preset: Argon2idPreset,
    key_length: usize,
) -> Result<Argon2idKeyResult, KeyError> {
    if password.is_empty() {
        return Err(KeyError::GenerationFailed("Empty password".into()));
    }

    if !(16..=1024).contains(&key_length) {
        return Err(KeyError::GenerationFailed(
            "Invalid key length: must be between 16 and 1024 bytes".into(),
        ));
    }

    let params = argon2id_params_for_preset(&preset);

    params
        .validate()
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    let mut salt = [0u8; ARGON2ID_SALT_LENGTH];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| KeyError::GenerationFailed("Failed to generate salt".into()))?;

    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(key_length), // Output length depends on the key size
    )
    .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    let block_count = argon2_params.block_count();
    let argon2 = if let Some(sec) = secret {
        Argon2::new_with_secret(
            sec,
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        )
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?
    } else {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        )
    };

    let mut output_key = Zeroizing::new(vec![0u8; key_length]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); block_count]);
    argon2
        .hash_password_into_with_memory(password, &salt, &mut output_key, memory.as_mut_slice())
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    let params_bytes = params.to_le_bytes().to_vec();

    Ok(Argon2idKeyResult {
        key: output_key,
        salt: salt.to_vec(),
        params: params_bytes,
    })
}

pub fn reconstruct_key_argon2id(
    password: &[u8],
    secret: Option<&[u8]>,
    salt: &[u8],
    params_bytes: &[u8],
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if password.is_empty() {
        return Err(KeyError::GenerationFailed("Empty password".into()));
    }

    if !(16..=1024).contains(&key_length) {
        return Err(KeyError::GenerationFailed(
            "Invalid key length: must be between 16 and 1024 bytes".into(),
        ));
    }

    let params = Argon2idParams::from_le_bytes(params_bytes)
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    if salt.len() != ARGON2ID_SALT_LENGTH {
        return Err(KeyError::InvalidLength {
            expected: ARGON2ID_SALT_LENGTH,
            actual: salt.len(),
        });
    }

    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(key_length),
    )
    .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    let block_count = argon2_params.block_count();
    let argon2 = if let Some(sec) = secret {
        Argon2::new_with_secret(
            sec,
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        )
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?
    } else {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        )
    };

    let mut output_key = Zeroizing::new(vec![0u8; key_length]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); block_count]);
    argon2
        .hash_password_into_with_memory(password, salt, &mut output_key, memory.as_mut_slice())
        .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;

    Ok(output_key)
}
