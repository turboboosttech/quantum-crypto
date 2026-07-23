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
use quantum_crypto::{
    Argon2idParams, Argon2idPreset, RootKeySource, XCHACHA20_KEY_LENGTH,
    argon2id_params_for_preset, argon2id_preset_info, derive_root_key_argon2id,
    reconstruct_root_key_argon2id,
};
use subtle::ConstantTimeEq;

fn decode_params(params: &[u8]) -> Argon2idParams {
    Argon2idParams::from_le_bytes(params).expect("valid Argon2id params")
}

#[test]
fn test_argon2id_preset_info() {
    let presets = argon2id_preset_info();

    assert_eq!(presets.len(), 4);

    assert_eq!(presets[0].preset, Argon2idPreset::Low);
    assert_eq!(presets[0].name, "Low");
    assert_eq!(presets[0].memory, "19 MiB");
    assert_eq!(presets[0].memory_mib, 19);
    assert_eq!(
        presets[0].params,
        Argon2idParams {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    );
    assert_eq!(
        presets[0].target_use_case,
        "For low-memory and older devices."
    );

    assert_eq!(presets[1].preset, Argon2idPreset::Medium);
    assert_eq!(presets[1].name, "Medium");
    assert_eq!(presets[1].memory, "64 MiB");
    assert_eq!(presets[1].memory_mib, 64);
    assert_eq!(
        presets[1].params,
        Argon2idParams {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    );
    assert_eq!(presets[1].target_use_case, "Maximum for mobile devices.");

    assert_eq!(presets[2].preset, Argon2idPreset::High);
    assert_eq!(presets[2].name, "High");
    assert_eq!(presets[2].memory, "256 MiB");
    assert_eq!(presets[2].memory_mib, 256);
    assert_eq!(
        presets[2].params,
        Argon2idParams {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 4,
        }
    );
    assert_eq!(
        presets[2].target_use_case,
        "Recommended for desktops and laptops."
    );

    assert_eq!(presets[3].preset, Argon2idPreset::Maximum);
    assert_eq!(presets[3].name, "Maximum");
    assert_eq!(presets[3].memory, "1 GiB");
    assert_eq!(presets[3].memory_mib, 1024);
    assert_eq!(
        presets[3].params,
        Argon2idParams {
            m_cost: 1_048_576,
            t_cost: 3,
            p_cost: 4,
        }
    );
    assert_eq!(
        presets[3].target_use_case,
        "Maximum security for powerful systems."
    );

    for info in presets {
        assert_eq!(argon2id_params_for_preset(&info.preset), info.params);
    }
}

#[test]
fn test_argon2id_presets() {
    let password = b"test-password";

    let low_key =
        derive_root_key_argon2id(password, None, Argon2idPreset::Low).expect("Low preset failed");
    if let RootKeySource::Argon2id { params, .. } = low_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 19_456);
        assert_eq!(params.t_cost, 2);
        assert_eq!(params.p_cost, 1);
    }

    let med_key = derive_root_key_argon2id(password, None, Argon2idPreset::Medium)
        .expect("Medium preset failed");
    if let RootKeySource::Argon2id { params, .. } = med_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 65_536);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    let high_key =
        derive_root_key_argon2id(password, None, Argon2idPreset::High).expect("High preset failed");
    if let RootKeySource::Argon2id { params, .. } = high_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 262_144);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    assert_ne!(low_key.key(), med_key.key());
    assert_ne!(med_key.key(), high_key.key());
    assert_ne!(low_key.key(), high_key.key());
}

#[test]
fn test_argon2id_key_generation() {
    let password = b"test-password-123";
    let params = Argon2idParams {
        m_cost: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    let key_result = derive_root_key_argon2id(password, None, Argon2idPreset::Custom(params))
        .expect("Failed to generate key");

    assert_eq!(key_result.key().len(), XCHACHA20_KEY_LENGTH);

    match key_result.source() {
        RootKeySource::Argon2id {
            salt,
            params: params_bytes,
        } => {
            assert_eq!(salt.len(), 16);
            let deserialized_params = decode_params(params_bytes);
            assert_eq!(deserialized_params, params);
        }
        _ => panic!("Wrong key source type"),
    }

    if let RootKeySource::Argon2id {
        salt,
        params: params_bytes,
    } = key_result.source()
    {
        let reconstructed = reconstruct_root_key_argon2id(password, None, salt, params_bytes)
            .expect("Failed to reconstruct key");
        assert!(bool::from(key_result.key().ct_eq(&reconstructed)));
    }
}

#[test]
fn test_argon2id_parameter_validation() {
    let password = b"test-password";

    let invalid_params = Argon2idParams {
        m_cost: 0, // Invalid memory cost
        t_cost: 0, // Invalid time cost
        p_cost: 0, // Invalid parallelism
    };

    let result = derive_root_key_argon2id(password, None, Argon2idPreset::Custom(invalid_params));
    assert!(result.is_err());

    let result = derive_root_key_argon2id(&[], None, Argon2idPreset::Medium);
    assert!(result.is_err());

    let invalid_salt = vec![0u8; 8]; // Wrong length
    let params = Argon2idParams::default();
    let params_bytes = params.to_le_bytes();

    let result = reconstruct_root_key_argon2id(password, None, &invalid_salt, &params_bytes);
    assert!(result.is_err());
}

#[test]
fn test_argon2id_params_fixed_little_endian_encoding() {
    let params = Argon2idParams {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    let encoded = params.to_le_bytes();
    assert_eq!(encoded.len(), Argon2idParams::SERIALIZED_LEN);
    assert_eq!(encoded, [0, 76, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(Argon2idParams::from_le_bytes(&encoded), Ok(params));
    assert!(Argon2idParams::from_le_bytes(&encoded[..11]).is_err());
}

#[test]
fn test_argon2id_rejects_excessive_deserialized_memory_cost() {
    let password = b"test-password";
    let salt = [1u8; 16];
    let malicious_params = Argon2idParams {
        m_cost: 1_048_577,
        t_cost: 1,
        p_cost: 1,
    }
    .to_le_bytes();

    let result = reconstruct_root_key_argon2id(password, None, &salt, &malicious_params);
    assert!(result.is_err());
}

#[test]
fn test_root_key_argon2id_presets() {
    let password = b"test-password";

    let low_key =
        derive_root_key_argon2id(password, None, Argon2idPreset::Low).expect("Low preset failed");
    if let RootKeySource::Argon2id { params, .. } = low_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 19_456);
        assert_eq!(params.t_cost, 2);
        assert_eq!(params.p_cost, 1);
    }

    let med_key = derive_root_key_argon2id(password, None, Argon2idPreset::Medium)
        .expect("Medium preset failed");
    if let RootKeySource::Argon2id { params, .. } = med_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 65_536);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    let high_key =
        derive_root_key_argon2id(password, None, Argon2idPreset::High).expect("High preset failed");
    if let RootKeySource::Argon2id { params, .. } = high_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 262_144);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    let max_key = derive_root_key_argon2id(password, None, Argon2idPreset::Maximum)
        .expect("Maximum preset failed");
    if let RootKeySource::Argon2id { params, .. } = max_key.source() {
        let params = decode_params(params);
        assert_eq!(params.m_cost, 1_048_576);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    assert_ne!(low_key.key(), med_key.key());
    assert_ne!(med_key.key(), high_key.key());
    assert_ne!(low_key.key(), high_key.key());
    assert_ne!(high_key.key(), max_key.key());
}

#[test]
fn test_root_key_argon2id_key_generation() {
    let password = b"test-password-123";
    let params = Argon2idParams {
        m_cost: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    let key_result = derive_root_key_argon2id(password, None, Argon2idPreset::Custom(params))
        .expect("Failed to generate key");

    assert_eq!(key_result.key().len(), XCHACHA20_KEY_LENGTH);

    match key_result.source() {
        RootKeySource::Argon2id {
            salt,
            params: params_bytes,
        } => {
            assert_eq!(salt.len(), 16);
            let deserialized_params = decode_params(params_bytes);
            assert_eq!(deserialized_params, params);
        }
        _ => panic!("Wrong key source type"),
    }

    if let RootKeySource::Argon2id {
        salt,
        params: params_bytes,
    } = key_result.source()
    {
        let reconstructed = reconstruct_root_key_argon2id(password, None, salt, params_bytes)
            .expect("Failed to reconstruct key");
        assert!(bool::from(key_result.key().ct_eq(&reconstructed)));
    }
}

#[test]
fn test_root_key_argon2id_parameter_validation() {
    let password = b"test-password";

    let invalid_params = Argon2idParams {
        m_cost: 0, // Invalid memory cost
        t_cost: 0, // Invalid time cost
        p_cost: 0, // Invalid parallelism
    };

    let result = derive_root_key_argon2id(password, None, Argon2idPreset::Custom(invalid_params));
    assert!(result.is_err());

    let result = derive_root_key_argon2id(&[], None, Argon2idPreset::Medium);
    assert!(result.is_err());

    let invalid_salt = vec![0u8; 8]; // Wrong length
    let params = Argon2idParams::default();
    let params_bytes = params.to_le_bytes();

    let result = reconstruct_root_key_argon2id(password, None, &invalid_salt, &params_bytes);
    assert!(result.is_err());
}

#[test]
fn test_argon2id_with_secret() {
    let password = b"test-password-123";
    let secret1 = b"test-secret-abc";
    let secret2 = b"test-secret-xyz";
    let preset = Argon2idPreset::Low;

    let key1 = derive_root_key_argon2id(password, Some(secret1), preset.clone())
        .expect("Failed to generate key with secret1");

    let key2 = derive_root_key_argon2id(password, Some(secret2), preset.clone())
        .expect("Failed to generate key with secret2");

    let key_none = derive_root_key_argon2id(password, None, preset)
        .expect("Failed to generate key with no secret");

    assert_ne!(key1.key(), key2.key());
    assert_ne!(key1.key(), key_none.key());
    assert_ne!(key2.key(), key_none.key());

    if let RootKeySource::Argon2id {
        salt,
        params: params_bytes,
    } = key1.source()
    {
        let reconstructed =
            reconstruct_root_key_argon2id(password, Some(secret1), salt, params_bytes)
                .expect("Failed to reconstruct key");
        assert!(bool::from(key1.key().ct_eq(&reconstructed)));

        let reconstructed_wrong =
            reconstruct_root_key_argon2id(password, Some(secret2), salt, params_bytes)
                .expect("Failed to reconstruct key with wrong secret");
        assert!(!bool::from(key1.key().ct_eq(&reconstructed_wrong)));
    }
}
