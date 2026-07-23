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
    CombinedPublicKey, CombinedSecretKey, DilithiumVersion, MLDSA44_PUBLIC_KEY_LENGTH,
    MLDSA44_SECRET_KEY_LENGTH, MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM1024_SECRET_KEY_LENGTH,
    generate_keypair_with_mldsa,
};
use serde::Serialize;

#[derive(Serialize)]
struct PublicKeyWire {
    #[serde(with = "quantum_crypto::serialization::key_bytes")]
    kyber: Vec<u8>,
    #[serde(with = "quantum_crypto::types::serde_option_dilithium")]
    dilithium: Option<(DilithiumVersion, Vec<u8>)>,
}

#[derive(Serialize)]
struct SecretKeyWire {
    #[serde(with = "quantum_crypto::serialization::key_bytes")]
    kyber: Vec<u8>,
    #[serde(with = "quantum_crypto::types::serde_option_dilithium")]
    dilithium: Option<(DilithiumVersion, Vec<u8>)>,
}

#[test]
fn combined_keys_serde_round_trip() {
    for version in [
        None,
        Some(DilithiumVersion::V2),
        Some(DilithiumVersion::V3),
        Some(DilithiumVersion::V5),
    ] {
        let (public, secret) = generate_keypair_with_mldsa(version).unwrap();
        let public: CombinedPublicKey =
            bincode::deserialize(&bincode::serialize(&public).unwrap()).unwrap();
        let secret: CombinedSecretKey =
            bincode::deserialize(&bincode::serialize(&secret).unwrap()).unwrap();

        assert!(public.ml_kem().is_ok());
        assert_eq!(public.ml_dsa().unwrap().is_some(), version.is_some());
        assert!(secret.ml_kem().is_ok());
        assert_eq!(secret.ml_dsa().unwrap().is_some(), version.is_some());
    }
}

#[test]
fn combined_key_deserialization_rejects_invalid_lengths() {
    let invalid_public = PublicKeyWire {
        kyber: vec![0; MLKEM1024_PUBLIC_KEY_LENGTH - 1],
        dilithium: None,
    };
    let invalid_secret = SecretKeyWire {
        kyber: vec![0; MLKEM1024_SECRET_KEY_LENGTH - 1],
        dilithium: None,
    };
    let invalid_dsa_public = PublicKeyWire {
        kyber: vec![0; MLKEM1024_PUBLIC_KEY_LENGTH],
        dilithium: Some((DilithiumVersion::V2, vec![0; MLDSA44_PUBLIC_KEY_LENGTH - 1])),
    };
    let invalid_dsa_secret = SecretKeyWire {
        kyber: vec![0; MLKEM1024_SECRET_KEY_LENGTH],
        dilithium: Some((DilithiumVersion::V2, vec![0; MLDSA44_SECRET_KEY_LENGTH - 1])),
    };

    assert!(
        bincode::deserialize::<CombinedPublicKey>(&bincode::serialize(&invalid_public).unwrap())
            .is_err()
    );
    assert!(
        bincode::deserialize::<CombinedSecretKey>(&bincode::serialize(&invalid_secret).unwrap())
            .is_err()
    );
    assert!(
        bincode::deserialize::<CombinedPublicKey>(
            &bincode::serialize(&invalid_dsa_public).unwrap()
        )
        .is_err()
    );
    assert!(
        bincode::deserialize::<CombinedSecretKey>(
            &bincode::serialize(&invalid_dsa_secret).unwrap()
        )
        .is_err()
    );

    let oversized_length_prefix = u64::MAX.to_le_bytes();
    assert!(bincode::deserialize::<CombinedPublicKey>(&oversized_length_prefix).is_err());
    assert!(bincode::deserialize::<CombinedSecretKey>(&oversized_length_prefix).is_err());
}
