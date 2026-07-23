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
use pqcrypto_mlkem::mlkem1024::keypair as ml_kem_keypair;
use pqcrypto_traits::kem::{PublicKey, SecretKey};
use proptest::prelude::*;
use quantum_crypto::{
    CombinedPublicKey, CombinedSecretKey, MLKEM1024_CIPHERTEXT_LENGTH,
    MLKEM1024_SHARED_SECRET_LENGTH, RootKeySource, decapsulate_key, decapsulate_root_key,
    encapsulate_key, generate_keypair, generate_root_key_ml_kem,
};
use subtle::ConstantTimeEq;

#[test]
fn test_ml_kem_encapsulation() {
    let (pk, sk) = generate_keypair(false).expect("Failed to generate keypair");

    let encap_result = encapsulate_key(&pk).expect("Failed to encapsulate key");

    assert_eq!(
        encap_result.ciphertext().len(),
        MLKEM1024_CIPHERTEXT_LENGTH,
        "Invalid ciphertext length"
    );

    assert_eq!(
        encap_result.shared_secret().len(),
        MLKEM1024_SHARED_SECRET_LENGTH,
        "Invalid shared secret length"
    );

    let decap_secret =
        decapsulate_key(&sk, encap_result.ciphertext()).expect("Failed to decapsulate key");

    assert_eq!(
        decap_secret.len(),
        MLKEM1024_SHARED_SECRET_LENGTH,
        "Invalid decapsulated secret length"
    );

    assert!(
        bool::from(encap_result.shared_secret().ct_eq(&decap_secret)),
        "Shared secrets do not match"
    );
}

#[test]
fn test_ml_kem_root_key_round_trip() {
    let (public, secret) = generate_keypair(false).unwrap();
    let generated = generate_root_key_ml_kem(&public).unwrap();

    assert!(matches!(
        generated.source(),
        RootKeySource::MlKem { ciphertext }
            if ciphertext.len() == MLKEM1024_CIPHERTEXT_LENGTH
    ));

    let recovered = decapsulate_root_key(&secret, generated.source()).unwrap();
    assert!(bool::from(generated.key().ct_eq(recovered.as_slice())));
}

#[test]
fn test_modified_ciphertext_produces_unconfirmed_candidate_secret() {
    let (pk, sk) = generate_keypair(false).expect("Failed to generate keypair");
    let encap_result = encapsulate_key(&pk).expect("Failed to encapsulate key");
    let mut modified = encap_result.ciphertext().to_vec();
    modified[0] ^= 1;

    let candidate = decapsulate_key(&sk, &modified).expect("Implicit rejection must return a key");
    assert!(!bool::from(
        encap_result.shared_secret().ct_eq(candidate.as_slice())
    ));
}

#[test]
fn test_invalid_key_length() {
    let invalid_bytes = vec![0u8; 100]; // Wrong length
    let ml_kem_pk_result = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(&invalid_bytes);
    assert!(
        ml_kem_pk_result.is_err(),
        "Expected error for invalid public key length"
    );

    let ml_kem_sk_result = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(&invalid_bytes);
    assert!(
        ml_kem_sk_result.is_err(),
        "Expected error for invalid secret key length"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn generated_ml_kem_keypairs_construct_successfully(_case in any::<u64>()) {
        let (ml_kem_pk, ml_kem_sk) = ml_kem_keypair();

        prop_assert!(CombinedPublicKey::new(ml_kem_pk, None).is_ok());
        prop_assert!(CombinedSecretKey::new(ml_kem_sk, None).is_ok());
    }
}
