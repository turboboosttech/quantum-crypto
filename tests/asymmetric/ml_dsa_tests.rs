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
use pqcrypto_traits::sign::PublicKey;
use quantum_crypto::{
    DilithiumVersion, MAX_SIGNABLE_SIZE, MLDSA44_PUBLIC_KEY_LENGTH, MLDSA65_PUBLIC_KEY_LENGTH,
    MLDSA87_PUBLIC_KEY_LENGTH, SIGN_CONTEXT_PAIRING, SIGN_CONTEXT_SYNC_CHALLENGE,
    generate_keypair_with_mldsa, sign_message_enhanced, verify_signature_enhanced,
};

#[test]
fn test_ml_dsa_key_lengths() {
    let (pk2, _) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();
    if let Some(ml_dsa_pk) = pk2.ml_dsa().unwrap() {
        assert_eq!(ml_dsa_pk.as_bytes().len(), MLDSA44_PUBLIC_KEY_LENGTH);
    }

    let (pk3, _) = generate_keypair_with_mldsa(Some(DilithiumVersion::V3)).unwrap();
    if let Some(ml_dsa_pk) = pk3.ml_dsa().unwrap() {
        assert_eq!(ml_dsa_pk.as_bytes().len(), MLDSA65_PUBLIC_KEY_LENGTH);
    }

    let (pk5, _) = generate_keypair_with_mldsa(Some(DilithiumVersion::V5)).unwrap();
    if let Some(ml_dsa_pk) = pk5.ml_dsa().unwrap() {
        assert_eq!(ml_dsa_pk.as_bytes().len(), MLDSA87_PUBLIC_KEY_LENGTH);
    }
}

#[test]
fn test_enhanced_signature_rejects_oversized_messages_before_hashing() {
    let (public, secret) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();
    let message = vec![0; MAX_SIGNABLE_SIZE + 1];

    assert!(matches!(
        sign_message_enhanced(&secret, &message, SIGN_CONTEXT_PAIRING),
        Err(quantum_crypto::KeyError::MessageTooLong { .. })
    ));
    assert!(matches!(
        verify_signature_enhanced(&public, &message, &[], SIGN_CONTEXT_PAIRING),
        Err(quantum_crypto::KeyError::MessageTooLong { .. })
    ));
}

#[test]
fn test_enhanced_signature_context_separation() {
    let (pk, sk) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();
    let message = b"same protocol bytes";

    let signature = sign_message_enhanced(&sk, message, SIGN_CONTEXT_PAIRING).unwrap();

    assert!(verify_signature_enhanced(&pk, message, &signature, SIGN_CONTEXT_PAIRING).is_ok());
    assert!(
        verify_signature_enhanced(&pk, message, &signature, SIGN_CONTEXT_SYNC_CHALLENGE).is_err()
    );
}
