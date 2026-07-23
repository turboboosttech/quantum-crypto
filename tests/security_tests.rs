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
use pqcrypto_traits::{kem::SecretKey as KemSecretKey, sign::SecretKey as SignSecretKey};
use quantum_crypto::{
    DilithiumSecretKey, EncryptionError, decrypt_data, generate_keypair, generate_xchacha_nonce,
    verify_hmac,
};

#[test]
fn test_error_indistinguishability() {
    let key = [1; 32];
    let nonce = generate_xchacha_nonce().unwrap();
    assert!(matches!(
        decrypt_data(&key, &nonce, &[0; 10], None),
        Err(EncryptionError::InvalidCiphertext)
    ));
    assert!(matches!(
        decrypt_data(&key, &nonce, &[0; 40], None),
        Err(EncryptionError::InvalidCiphertext)
    ));
    assert!(matches!(
        verify_hmac(&key, b"data", &[0; 32]),
        Err(EncryptionError::InvalidCiphertext)
    ));
}
#[test]
fn test_entropy_output_sanity() {
    let a = generate_xchacha_nonce().unwrap();
    let b = generate_xchacha_nonce().unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert!(a.as_bytes().iter().any(|v| *v != 0));
}
#[test]
fn test_combined_secret_key_debug_redacts_key_material() {
    let (_, secret) = generate_keypair(true).unwrap();
    let kem = format!("{:?}", secret.ml_kem().unwrap().as_bytes());
    let dsa = match secret.ml_dsa().unwrap().unwrap() {
        DilithiumSecretKey::V2(k) => format!("{:?}", k.as_bytes()),
        DilithiumSecretKey::V3(k) => format!("{:?}", k.as_bytes()),
        DilithiumSecretKey::V5(k) => format!("{:?}", k.as_bytes()),
    };
    let debug = format!("{:?}", secret);
    assert!(debug.contains("<redacted"));
    assert!(!debug.contains(&kem));
    assert!(!debug.contains(&dsa));
}
