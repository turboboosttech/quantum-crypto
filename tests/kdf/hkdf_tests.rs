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
use quantum_crypto::kdf::hkdf::derive_subkey_hkdf;

#[test]
fn test_hkdf_basic_derivation() {
    let ikm = b"super_secret_master_key_123456";
    let salt = b"some_random_salt";
    let info = b"encryption_key";
    let output_length = 32;

    let derived = derive_subkey_hkdf(ikm, Some(salt), info, output_length).unwrap();
    assert_eq!(derived.len(), output_length);

    let derived2 = derive_subkey_hkdf(ikm, Some(salt), info, output_length).unwrap();
    assert_eq!(*derived, *derived2);
}

#[test]
fn test_hkdf_different_info() {
    let ikm = b"super_secret_master_key_123456";
    let salt = b"some_random_salt";

    let key_enc = derive_subkey_hkdf(ikm, Some(salt), b"encryption", 32).unwrap();
    let key_mac = derive_subkey_hkdf(ikm, Some(salt), b"mac", 32).unwrap();

    assert_ne!(*key_enc, *key_mac);
}

#[test]
fn test_hkdf_without_salt() {
    let ikm = b"super_secret_master_key_123456";

    let key1 = derive_subkey_hkdf(ikm, None, b"encryption", 32).unwrap();
    let key2 = derive_subkey_hkdf(ikm, None, b"encryption", 32).unwrap();

    assert_eq!(*key1, *key2);

    let key_with_salt = derive_subkey_hkdf(ikm, Some(b"salt"), b"encryption", 32).unwrap();
    assert_ne!(*key1, *key_with_salt);
}

#[test]
fn test_hkdf_invalid_length() {
    let ikm = b"super_secret_master_key";

    let result = derive_subkey_hkdf(ikm, None, b"info", 0);
    assert!(result.is_err());

    let result_too_large = derive_subkey_hkdf(ikm, None, b"info", 8161);
    assert!(result_too_large.is_err());
}

#[test]
fn test_hkdf_isolation() {
    let ikm = b"super_secret_master_key_123456";
    let salt = b"some_random_salt";

    let key_enc = derive_subkey_hkdf(ikm, Some(salt), b"encryption", 32).unwrap();
    let key_mac = derive_subkey_hkdf(ikm, Some(salt), b"mac", 32).unwrap();
    let key_pin = derive_subkey_hkdf(ikm, Some(salt), b"pin-wrap", 32).unwrap();

    assert_ne!(*key_enc, *key_mac);
    assert_ne!(*key_enc, *key_pin);
    assert_ne!(*key_mac, *key_pin);
}
