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
use proptest::prelude::*;
use quantum_crypto::{
    EncryptionError, MAX_MESSAGE_SIZE, XCHACHA20_KEY_LENGTH, decrypt_data, encrypt_data,
    generate_xchacha_nonce,
};

#[test]
fn test_xchacha_encryption_decryption_roundtrip() {
    let key = [0u8; XCHACHA20_KEY_LENGTH];
    let nonce = generate_xchacha_nonce().unwrap();
    let plaintext = b"Hello, this is a secret message that needs to be encrypted!";

    let ciphertext = encrypt_data(&key, &nonce, plaintext, None).expect("Encryption failed");

    assert_ne!(ciphertext, plaintext);

    let decrypted = decrypt_data(&key, &nonce, &ciphertext, None).expect("Decryption failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_xchacha_associated_data() {
    let key = [1u8; XCHACHA20_KEY_LENGTH];
    let nonce = generate_xchacha_nonce().unwrap();
    let plaintext = b"Another secret message";
    let aad = b"Context data for authentication";

    let ciphertext = encrypt_data(&key, &nonce, plaintext, Some(aad)).expect("Encryption failed");

    let decrypted = decrypt_data(&key, &nonce, &ciphertext, Some(aad)).expect("Decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext);

    let wrong_aad = b"Wrong context data";
    let result = decrypt_data(&key, &nonce, &ciphertext, Some(wrong_aad));
    assert!(matches!(result, Err(EncryptionError::InvalidCiphertext)));

    let result_no_aad = decrypt_data(&key, &nonce, &ciphertext, None);
    assert!(result_no_aad.is_err());
}

#[test]
fn test_xchacha_rejects_plaintext_header_tampering_via_aad() {
    let key = [2u8; XCHACHA20_KEY_LENGTH];
    let nonce = generate_xchacha_nonce().unwrap();
    let plaintext = b"encrypted body";
    let header = b"format=generic;version=1;salt=1234567890123456;";

    let ciphertext = encrypt_data(&key, &nonce, plaintext, Some(header)).unwrap();
    assert_eq!(
        decrypt_data(&key, &nonce, &ciphertext, Some(header))
            .unwrap()
            .as_slice(),
        plaintext
    );

    let mut tampered_header = header.to_vec();
    tampered_header[15] = b'2';
    assert!(matches!(
        decrypt_data(&key, &nonce, &ciphertext, Some(&tampered_header)),
        Err(EncryptionError::InvalidCiphertext)
    ));
}

#[test]
fn test_xchacha_empty_payload() {
    let key = [0u8; XCHACHA20_KEY_LENGTH];
    let nonce = generate_xchacha_nonce().unwrap();
    let plaintext = b"";

    let ciphertext =
        encrypt_data(&key, &nonce, plaintext, None).expect("Encryption failed on empty payload");

    assert!(!ciphertext.is_empty());

    let decrypted =
        decrypt_data(&key, &nonce, &ciphertext, None).expect("Decryption failed on empty payload");

    assert_eq!(decrypted.as_slice(), plaintext);
    assert!(decrypted.is_empty());
}

#[test]
fn test_xchacha_rejects_plaintext_over_single_message_limit() {
    let key = [0u8; XCHACHA20_KEY_LENGTH];
    let nonce = generate_xchacha_nonce().unwrap();
    let plaintext = vec![0u8; MAX_MESSAGE_SIZE + 1];

    let result = encrypt_data(&key, &nonce, &plaintext, None);

    assert!(matches!(
        result,
        Err(EncryptionError::MessageTooLarge {
            size,
            max: MAX_MESSAGE_SIZE
        }) if size == MAX_MESSAGE_SIZE + 1
    ));
}

proptest! {
    #[test]
    fn prop_xchacha_roundtrip(
        key_bytes in any::<[u8; XCHACHA20_KEY_LENGTH]>(),
        plaintext in any::<Vec<u8>>()
    ) {
        let nonce = generate_xchacha_nonce().unwrap();
        let ciphertext = encrypt_data(&key_bytes, &nonce, &plaintext, None)
            .expect("Encryption failed");

        let decrypted = decrypt_data(&key_bytes, &nonce, &ciphertext, None)
            .expect("Decryption failed");

        prop_assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn prop_xchacha_nonce_uniqueness(
        key_bytes in any::<[u8; XCHACHA20_KEY_LENGTH]>(),
        plaintext in any::<Vec<u8>>()
    ) {
        let nonce1 = generate_xchacha_nonce().unwrap();
        let nonce2 = generate_xchacha_nonce().unwrap();

        prop_assume!(nonce1.as_bytes() != nonce2.as_bytes());

        let ciphertext1 = encrypt_data(&key_bytes, &nonce1, &plaintext, None)
            .expect("Encryption failed");

        let ciphertext2 = encrypt_data(&key_bytes, &nonce2, &plaintext, None)
            .expect("Encryption failed");

        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn prop_xchacha_malleability(
        key_bytes in any::<[u8; XCHACHA20_KEY_LENGTH]>(),
        plaintext in any::<Vec<u8>>(),
        flip_index in any::<usize>()
    ) {
        let nonce = generate_xchacha_nonce().unwrap();
        let mut ciphertext = encrypt_data(&key_bytes, &nonce, &plaintext, None)
            .expect("Encryption failed");

        prop_assume!(!ciphertext.is_empty());

        let idx = flip_index % ciphertext.len();
        ciphertext[idx] ^= 1;

        let result = decrypt_data(&key_bytes, &nonce, &ciphertext, None);
        prop_assert!(result.is_err(), "Decryption succeeded on tampered ciphertext");
    }
}
