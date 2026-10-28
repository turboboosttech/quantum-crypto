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
use quantum_crypto::{
    P256_MAX_MESSAGE_SIZE, P256_PUBLIC_KEY_LENGTH, P256Error, P256KeyPair, generate_p256_keypair,
    p256_public_key_from_pkcs8, sign_es256_der, verify_es256_der,
};

#[test]
fn test_p256_key_generation_and_derivation() {
    let key_pair = generate_p256_keypair().unwrap();
    let derived = p256_public_key_from_pkcs8(key_pair.private_key_pkcs8_der()).unwrap();

    assert_eq!(key_pair.public_key_sec1().len(), P256_PUBLIC_KEY_LENGTH);
    assert_eq!(key_pair.public_key_sec1()[0], 0x04);
    assert_eq!(derived, *key_pair.public_key_sec1());
    assert!(!key_pair.private_key_pkcs8_der().is_empty());
}

#[test]
fn test_es256_roundtrip_and_tampering() {
    let key_pair = generate_p256_keypair().unwrap();
    let message = b"webauthn authenticator data and client data hash";
    let signature = sign_es256_der(key_pair.private_key_pkcs8_der(), message).unwrap();

    assert_eq!(signature[0], 0x30);
    assert!(verify_es256_der(key_pair.public_key_sec1(), message, &signature).is_ok());
    assert!(verify_es256_der(key_pair.public_key_sec1(), b"tampered", &signature).is_err());

    let mut tampered_signature = signature;
    let last = tampered_signature.len() - 1;
    tampered_signature[last] ^= 1;
    assert!(verify_es256_der(key_pair.public_key_sec1(), message, &tampered_signature).is_err());
}

#[test]
fn test_p256_rejects_malformed_and_trailing_encodings() {
    let key_pair = generate_p256_keypair().unwrap();
    let message = b"message";
    let signature = sign_es256_der(key_pair.private_key_pkcs8_der(), message).unwrap();

    let mut trailing_private_key = key_pair.private_key_pkcs8_der().to_vec();
    trailing_private_key.push(0);
    assert_eq!(
        p256_public_key_from_pkcs8(&trailing_private_key),
        Err(P256Error::InvalidPrivateKey)
    );
    assert_eq!(
        sign_es256_der(&trailing_private_key, message),
        Err(P256Error::InvalidPrivateKey)
    );

    assert_eq!(
        verify_es256_der(&[0x04; P256_PUBLIC_KEY_LENGTH], message, &signature),
        Err(P256Error::InvalidPublicKey)
    );
    assert_eq!(
        verify_es256_der(&key_pair.public_key_sec1()[..64], message, &signature),
        Err(P256Error::InvalidPublicKey)
    );

    let mut trailing_signature = signature.clone();
    trailing_signature.push(0);
    assert_eq!(
        verify_es256_der(key_pair.public_key_sec1(), message, &trailing_signature),
        Err(P256Error::InvalidSignature)
    );
    assert_eq!(
        verify_es256_der(key_pair.public_key_sec1(), message, &[0x30, 0x00]),
        Err(P256Error::InvalidSignature)
    );
}

#[test]
fn test_es256_rfc6979_sha256_vector() {
    let private_key = decode_hex(concat!(
        "3041020100301306072a8648ce3d020106082a8648ce3d0301070427",
        "30250201010420",
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    ));
    let signature = decode_hex(concat!(
        "3046022100",
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "022100",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ));
    let public_key = p256_public_key_from_pkcs8(&private_key).unwrap();

    assert_eq!(sign_es256_der(&private_key, b"sample").unwrap(), signature);
    assert!(verify_es256_der(&public_key, b"sample", &signature).is_ok());
    assert!(verify_es256_der(&public_key, b"test", &signature).is_err());
}

#[test]
fn test_p256_message_bound() {
    let key_pair = generate_p256_keypair().unwrap();
    let message = vec![0; P256_MAX_MESSAGE_SIZE + 1];

    assert!(matches!(
        sign_es256_der(key_pair.private_key_pkcs8_der(), &message),
        Err(P256Error::MessageTooLong { .. })
    ));
    assert!(matches!(
        verify_es256_der(key_pair.public_key_sec1(), &message, &[]),
        Err(P256Error::MessageTooLong { .. })
    ));
}

#[test]
fn test_p256_debug_redacts_private_key() {
    let key_pair = generate_p256_keypair().unwrap();
    let private_key = format!("{:?}", key_pair.private_key_pkcs8_der());
    let debug = format!("{key_pair:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&private_key));
}

#[test]
fn test_p256_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<P256KeyPair>();
    assert_send_sync::<P256Error>();
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
