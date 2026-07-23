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
use quantum_crypto::symmetric::hmac::{
    HMAC_SHA256_TAG_LENGTH, MIN_HMAC_KEY_LENGTH, compute_hmac, verify_hmac,
};

const KEY: [u8; MIN_HMAC_KEY_LENGTH] = [7; MIN_HMAC_KEY_LENGTH];
const OTHER_KEY: [u8; MIN_HMAC_KEY_LENGTH] = [8; MIN_HMAC_KEY_LENGTH];

#[test]
fn test_hmac_compute_and_verify() {
    let data = b"vault_file_contents_to_authenticate";
    let tag = compute_hmac(&KEY, data).unwrap();

    assert_eq!(tag.len(), HMAC_SHA256_TAG_LENGTH);
    assert!(verify_hmac(&KEY, data, &tag).is_ok());
}

#[test]
fn test_hmac_verify_tampered_data() {
    let data = b"vault_file_contents_to_authenticate";
    let tag = compute_hmac(&KEY, data).unwrap();

    assert!(verify_hmac(&KEY, b"vault_file_contents_to_authenticate!", &tag).is_err());
}

#[test]
fn test_hmac_authenticates_caller_serialized_header_and_body() {
    let header = b"version=1;salt=1234567890123456;params=low;";
    let encrypted_body = b"ciphertext-and-aead-tag";
    let mut authenticated_bytes = Vec::new();
    authenticated_bytes.extend_from_slice(header);
    authenticated_bytes.extend_from_slice(encrypted_body);

    let tag = compute_hmac(&KEY, &authenticated_bytes).unwrap();
    assert!(verify_hmac(&KEY, &authenticated_bytes, &tag).is_ok());

    authenticated_bytes[0] ^= 1;
    assert!(verify_hmac(&KEY, &authenticated_bytes, &tag).is_err());
}

#[test]
fn test_hmac_verify_wrong_key() {
    let data = b"vault_file_contents_to_authenticate";
    let tag = compute_hmac(&KEY, data).unwrap();

    assert!(verify_hmac(&OTHER_KEY, data, &tag).is_err());
}

#[test]
fn test_hmac_invalid_tag_length() {
    let data = b"vault_file_contents";

    assert!(verify_hmac(&KEY, data, &[0; 31]).is_err());
    assert!(verify_hmac(&KEY, data, &[0; 33]).is_err());
}

#[test]
fn test_hmac_rejects_short_keys() {
    let short_key = [0; MIN_HMAC_KEY_LENGTH - 1];

    assert!(compute_hmac(&short_key, b"data").is_err());
    assert!(verify_hmac(&short_key, b"data", &[0; HMAC_SHA256_TAG_LENGTH]).is_err());
}
