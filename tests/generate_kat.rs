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
use quantum_crypto::kdf::argon2id::derive_key_argon2id;
use quantum_crypto::kdf::hkdf::derive_subkey_hkdf;
use quantum_crypto::symmetric::hmac::compute_hmac;
use quantum_crypto::symmetric::xchacha::{encrypt_data, generate_xchacha_nonce};
use quantum_crypto::types::Argon2idPreset;

#[test]
fn generate_kat_data() {
    let password = b"my_secure_password";
    let secret_key = b"my_secret_key_16"; // 16 bytes

    let derived = derive_key_argon2id(password, Some(secret_key), Argon2idPreset::Low, 64).unwrap();
    let master_key = derived.key.as_slice();

    let enc_key = derive_subkey_hkdf(master_key, None, b"encryption", 32).unwrap();
    let mac_key = derive_subkey_hkdf(master_key, None, b"mac", 32).unwrap();

    let metadata_plaintext = b"metadata: vault_name=test_vault, items=1";
    let metadata_nonce = generate_xchacha_nonce().unwrap();
    let metadata_ciphertext = encrypt_data(
        enc_key.as_slice(),
        &metadata_nonce,
        metadata_plaintext,
        None,
    )
    .unwrap();

    let item_plaintext = b"item: secret_password_for_github";
    let item_nonce = generate_xchacha_nonce().unwrap();
    let item_ciphertext =
        encrypt_data(enc_key.as_slice(), &item_nonce, item_plaintext, None).unwrap();

    let mut vault_payload = Vec::new();
    vault_payload.extend_from_slice(&derived.salt);
    vault_payload.extend_from_slice(&derived.params);
    vault_payload.extend_from_slice(metadata_nonce.as_bytes());
    vault_payload.extend_from_slice(&(metadata_ciphertext.len() as u32).to_le_bytes());
    vault_payload.extend_from_slice(&metadata_ciphertext);
    vault_payload.extend_from_slice(item_nonce.as_bytes());
    vault_payload.extend_from_slice(&(item_ciphertext.len() as u32).to_le_bytes());
    vault_payload.extend_from_slice(&item_ciphertext);

    let hmac_tag = compute_hmac(mac_key.as_slice(), &vault_payload).unwrap();

    println!("// GENERATED KAT DATA:");
    println!("const SALT: &[u8] = &{:?};", derived.salt);
    println!("const PARAMS: &[u8] = &{:?};", derived.params);
    println!("const EXPECTED_MASTER_KEY: &[u8] = &{:?};", master_key);
    println!("const EXPECTED_ENC_KEY: &[u8] = &{:?};", enc_key.as_slice());
    println!("const EXPECTED_MAC_KEY: &[u8] = &{:?};", mac_key.as_slice());
    println!("const VAULT_PAYLOAD: &[u8] = &{:?};", vault_payload);
    println!("const HMAC_TAG: &[u8] = &{:?};", hmac_tag);
    println!(
        "const METADATA_NONCE: &[u8] = &{:?};",
        metadata_nonce.as_bytes()
    );
    println!(
        "const METADATA_CIPHERTEXT: &[u8] = &{:?};",
        metadata_ciphertext
    );
    println!("const ITEM_NONCE: &[u8] = &{:?};", item_nonce.as_bytes());
    println!("const ITEM_CIPHERTEXT: &[u8] = &{:?};", item_ciphertext);
}
