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
use quantum_crypto::{DilithiumVersion, generate_keypair, generate_keypair_with_mldsa};

mod asymmetric;
mod generator;
mod kdf;
mod streaming;
mod symmetric;

use pqcrypto_traits::kem::{PublicKey, SecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait};

#[test]
fn test_key_serialization_roundtrip() {
    let (pk, sk) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();

    let ml_kem_pk = pk.ml_kem().unwrap();
    let ml_kem_pk_bytes = PublicKey::as_bytes(&ml_kem_pk);
    let ml_kem_pk_restored =
        pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(ml_kem_pk_bytes).unwrap();
    assert_eq!(
        PublicKey::as_bytes(&ml_kem_pk),
        PublicKey::as_bytes(&ml_kem_pk_restored)
    );

    let ml_kem_sk = sk.ml_kem().unwrap();
    let ml_kem_sk_bytes = SecretKey::as_bytes(&ml_kem_sk);
    let ml_kem_sk_restored =
        pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(ml_kem_sk_bytes).unwrap();
    assert_eq!(
        SecretKey::as_bytes(&ml_kem_sk),
        SecretKey::as_bytes(&ml_kem_sk_restored)
    );

    if let Some(ml_dsa_pk) = pk.ml_dsa().unwrap() {
        let ml_dsa_pk_bytes = SignPublicKeyTrait::as_bytes(&ml_dsa_pk);
        let ml_dsa_pk_restored =
            pqcrypto_mldsa::mldsa44::PublicKey::from_bytes(ml_dsa_pk_bytes).unwrap();
        assert_eq!(
            SignPublicKeyTrait::as_bytes(&ml_dsa_pk),
            SignPublicKeyTrait::as_bytes(&ml_dsa_pk_restored)
        );
    }

    if let Some(ml_dsa_sk) = sk.ml_dsa().unwrap() {
        let ml_dsa_sk_bytes = SignSecretKeyTrait::as_bytes(&ml_dsa_sk);
        let ml_dsa_sk_restored =
            pqcrypto_mldsa::mldsa44::SecretKey::from_bytes(ml_dsa_sk_bytes).unwrap();
        assert_eq!(
            SignSecretKeyTrait::as_bytes(&ml_dsa_sk),
            SignSecretKeyTrait::as_bytes(&ml_dsa_sk_restored)
        );
    }
}

#[test]
fn test_keypair_generation_encryption_only() {
    let (pk, sk) = generate_keypair(false).unwrap();
    assert!(pk.ml_dsa().unwrap().is_none());
    assert!(sk.ml_dsa().unwrap().is_none());
    assert!(pk.ml_kem().is_ok());
    assert!(sk.ml_kem().is_ok());
}

#[test]
fn test_keypair_generation_with_signing() {
    let (pk, sk) = generate_keypair(true).unwrap();
    assert!(pk.ml_dsa().unwrap().is_some());
    assert!(sk.ml_dsa().unwrap().is_some());
    assert!(pk.ml_kem().is_ok());
    assert!(sk.ml_kem().is_ok());
}

#[test]
fn test_flow6_secure_send_simulation() {
    use quantum_crypto::{
        Argon2idPreset, decrypt_data, derive_key_argon2id, encrypt_data, generate_xchacha_nonce,
    };

    let pin = b"123456";

    let send_key_result = derive_key_argon2id(pin, None, Argon2idPreset::Low, 32).unwrap();
    let send_key = send_key_result.key;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&send_key[0..32]);

    let item_payload = b"super secret credential";
    let nonce = generate_xchacha_nonce().unwrap();

    let ciphertext = encrypt_data(&key_bytes, &nonce, item_payload, None).unwrap();

    use quantum_crypto::reconstruct_key_argon2id;
    let recipient_key = reconstruct_key_argon2id(
        pin,
        None,
        &send_key_result.salt,
        &send_key_result.params,
        32,
    )
    .unwrap();

    let mut rec_key_bytes = [0u8; 32];
    rec_key_bytes.copy_from_slice(&recipient_key[0..32]);

    let decrypted = decrypt_data(&rec_key_bytes, &nonce, &ciphertext, None).unwrap();

    assert_eq!(item_payload.as_slice(), decrypted.as_slice());

    let wrong_pin = b"654321";
    let wrong_key = reconstruct_key_argon2id(
        wrong_pin,
        None,
        &send_key_result.salt,
        &send_key_result.params,
        32,
    )
    .unwrap();

    let mut wrong_key_bytes = [0u8; 32];
    wrong_key_bytes.copy_from_slice(&wrong_key[0..32]);

    let decrypt_fail = decrypt_data(&wrong_key_bytes, &nonce, &ciphertext, None);
    assert!(decrypt_fail.is_err());
}

#[test]
fn test_flow5_sync_handshake_simulation() {
    use quantum_crypto::asymmetric::ml_dsa::{
        SIGN_CONTEXT_SYNC_CHALLENGE, sign_message_enhanced, verify_signature_enhanced,
    };
    use quantum_crypto::{
        DilithiumVersion, decapsulate_key, decrypt_data, encapsulate_key, encrypt_data,
        generate_keypair_with_mldsa, generate_xchacha_nonce,
    };

    let (pk_a, sk_a) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();
    let (pk_b, sk_b) = generate_keypair_with_mldsa(Some(DilithiumVersion::V2)).unwrap();

    let device_a_id = b"device-a";
    let device_b_id = b"device-b";
    let nonce_a = b"random_nonce_from_a";
    let nonce_b = b"random_nonce_from_b";

    let encap_result = encapsulate_key(&pk_b).unwrap();
    let shared_secret_a = encap_result.shared_secret();
    let ciphertext = encap_result.ciphertext();

    let build_flow5_transcript =
        |sender_id: &[u8], receiver_id: &[u8], ml_kem_ciphertext: &[u8]| {
            let ciphertext_hash = blake3::hash(ml_kem_ciphertext);
            let mut transcript = Vec::new();
            transcript.extend_from_slice(b"QC-FLOW5-SYNC-v1");
            transcript.extend_from_slice(&(nonce_a.len() as u64).to_le_bytes());
            transcript.extend_from_slice(nonce_a);
            transcript.extend_from_slice(&(nonce_b.len() as u64).to_le_bytes());
            transcript.extend_from_slice(nonce_b);
            transcript.extend_from_slice(&(sender_id.len() as u64).to_le_bytes());
            transcript.extend_from_slice(sender_id);
            transcript.extend_from_slice(&(receiver_id.len() as u64).to_le_bytes());
            transcript.extend_from_slice(receiver_id);
            transcript.extend_from_slice(ciphertext_hash.as_bytes());
            transcript
        };

    let transcript_a_to_b = build_flow5_transcript(device_a_id, device_b_id, ciphertext);
    let sig_a =
        sign_message_enhanced(&sk_a, &transcript_a_to_b, SIGN_CONTEXT_SYNC_CHALLENGE).unwrap();
    assert!(
        verify_signature_enhanced(
            &pk_a,
            &transcript_a_to_b,
            &sig_a,
            SIGN_CONTEXT_SYNC_CHALLENGE
        )
        .is_ok()
    );

    let transcript_b_to_a = build_flow5_transcript(device_b_id, device_a_id, ciphertext);
    let sig_b =
        sign_message_enhanced(&sk_b, &transcript_b_to_a, SIGN_CONTEXT_SYNC_CHALLENGE).unwrap();
    assert!(
        verify_signature_enhanced(
            &pk_b,
            &transcript_b_to_a,
            &sig_b,
            SIGN_CONTEXT_SYNC_CHALLENGE
        )
        .is_ok()
    );

    let shared_secret_b = decapsulate_key(&sk_b, ciphertext).unwrap();

    assert_eq!(shared_secret_a, shared_secret_b.as_slice());

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(shared_secret_a);

    let state_payload = b"encrypted_vault_state_sync_data";
    let nonce = generate_xchacha_nonce().unwrap();

    let encrypted_state = encrypt_data(&session_key, &nonce, state_payload, None).unwrap();

    let decrypted_state = decrypt_data(&session_key, &nonce, &encrypted_state, None).unwrap();

    assert_eq!(state_payload.as_slice(), decrypted_state.as_slice());

    let bad_decryption = decrypt_data(
        &session_key,
        &nonce,
        &encrypted_state[..encrypted_state.len() - 1], // Corrupted ciphertext
        None,
    );
    assert!(bad_decryption.is_err());
}

#[test]
fn test_flow3_partial_vault_update_simulation() {
    use quantum_crypto::{
        Argon2idPreset, decrypt_data, derive_key_argon2id, encrypt_data, generate_xchacha_nonce,
        symmetric::hmac::{compute_hmac, verify_hmac},
    };

    let master_key = derive_key_argon2id(b"password", None, Argon2idPreset::Low, 32)
        .unwrap()
        .key;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&master_key[0..32]);

    let mac_key = b"simulated_mac_key_32_bytes_long!";

    let item1_plaintext = b"Item 1 Data";
    let item2_plaintext = b"Item 2 Data";

    let nonce1 = generate_xchacha_nonce().unwrap();
    let nonce2 = generate_xchacha_nonce().unwrap();

    let item1_ciphertext = encrypt_data(&key_bytes, &nonce1, item1_plaintext, None).unwrap();
    let item2_ciphertext = encrypt_data(&key_bytes, &nonce2, item2_plaintext, None).unwrap();

    let mut vault_buffer = Vec::new();
    vault_buffer.extend_from_slice(b"metadata_v1");
    vault_buffer.extend_from_slice(&item1_ciphertext);
    vault_buffer.extend_from_slice(&item2_ciphertext);

    let initial_mac = compute_hmac(mac_key, &vault_buffer).unwrap();

    let item2_new_plaintext = b"Item 2 UPDATED Data";
    let nonce2_new = generate_xchacha_nonce().unwrap();
    let item2_new_ciphertext =
        encrypt_data(&key_bytes, &nonce2_new, item2_new_plaintext, None).unwrap();

    let mut new_vault_buffer = Vec::new();
    new_vault_buffer.extend_from_slice(b"metadata_v2");
    new_vault_buffer.extend_from_slice(&item1_ciphertext); // Kept identical!
    new_vault_buffer.extend_from_slice(&item2_new_ciphertext);

    let new_mac = compute_hmac(mac_key, &new_vault_buffer).unwrap();

    assert!(verify_hmac(mac_key, &new_vault_buffer, &new_mac).is_ok());

    let decrypted_item1 = decrypt_data(&key_bytes, &nonce1, &item1_ciphertext, None).unwrap();
    assert_eq!(decrypted_item1.as_slice(), item1_plaintext);

    let decrypted_item2 =
        decrypt_data(&key_bytes, &nonce2_new, &item2_new_ciphertext, None).unwrap();
    assert_eq!(decrypted_item2.as_slice(), item2_new_plaintext);

    assert!(verify_hmac(mac_key, &new_vault_buffer, &initial_mac).is_err());
}
