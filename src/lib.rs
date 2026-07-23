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
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]


use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand_core::OsRng;

pub mod asymmetric;
pub mod errors;
pub mod generator;
pub mod kdf;
pub mod serialization;
pub mod streaming;
pub mod symmetric;
pub mod types;

#[allow(deprecated)]
pub use crate::{
    asymmetric::{
        keys::{generate_keypair, generate_keypair_with_dilithium, generate_keypair_with_mldsa},
        ml_dsa::{
            DILITHIUM2_PUBLIC_KEY_LENGTH, DILITHIUM2_SECRET_KEY_LENGTH,
            DILITHIUM2_SIGNATURE_LENGTH, DILITHIUM3_PUBLIC_KEY_LENGTH,
            DILITHIUM3_SECRET_KEY_LENGTH, DILITHIUM3_SIGNATURE_LENGTH,
            DILITHIUM5_PUBLIC_KEY_LENGTH, DILITHIUM5_SECRET_KEY_LENGTH,
            DILITHIUM5_SIGNATURE_LENGTH, MAX_SIGNABLE_SIZE, MLDSA44_PUBLIC_KEY_LENGTH,
            MLDSA44_SECRET_KEY_LENGTH, MLDSA44_SIGNATURE_LENGTH, MLDSA65_PUBLIC_KEY_LENGTH,
            MLDSA65_SECRET_KEY_LENGTH, MLDSA65_SIGNATURE_LENGTH, MLDSA87_PUBLIC_KEY_LENGTH,
            MLDSA87_SECRET_KEY_LENGTH, MLDSA87_SIGNATURE_LENGTH, SIGN_CONTEXT_PAIRING,
            SIGN_CONTEXT_SYNC_CHALLENGE, sign_message_enhanced, verify_signature_enhanced,
        },
        ml_kem::{
            KYBER1024_CIPHERTEXT_LENGTH, KYBER1024_PUBLIC_KEY_LENGTH, KYBER1024_SECRET_KEY_LENGTH,
            KYBER1024_SHARED_SECRET_LENGTH, MLKEM1024_CIPHERTEXT_LENGTH,
            MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM1024_SECRET_KEY_LENGTH,
            MLKEM1024_SHARED_SECRET_LENGTH, decapsulate_key, encapsulate_key,
        },
    },
    errors::{EncryptionError, GeneratorError, KeyError, StreamingError},
    kdf::{
        argon2id::{
            ARGON2ID_SALT_LENGTH, argon2id_params_for_preset, argon2id_preset_info,
            derive_key_argon2id, reconstruct_key_argon2id,
        },
        hkdf::derive_subkey_hkdf,
    },
    symmetric::{
        hmac::{HMAC_SHA256_TAG_LENGTH, MIN_HMAC_KEY_LENGTH, compute_hmac, verify_hmac},
        root_keys::{
            decapsulate_root_key, derive_root_key_argon2id, generate_root_key_ml_kem,
            reconstruct_root_key_argon2id,
        },
        xchacha::{
            MAX_MESSAGE_SIZE, XCHACHA20_KEY_LENGTH, XCHACHA20_NONCE_LENGTH, XCHACHA20_TAG_LENGTH,
            XChaChaNonce, decrypt_data, encrypt_data, generate_xchacha_nonce,
        },
    },
    types::{
        Argon2idKeyResult, Argon2idParams, Argon2idPreset, Argon2idPresetInfo, CombinedPublicKey,
        CombinedSecretKey, DilithiumPublicKey, DilithiumSecretKey, DilithiumVersion, RootKeyResult,
        RootKeySource,
    },
};

pub use streaming::{
    DEFAULT_CHUNK_SIZE, DecryptStreamConfig, EncryptStreamConfig, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    StreamContext, StreamSummary, decrypt_stream, encrypt_stream,
};

pub use generator::{
    DICEWARE_BITS_PER_WORD, DICEWARE_DEFAULT_SEPARATOR, DICEWARE_DEFAULT_WORD_COUNT,
    DICEWARE_MAX_WORD_COUNT, DICEWARE_MIN_WORD_COUNT, DICEWARE_MIN_WORD_EDIT_DISTANCE,
    DICEWARE_WORDLIST_SIZE, DicewarePassphrase, PASSWORD_DEFAULT_LENGTH,
    RANDOM_PASSWORD_MAX_LENGTH, RANDOM_PASSWORD_MIN_LENGTH, STRUCTURED_PASSWORD_DEFAULT_DIVIDER,
    STRUCTURED_PASSWORD_DEFAULT_SEGMENTS, STRUCTURED_PASSWORD_MAX_SEGMENTS,
    STRUCTURED_PASSWORD_MIN_SEGMENTS, generate_default_diceware, generate_diceware,
    generate_random_password, generate_structured_password,
};

pub fn security_post() -> Result<(), &'static str> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let test_nonce = XChaChaNonce::generate().map_err(|_| "Nonce generation POST failed")?;
    let test_plaintext = b"POST_TEST";
    let test_aad = b"POST_TEST_AAD";

    let ciphertext = encrypt_data(&key, &test_nonce, test_plaintext, Some(test_aad))
        .map_err(|_| "XChaCha20 encryption POST failed")?;

    if ciphertext.len() < XCHACHA20_TAG_LENGTH {
        return Err("XChaCha20 POST ciphertext too short");
    }

    let decrypted = decrypt_data(&key, &test_nonce, &ciphertext, Some(test_aad))
        .map_err(|_| "XChaCha20 decryption POST failed")?;

    if decrypted.as_slice() != test_plaintext {
        return Err("XChaCha20 POST plaintext mismatch");
    }

    let (pk, sk) = generate_keypair(false).map_err(|_| "Kyber keypair generation POST failed")?;

    let encap_result = encapsulate_key(&pk).map_err(|_| "Kyber encapsulation POST failed")?;

    if encap_result.ciphertext().len() != MLKEM1024_CIPHERTEXT_LENGTH {
        return Err("Kyber POST invalid ciphertext length");
    }

    let decap_secret = decapsulate_key(&sk, encap_result.ciphertext())
        .map_err(|_| "Kyber decapsulation POST failed")?;

    if decap_secret.len() != MLKEM1024_SHARED_SECRET_LENGTH {
        return Err("Kyber POST invalid shared secret length");
    }

    use subtle::ConstantTimeEq;
    if !bool::from(encap_result.shared_secret().ct_eq(&decap_secret)) {
        return Err("Shared secrets do not match");
    }

    Ok(())
}
