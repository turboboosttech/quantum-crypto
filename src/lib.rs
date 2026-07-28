/*
 * Business Source License 1.1
 *
 * Licensor: TurboBoostTechnologies
 * Licensed Work: quantum-crypto 2026.s.3.0.1
 * Change Date: 2030-07-27
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
    errors::{
        Argon2idParamsError, EncryptionError, GeneratorError, KeyError, SecurityPostError,
        StreamingError,
    },
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
    security_post_detailed().map_err(|error| match error {
        SecurityPostError::NonceGeneration(_) => "Nonce generation POST failed",
        SecurityPostError::Encryption(_) => "XChaCha20 encryption POST failed",
        SecurityPostError::Decryption(_) => "XChaCha20 decryption POST failed",
        SecurityPostError::PlaintextMismatch => "XChaCha20 POST plaintext mismatch",
        SecurityPostError::KeyGeneration(_) => "Kyber keypair generation POST failed",
        SecurityPostError::Encapsulation(_) => "Kyber encapsulation POST failed",
        SecurityPostError::Decapsulation(_) => "Kyber decapsulation POST failed",
        SecurityPostError::CiphertextLength { .. } => "Kyber POST invalid ciphertext length",
        SecurityPostError::SharedSecretLength { .. } => "Kyber POST invalid shared secret length",
        SecurityPostError::SharedSecretMismatch => "Shared secrets do not match",
    })
}

pub fn security_post_detailed() -> Result<(), SecurityPostError> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce = XChaChaNonce::generate().map_err(SecurityPostError::NonceGeneration)?;
    let plaintext = b"POST_TEST";
    let aad = b"POST_TEST_AAD";
    let ciphertext =
        encrypt_data(&key, &nonce, plaintext, Some(aad)).map_err(SecurityPostError::Encryption)?;
    let decrypted = decrypt_data(&key, &nonce, &ciphertext, Some(aad))
        .map_err(SecurityPostError::Decryption)?;

    if decrypted.as_slice() != plaintext {
        return Err(SecurityPostError::PlaintextMismatch);
    }

    let (public_key, secret_key) =
        generate_keypair(false).map_err(SecurityPostError::KeyGeneration)?;
    let encapsulation = encapsulate_key(&public_key).map_err(SecurityPostError::Encapsulation)?;

    if encapsulation.ciphertext().len() != MLKEM1024_CIPHERTEXT_LENGTH {
        return Err(SecurityPostError::CiphertextLength {
            expected: MLKEM1024_CIPHERTEXT_LENGTH,
            actual: encapsulation.ciphertext().len(),
        });
    }

    let decapsulated = decapsulate_key(&secret_key, encapsulation.ciphertext())
        .map_err(SecurityPostError::Decapsulation)?;
    if decapsulated.len() != MLKEM1024_SHARED_SECRET_LENGTH {
        return Err(SecurityPostError::SharedSecretLength {
            expected: MLKEM1024_SHARED_SECRET_LENGTH,
            actual: decapsulated.len(),
        });
    }

    use subtle::ConstantTimeEq;
    if !bool::from(encapsulation.shared_secret().ct_eq(&decapsulated)) {
        return Err(SecurityPostError::SharedSecretMismatch);
    }

    Ok(())
}
