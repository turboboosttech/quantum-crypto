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

pub mod hmac;
pub mod keys;
pub mod root_keys;
pub mod xchacha;

pub use xchacha::{
    MAX_MESSAGE_SIZE, XCHACHA20_KEY_LENGTH, XCHACHA20_NONCE_LENGTH, XCHACHA20_TAG_LENGTH,
    XChaChaNonce, decrypt_data, encrypt_data, generate_xchacha_nonce,
};

pub use hmac::{HMAC_SHA256_TAG_LENGTH, MIN_HMAC_KEY_LENGTH, compute_hmac, verify_hmac};

pub use root_keys::{
    decapsulate_root_key, derive_root_key_argon2id, generate_root_key_ml_kem,
    reconstruct_root_key_argon2id,
};
