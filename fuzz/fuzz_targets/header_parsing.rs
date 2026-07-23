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
#![no_main]

use libfuzzer_sys::fuzz_target;
use quantum_crypto::kdf::argon2id::{reconstruct_key_argon2id, ARGON2ID_SALT_LENGTH};

fuzz_target!(|data: &[u8]| {
    if data.len() < ARGON2ID_SALT_LENGTH {
        return;
    }

    let password = b"fuzz_password";
    let (salt, params_bytes) = data.split_at(ARGON2ID_SALT_LENGTH);

    let _ = reconstruct_key_argon2id(password, None, salt, params_bytes, 32);
});
