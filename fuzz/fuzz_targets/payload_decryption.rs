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
use quantum_crypto::symmetric::hmac::verify_hmac;
use quantum_crypto::{
    XCHACHA20_KEY_LENGTH, XCHACHA20_NONCE_LENGTH, decrypt_data, XChaChaNonce,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < XCHACHA20_KEY_LENGTH + XCHACHA20_NONCE_LENGTH {
        return;
    }

    let (key_bytes, rest) = data.split_at(XCHACHA20_KEY_LENGTH);
    let (nonce_bytes, ciphertext) = rest.split_at(XCHACHA20_NONCE_LENGTH);

    let nonce = match XChaChaNonce::from_slice(nonce_bytes) {
        Some(n) => n,
        None => return,
    };

    let _ = decrypt_data(key_bytes, &nonce, ciphertext, None);

    if ciphertext.len() >= 32 {
        let (mac_key, _) = key_bytes.split_at(32);
        let (tag, message) = ciphertext.split_at(32);
        let _ = verify_hmac(mac_key, message, tag.try_into().unwrap());
    }
});
