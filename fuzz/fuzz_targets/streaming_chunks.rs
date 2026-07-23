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
use quantum_crypto::{
    DecryptStreamConfig, EncryptStreamConfig, MIN_CHUNK_SIZE, StreamContext, StreamingError,
    decrypt_stream, encrypt_stream,
};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

const KEY: [u8; 32] = [0; 32];
const HEADER_LEN: usize = 64;
const RECORD_HEADER_LEN: usize = 16;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT: usize = MIN_CHUNK_SIZE as usize * 2 + 1;

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("fuzz runtime"))
}

fn context() -> StreamContext<'static> {
    StreamContext {
        domain: b"fuzz.stream",
        aad: b"",
    }
}

async fn valid_stream(data: &[u8]) {
    let target_len = match data.first().copied().unwrap_or(0) % 3 {
        0 => 0,
        1 => MIN_CHUNK_SIZE as usize,
        _ => MAX_PLAINTEXT,
    };
    let source = data.get(1..).unwrap_or_default();
    let plaintext = if source.is_empty() {
        vec![0; target_len]
    } else {
        source.iter().copied().cycle().take(target_len).collect()
    };
    let mut wire = Vec::new();
    encrypt_stream(
        plaintext.as_slice(),
        &mut wire,
        &KEY,
        EncryptStreamConfig::new(target_len as u64, context()).with_chunk_size(MIN_CHUNK_SIZE),
    )
    .await
    .expect("valid seed encryption");

    let mut output = Vec::new();
    let summary = decrypt_stream(
        wire.as_slice(),
        &mut output,
        &KEY,
        DecryptStreamConfig::new(context()),
    )
    .await
    .expect("valid seed decryption");
    assert_eq!(output, plaintext);
    assert_eq!(summary.plaintext_bytes as usize, target_len);

    if target_len != 0 {
        wire[HEADER_LEN + RECORD_HEADER_LEN] ^= 1;
        output.clear();
        let result = decrypt_stream(
            wire.as_slice(),
            &mut output,
            &KEY,
            DecryptStreamConfig::new(context()),
        )
        .await;
        assert!(matches!(result, Err(StreamingError::AuthenticationFailed)));
        assert!(output.is_empty());
    }
    assert!(wire.len() <= HEADER_LEN + target_len + 3 * (RECORD_HEADER_LEN + TAG_LEN));
}

fuzz_target!(|data: &[u8]| {
    runtime().block_on(async {
        if data.first().copied().unwrap_or(0) & 0x80 == 0 {
            valid_stream(data).await;
        } else {
            let mut output = Vec::new();
            let _ = decrypt_stream(
                data,
                &mut output,
                &KEY,
                DecryptStreamConfig::new(context()),
            )
            .await;
            assert!(output.len() <= data.len());
        }
    });
});
