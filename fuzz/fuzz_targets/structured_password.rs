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
use quantum_crypto::generate_structured_password;

fuzz_target!(|data: (usize, char)| {
    let (segments, divider) = data;
    
    let _ = generate_structured_password(segments, divider);
});
