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
use quantum_crypto::asymmetric::ml_kem::EncapsulationResult;
use quantum_crypto::types::{CombinedPublicKey, CombinedSecretKey};

fuzz_target!(|data: &[u8]| {

    let _ = bincode::deserialize::<CombinedPublicKey>(data);

    let _ = EncapsulationResult::new(data.to_vec(), vec![0u8; 32]);

    let _ = bincode::deserialize::<CombinedSecretKey>(data);
});
