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
use quantum_crypto::{
    DecryptStreamConfig, EncryptStreamConfig, StreamContext, decapsulate_key, decrypt_stream,
    encapsulate_key, encrypt_stream, generate_keypair,
};

#[tokio::test]
async fn ml_kem_established_key_is_external_to_stream() {
    let (public, secret) = generate_keypair(false).unwrap();
    let established = encapsulate_key(&public).unwrap();
    let recovered = decapsulate_key(&secret, established.ciphertext()).unwrap();
    let key: [u8; 32] = recovered.as_slice().try_into().unwrap();
    let context = StreamContext {
        domain: b"9core.sync-record",
        aad: b"account:1/record:1/schema:1",
    };
    let mut wire = Vec::new();
    encrypt_stream(
        &b"record"[..],
        &mut wire,
        &key,
        EncryptStreamConfig::new(6, context),
    )
    .await
    .unwrap();
    assert!(
        !wire
            .windows(established.ciphertext().len())
            .any(|w| w == established.ciphertext())
    );
    let mut plain = Vec::new();
    decrypt_stream(
        wire.as_slice(),
        &mut plain,
        &key,
        DecryptStreamConfig::new(context),
    )
    .await
    .unwrap();
    assert_eq!(plain, b"record");
}

#[tokio::test]
async fn sync_records_have_independent_boundaries() {
    let key = [9; 32];
    let mut wires = Vec::new();
    for id in [b'1', b'2'] {
        let aad = [id];
        let context = StreamContext {
            domain: b"9core.sync-record",
            aad: &aad,
        };
        let mut wire = Vec::new();
        encrypt_stream(
            &[id][..],
            &mut wire,
            &key,
            EncryptStreamConfig::new(1, context),
        )
        .await
        .unwrap();
        wires.push(wire);
    }
    assert_ne!(&wires[0][32..64], &wires[1][32..64]);
    for (index, wire) in wires.iter().enumerate() {
        let aad = [b'1' + index as u8];
        let context = StreamContext {
            domain: b"9core.sync-record",
            aad: &aad,
        };
        let mut plain = Vec::new();
        decrypt_stream(
            wire.as_slice(),
            &mut plain,
            &key,
            DecryptStreamConfig::new(context),
        )
        .await
        .unwrap();
        assert_eq!(plain, aad);
    }
}
