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
use quantum_crypto::XChaChaNonce;
use quantum_crypto::kdf::argon2id::reconstruct_key_argon2id;
use quantum_crypto::kdf::hkdf::derive_subkey_hkdf;
use quantum_crypto::symmetric::hmac::verify_hmac;
use quantum_crypto::symmetric::xchacha::decrypt_data;

const SALT: &[u8] = &[
    221, 23, 106, 240, 216, 145, 149, 169, 213, 42, 46, 94, 154, 252, 255, 4,
];
const PARAMS: &[u8] = &[0, 76, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0];
const EXPECTED_MASTER_KEY: &[u8] = &[
    65, 196, 207, 191, 87, 150, 180, 106, 53, 130, 191, 70, 243, 63, 171, 139, 234, 59, 103, 76,
    214, 187, 214, 185, 73, 20, 97, 195, 179, 217, 59, 18, 166, 18, 13, 253, 87, 254, 223, 97, 65,
    124, 87, 230, 0, 21, 12, 109, 225, 215, 123, 116, 12, 1, 65, 167, 139, 154, 149, 86, 73, 225,
    127, 153,
];
const EXPECTED_ENC_KEY: &[u8] = &[
    243, 78, 103, 164, 32, 245, 218, 153, 200, 223, 69, 203, 75, 109, 134, 68, 63, 17, 154, 122,
    207, 4, 214, 188, 6, 106, 23, 249, 54, 32, 236, 137,
];
const EXPECTED_MAC_KEY: &[u8] = &[
    160, 6, 114, 190, 203, 183, 205, 36, 124, 47, 170, 202, 209, 199, 199, 38, 101, 114, 33, 4,
    183, 143, 15, 102, 215, 133, 76, 62, 173, 186, 88, 222,
];
const VAULT_PAYLOAD: &[u8] = &[
    221, 23, 106, 240, 216, 145, 149, 169, 213, 42, 46, 94, 154, 252, 255, 4, 0, 76, 0, 0, 2, 0, 0,
    0, 1, 0, 0, 0, 170, 8, 222, 67, 211, 78, 70, 19, 17, 39, 156, 75, 255, 75, 8, 221, 111, 80,
    238, 60, 137, 94, 186, 158, 56, 0, 0, 0, 57, 8, 52, 58, 0, 59, 224, 223, 7, 161, 255, 27, 133,
    11, 5, 111, 82, 27, 150, 95, 190, 117, 120, 105, 77, 137, 197, 107, 50, 156, 79, 220, 90, 234,
    146, 135, 77, 75, 159, 165, 255, 144, 191, 157, 142, 224, 51, 46, 99, 196, 121, 191, 204, 244,
    109, 74, 97, 2, 203, 103, 212, 119, 43, 238, 104, 88, 147, 0, 113, 42, 100, 225, 113, 17, 168,
    165, 144, 25, 239, 204, 48, 0, 0, 0, 167, 40, 180, 69, 130, 32, 167, 128, 120, 173, 82, 144,
    183, 244, 143, 233, 184, 158, 122, 191, 182, 89, 66, 134, 134, 254, 47, 20, 50, 98, 20, 129,
    246, 27, 210, 17, 207, 104, 57, 130, 6, 160, 47, 86, 126, 10, 175, 70,
];
const HMAC_TAG: &[u8] = &[
    215, 171, 9, 192, 236, 17, 161, 148, 214, 118, 212, 231, 156, 199, 109, 28, 127, 236, 253, 133,
    157, 98, 119, 150, 110, 185, 198, 83, 34, 90, 89, 47,
];
const METADATA_NONCE: &[u8] = &[
    170, 8, 222, 67, 211, 78, 70, 19, 17, 39, 156, 75, 255, 75, 8, 221, 111, 80, 238, 60, 137, 94,
    186, 158,
];
const METADATA_CIPHERTEXT: &[u8] = &[
    57, 8, 52, 58, 0, 59, 224, 223, 7, 161, 255, 27, 133, 11, 5, 111, 82, 27, 150, 95, 190, 117,
    120, 105, 77, 137, 197, 107, 50, 156, 79, 220, 90, 234, 146, 135, 77, 75, 159, 165, 255, 144,
    191, 157, 142, 224, 51, 46, 99, 196, 121, 191, 204, 244, 109, 74,
];
const ITEM_NONCE: &[u8] = &[
    97, 2, 203, 103, 212, 119, 43, 238, 104, 88, 147, 0, 113, 42, 100, 225, 113, 17, 168, 165, 144,
    25, 239, 204,
];
const ITEM_CIPHERTEXT: &[u8] = &[
    167, 40, 180, 69, 130, 32, 167, 128, 120, 173, 82, 144, 183, 244, 143, 233, 184, 158, 122, 191,
    182, 89, 66, 134, 134, 254, 47, 20, 50, 98, 20, 129, 246, 27, 210, 17, 207, 104, 57, 130, 6,
    160, 47, 86, 126, 10, 175, 70,
];

#[test]
fn test_known_answer_vault_unlock() {
    let password = b"my_secure_password";
    let secret_key = b"my_secret_key_16"; // 16 bytes

    let reconstructed_master_key =
        reconstruct_key_argon2id(password, Some(secret_key), SALT, PARAMS, 64)
            .expect("Failed to reconstruct master key");
    assert_eq!(
        reconstructed_master_key.as_slice(),
        EXPECTED_MASTER_KEY,
        "Master key mismatch"
    );

    let enc_key = derive_subkey_hkdf(&reconstructed_master_key, None, b"encryption", 32)
        .expect("Failed to derive encryption key");
    assert_eq!(
        enc_key.as_slice(),
        EXPECTED_ENC_KEY,
        "Encryption key mismatch"
    );

    let mac_key = derive_subkey_hkdf(&reconstructed_master_key, None, b"mac", 32)
        .expect("Failed to derive MAC key");
    assert_eq!(mac_key.as_slice(), EXPECTED_MAC_KEY, "MAC key mismatch");

    verify_hmac(mac_key.as_slice(), VAULT_PAYLOAD, HMAC_TAG).expect("HMAC verification failed");

    let decrypted_metadata = decrypt_data(
        enc_key.as_slice(),
        &XChaChaNonce::from_slice(METADATA_NONCE).unwrap(),
        METADATA_CIPHERTEXT,
        None,
    )
    .expect("Failed to decrypt metadata");
    assert_eq!(
        decrypted_metadata.as_slice(),
        b"metadata: vault_name=test_vault, items=1"
    );

    let decrypted_item = decrypt_data(
        enc_key.as_slice(),
        &XChaChaNonce::from_slice(ITEM_NONCE).unwrap(),
        ITEM_CIPHERTEXT,
        None,
    )
    .expect("Failed to decrypt item");
    assert_eq!(
        decrypted_item.as_slice(),
        b"item: secret_password_for_github"
    );
}
