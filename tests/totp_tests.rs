/*
 * Business Source License 1.1
 *
 * Licensor: TurboBoostTechnologies
 * Licensed Work: quantum-crypto 2026.s.3.0.2
 * Change Date: 2030-10-28
 * Change License: Apache License, Version 2.0
 *
 * See the LICENSE file for full text.
 */
use quantum_crypto::{TotpAlgorithm, TotpError, generate_totp};

#[test]
fn matches_rfc_6238_appendix_b() {
    let sha1 = b"12345678901234567890";
    let sha256 = b"12345678901234567890123456789012";
    let sha512 = b"1234567890123456789012345678901234567890123456789012345678901234";
    let vectors = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    for (time, expected_sha1, expected_sha256, expected_sha512) in vectors {
        assert_eq!(
            generate_totp(sha1, time, 30, 8, TotpAlgorithm::Sha1)
                .unwrap()
                .as_str(),
            expected_sha1
        );
        assert_eq!(
            generate_totp(sha256, time, 30, 8, TotpAlgorithm::Sha256)
                .unwrap()
                .as_str(),
            expected_sha256
        );
        assert_eq!(
            generate_totp(sha512, time, 30, 8, TotpAlgorithm::Sha512)
                .unwrap()
                .as_str(),
            expected_sha512
        );
    }
}

#[test]
fn generates_default_six_digit_codes_at_counter_boundaries() {
    let secret = b"12345678901234567890";
    assert_eq!(
        generate_totp(secret, 59, 30, 6, TotpAlgorithm::Sha1)
            .unwrap()
            .as_str(),
        "287082"
    );
    assert_eq!(
        generate_totp(secret, 29, 30, 6, TotpAlgorithm::Sha1).unwrap(),
        generate_totp(secret, 0, 30, 6, TotpAlgorithm::Sha1).unwrap()
    );
    assert_ne!(
        generate_totp(secret, 29, 30, 6, TotpAlgorithm::Sha1).unwrap(),
        generate_totp(secret, 30, 30, 6, TotpAlgorithm::Sha1).unwrap()
    );
}

#[test]
fn rejects_invalid_parameters_without_secret_text() {
    assert_eq!(
        generate_totp(&[], 0, 30, 6, TotpAlgorithm::Sha1),
        Err(TotpError::EmptySecret)
    );
    assert_eq!(
        generate_totp(b"private", 0, 0, 6, TotpAlgorithm::Sha1),
        Err(TotpError::InvalidPeriod)
    );
    assert_eq!(
        generate_totp(b"private", 0, 30, 7, TotpAlgorithm::Sha1),
        Err(TotpError::InvalidDigits)
    );
    assert!(!format!("{:?}", TotpError::InvalidDigits).contains("private"));
}
