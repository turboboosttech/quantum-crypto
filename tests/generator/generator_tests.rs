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
use quantum_crypto::errors::GeneratorError;
use quantum_crypto::{
    DICEWARE_BITS_PER_WORD, DICEWARE_DEFAULT_SEPARATOR, DICEWARE_DEFAULT_WORD_COUNT,
    DICEWARE_MAX_WORD_COUNT, DICEWARE_MIN_WORD_COUNT, DICEWARE_WORDLIST_SIZE,
    PASSWORD_DEFAULT_LENGTH, RANDOM_PASSWORD_MAX_LENGTH, STRUCTURED_PASSWORD_DEFAULT_DIVIDER,
    STRUCTURED_PASSWORD_DEFAULT_SEGMENTS, STRUCTURED_PASSWORD_MAX_SEGMENTS,
    STRUCTURED_PASSWORD_MIN_SEGMENTS, generate_default_diceware, generate_diceware,
    generate_random_password, generate_structured_password,
};

#[test]
fn test_generate_random_password_all_sets() {
    let pwd = generate_random_password(PASSWORD_DEFAULT_LENGTH, true, true, true, true).unwrap();
    assert_eq!(pwd.len(), PASSWORD_DEFAULT_LENGTH);

    assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
    assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
    assert!(pwd.chars().any(|c| c.is_ascii_digit()));
    assert!(pwd.chars().any(|c| !c.is_ascii_alphanumeric()));
}

#[test]
fn test_generate_random_password_only_lowercase() {
    let pwd = generate_random_password(10, false, true, false, false).unwrap();
    assert_eq!(pwd.len(), 10);
    assert!(pwd.chars().all(|c| c.is_ascii_lowercase()));
}

#[test]
fn test_generate_random_password_no_sets() {
    let err = generate_random_password(10, false, false, false, false).unwrap_err();
    match err {
        GeneratorError::NoCharacterSetSelected => (),
        _ => panic!("Expected NoCharacterSetSelected"),
    }
}

#[test]
fn test_generate_random_password_length_too_small() {
    let err = generate_random_password(3, true, true, true, true).unwrap_err();
    match err {
        GeneratorError::LengthTooSmall {
            requested: 3,
            minimum: 4,
        } => (),
        _ => panic!("Expected LengthTooSmall"),
    }
}

#[test]
fn test_generate_random_password_exact_minimum_length() {
    let pwd = generate_random_password(4, true, true, true, true).unwrap();
    assert_eq!(pwd.len(), 4);
    assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
    assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
    assert!(pwd.chars().any(|c| c.is_ascii_digit()));
    assert!(pwd.chars().any(|c| !c.is_ascii_alphanumeric()));
}

#[test]
fn test_generate_random_password_exact_maximum_length() {
    let pwd = generate_random_password(128, true, true, true, true).unwrap();
    assert_eq!(pwd.len(), 128);
}

#[test]
fn test_generate_random_password_length_too_large() {
    let err = generate_random_password(129, true, true, true, true).unwrap_err();
    match err {
        GeneratorError::LengthTooLarge {
            requested: 129,
            maximum: 128,
        } => (),
        _ => panic!("Expected LengthTooLarge"),
    }
}

#[test]
fn test_generate_structured_password_basic() {
    let pwd = generate_structured_password(
        STRUCTURED_PASSWORD_DEFAULT_SEGMENTS,
        STRUCTURED_PASSWORD_DEFAULT_DIVIDER,
    )
    .unwrap();
    assert_eq!(pwd.len(), PASSWORD_DEFAULT_LENGTH);

    assert_eq!(
        pwd.chars()
            .filter(|&c| c == STRUCTURED_PASSWORD_DEFAULT_DIVIDER)
            .count(),
        2
    );

    assert_eq!(pwd.chars().filter(|c| c.is_ascii_uppercase()).count(), 1);

    assert_eq!(pwd.chars().filter(|c| c.is_ascii_digit()).count(), 1);
}

#[test]
fn test_generate_structured_password_below_minimum() {
    let err = generate_structured_password(STRUCTURED_PASSWORD_MIN_SEGMENTS - 1, '-').unwrap_err();
    match err {
        GeneratorError::LengthTooSmall {
            requested: 1,
            minimum: STRUCTURED_PASSWORD_MIN_SEGMENTS,
        } => (),
        _ => panic!("Expected LengthTooSmall"),
    }
}

#[test]
fn test_generate_structured_password_exact_minimum_segments() {
    let pwd = generate_structured_password(STRUCTURED_PASSWORD_MIN_SEGMENTS, '-').unwrap();
    assert_eq!(pwd.len(), 13);
}

#[test]
fn test_generate_structured_password_exact_maximum_segments() {
    let pwd = generate_structured_password(STRUCTURED_PASSWORD_MAX_SEGMENTS, '-').unwrap();

    assert_eq!(pwd.len(), 125);
}

#[test]
fn test_generate_structured_password_too_many_segments() {
    let err = generate_structured_password(STRUCTURED_PASSWORD_MAX_SEGMENTS + 1, '-').unwrap_err();

    match err {
        GeneratorError::LengthTooLarge {
            requested: 132,
            maximum: RANDOM_PASSWORD_MAX_LENGTH,
        } => (),
        _ => panic!("Expected LengthTooLarge"),
    }
}

#[test]
fn test_generate_diceware_default_shape() {
    let result =
        generate_diceware(DICEWARE_DEFAULT_WORD_COUNT, DICEWARE_DEFAULT_SEPARATOR).unwrap();
    let passphrase = result.passphrase.as_str();

    assert_eq!(result.word_count, DICEWARE_DEFAULT_WORD_COUNT);
    assert!(
        passphrase
            .chars()
            .filter(|&c| c == DICEWARE_DEFAULT_SEPARATOR)
            .count()
            >= 4
    );
    assert!(
        passphrase
            .chars()
            .all(|c| { c == DICEWARE_DEFAULT_SEPARATOR || c.is_ascii_lowercase() })
    );
    assert!((result.entropy_bits - 64.624_062_518_028_9).abs() < 0.000_000_000_001);
}

#[test]
fn test_generate_default_diceware() {
    let result = generate_default_diceware().unwrap();

    assert_eq!(result.word_count, DICEWARE_DEFAULT_WORD_COUNT);
    assert!(!result.passphrase.is_empty());
}

#[test]
fn test_generate_diceware_floors_word_count() {
    let result = generate_diceware(1, '-').unwrap();

    assert_eq!(result.word_count, DICEWARE_MIN_WORD_COUNT);
    assert!(!result.passphrase.is_empty());
}

#[test]
fn test_generate_diceware_exact_maximum_word_count() {
    let result = generate_diceware(DICEWARE_MAX_WORD_COUNT, '-').unwrap();

    assert_eq!(result.word_count, DICEWARE_MAX_WORD_COUNT);
    assert!(!result.passphrase.is_empty());
}

#[test]
fn test_generate_diceware_rejects_too_many_words() {
    let err = generate_diceware(DICEWARE_MAX_WORD_COUNT + 1, '-').unwrap_err();

    match err {
        GeneratorError::LengthTooLarge {
            requested: 26,
            maximum: DICEWARE_MAX_WORD_COUNT,
        } => (),
        _ => panic!("Expected LengthTooLarge"),
    }
}

#[test]
fn test_generate_diceware_custom_word_count_and_separator() {
    let result = generate_diceware(7, '.').unwrap();

    assert_eq!(result.word_count, 7);
    assert_eq!(result.passphrase.split('.').count(), 7);
    assert!((result.entropy_bits - 7.0 * DICEWARE_BITS_PER_WORD).abs() < 0.000_000_000_001);
}

#[test]
fn test_generate_diceware_rejects_alphanumeric_separator() {
    let err = generate_diceware(5, 'a').unwrap_err();

    match err {
        GeneratorError::GenerationFailed(_) => (),
        _ => panic!("Expected GenerationFailed"),
    }
}

#[test]
fn test_generate_diceware_rejects_non_ascii_separator() {
    let err = generate_diceware(5, '•').unwrap_err();

    match err {
        GeneratorError::GenerationFailed(_) => (),
        _ => panic!("Expected GenerationFailed"),
    }
}

#[test]
fn test_diceware_embedded_wordlist_size() {
    assert_eq!(DICEWARE_WORDLIST_SIZE, 7_776);

    let result = generate_diceware(5, '-').unwrap();

    assert_eq!(result.word_count, 5);
}

use proptest::prelude::*;

const PUNCTUATION: &[char] = &[
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
    '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~',
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn prop_test_structured_password(
        segments in STRUCTURED_PASSWORD_MIN_SEGMENTS..=STRUCTURED_PASSWORD_MAX_SEGMENTS,
        divider_idx in 0usize..PUNCTUATION.len()
    ) {
        let divider = PUNCTUATION[divider_idx];

        let pwd_result = generate_structured_password(segments, divider);

        assert!(pwd_result.is_ok(), "Failed to generate password");
        let pwd = pwd_result.unwrap();

        let expected_len = (segments * 6) + (segments - 1);
        assert_eq!(pwd.len(), expected_len, "Invalid length");

        let upper_count = pwd.chars().filter(|c| c.is_ascii_uppercase()).count();
        assert_eq!(upper_count, 1, "Must contain exactly one uppercase letter");

        let digit_count = pwd.chars().filter(|c| c.is_ascii_digit()).count();
        assert_eq!(digit_count, 1, "Must contain exactly one digit");

        let divider_count = pwd.chars().filter(|&c| c == divider).count();
        assert_eq!(divider_count, segments - 1, "Must contain exactly segments - 1 dividers");
    }
}
