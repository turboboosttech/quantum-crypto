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
use crate::errors::GeneratorError;
use lazy_static::lazy_static;
use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::fmt;
use zeroize::Zeroizing;

const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBER_CHARS: &[u8] = b"0123456789";
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()_+-=[]{}|;':\",./<>?";

pub const PASSWORD_DEFAULT_LENGTH: usize = 20;
pub const RANDOM_PASSWORD_MIN_LENGTH: usize = 4;
pub const RANDOM_PASSWORD_MAX_LENGTH: usize = 128;
pub const STRUCTURED_PASSWORD_DEFAULT_SEGMENTS: usize = 3;
pub const STRUCTURED_PASSWORD_MIN_SEGMENTS: usize = 2;
pub const STRUCTURED_PASSWORD_MAX_SEGMENTS: usize = 18;
pub const STRUCTURED_PASSWORD_DEFAULT_DIVIDER: char = '-';
pub const DICEWARE_DEFAULT_WORD_COUNT: usize = 5;
pub const DICEWARE_MIN_WORD_COUNT: usize = 2;
pub const DICEWARE_MAX_WORD_COUNT: usize = 25;
pub const DICEWARE_DEFAULT_SEPARATOR: char = '-';
pub const DICEWARE_WORDLIST_SIZE: usize = 7_776;
pub const DICEWARE_BITS_PER_WORD: f64 = 12.924_812_503_605_78;
pub const DICEWARE_MIN_WORD_EDIT_DISTANCE: usize = 3;

const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwx";
const VOWELS: &[u8] = b"aeiouy";
const EFF_LONG_WORDLIST: &str = include_str!("eff_large_wordlist.txt");
const DICEWARE_MAX_SELECTION_ATTEMPTS: usize = 4096;
const OFFENSIVE_WORDS: &[&str] = &[
    "fuck", "shit", "bitch", "cunt", "dick", "pussy", "cock", "slut", "whore",
];

lazy_static! {
    static ref DICEWARE_WORDS: Vec<&'static str> = load_diceware_words();
}

pub struct DicewarePassphrase {
    pub passphrase: Zeroizing<String>,
    pub entropy_bits: f64,
    pub word_count: usize,
}

impl fmt::Debug for DicewarePassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DicewarePassphrase")
            .field("passphrase", &"[redacted]")
            .field("entropy_bits", &self.entropy_bits)
            .field("word_count", &self.word_count)
            .finish()
    }
}

fn load_diceware_words() -> Vec<&'static str> {
    let words: Vec<&'static str> = EFF_LONG_WORDLIST
        .lines()
        .map(|line| {
            let mut parts = line.split_whitespace();
            let index = parts
                .next()
                .unwrap_or_else(|| panic!("EFF Diceware wordlist row is missing an index"));
            let word = parts
                .next()
                .unwrap_or_else(|| panic!("EFF Diceware wordlist row is missing a word"));

            assert!(
                parts.next().is_none(),
                "EFF Diceware wordlist row has extra columns"
            );
            assert!(
                index.len() == 5 && index.bytes().all(|b| (b'1'..=b'6').contains(&b)),
                "EFF Diceware wordlist index must be five base-6 dice digits"
            );

            word
        })
        .collect();

    assert_eq!(
        words.len(),
        DICEWARE_WORDLIST_SIZE,
        "EFF Diceware wordlist must contain exactly 7,776 entries"
    );

    words
}

fn structured_password_length(segments: usize) -> Option<usize> {
    segments
        .checked_mul(6)
        .and_then(|length| length.checked_add(segments.saturating_sub(1)))
}

fn edit_distance_less_than(left: &str, right: &str, limit: usize) -> bool {
    if left == right {
        return true;
    }

    if left.len().abs_diff(right.len()) >= limit {
        return false;
    }

    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];

    for (left_index, left_byte) in left.bytes().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_byte) in right.bytes().enumerate() {
            let substitution_cost = usize::from(left_byte != right_byte);
            let deletion = previous[right_index + 1] + 1;
            let insertion = current[right_index] + 1;
            let substitution = previous[right_index] + substitution_cost;

            current[right_index + 1] = deletion.min(insertion).min(substitution);
        }

        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()] < limit
}

fn diceware_word_allowed(word: &str, selected_words: &[&str]) -> bool {
    selected_words
        .iter()
        .all(|selected| !edit_distance_less_than(word, selected, DICEWARE_MIN_WORD_EDIT_DISTANCE))
}

fn structured_digit_candidate_indices(chars: &[char], divider: char) -> Vec<usize> {
    chars
        .iter()
        .enumerate()
        .filter_map(|(index, &character)| (character != divider).then_some(index))
        .collect()
}

pub fn generate_random_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<Zeroizing<String>, GeneratorError> {
    let mut active_sets = Vec::new();

    if uppercase {
        active_sets.push(UPPERCASE_CHARS);
    }
    if lowercase {
        active_sets.push(LOWERCASE_CHARS);
    }
    if numbers {
        active_sets.push(NUMBER_CHARS);
    }
    if symbols {
        active_sets.push(SYMBOL_CHARS);
    }

    if active_sets.is_empty() {
        return Err(GeneratorError::NoCharacterSetSelected);
    }

    if length < RANDOM_PASSWORD_MIN_LENGTH {
        return Err(GeneratorError::LengthTooSmall {
            requested: length,
            minimum: RANDOM_PASSWORD_MIN_LENGTH,
        });
    }

    if length > RANDOM_PASSWORD_MAX_LENGTH {
        return Err(GeneratorError::LengthTooLarge {
            requested: length,
            maximum: RANDOM_PASSWORD_MAX_LENGTH,
        });
    }

    if length < active_sets.len() {
        return Err(GeneratorError::LengthTooSmall {
            requested: length,
            minimum: active_sets.len(),
        });
    }

    let mut password_bytes = Vec::with_capacity(length);
    let mut rng = OsRng;

    for set in &active_sets {
        let &ch = set.choose(&mut rng).ok_or_else(|| {
            GeneratorError::GenerationFailed("Character set must not be empty".to_string())
        })?;
        password_bytes.push(ch);
    }

    let all_active_chars: Vec<u8> = active_sets.into_iter().flatten().copied().collect();

    let remaining_length = length - password_bytes.len();
    for _ in 0..remaining_length {
        let &ch = all_active_chars.choose(&mut rng).ok_or_else(|| {
            GeneratorError::GenerationFailed("Flattened pool must not be empty".to_string())
        })?;
        password_bytes.push(ch);
    }

    password_bytes.shuffle(&mut rng);

    let password = String::from_utf8(password_bytes).map_err(|_| {
        GeneratorError::GenerationFailed("Generated password is not valid UTF-8".to_string())
    })?;

    Ok(Zeroizing::new(password))
}

pub fn generate_structured_password(
    segments: usize,
    divider: char,
) -> Result<Zeroizing<String>, GeneratorError> {
    if segments < STRUCTURED_PASSWORD_MIN_SEGMENTS {
        return Err(GeneratorError::LengthTooSmall {
            requested: segments,
            minimum: STRUCTURED_PASSWORD_MIN_SEGMENTS,
        });
    }

    let password_length =
        structured_password_length(segments).ok_or(GeneratorError::LengthTooLarge {
            requested: usize::MAX,
            maximum: RANDOM_PASSWORD_MAX_LENGTH,
        })?;

    if segments > STRUCTURED_PASSWORD_MAX_SEGMENTS || password_length > RANDOM_PASSWORD_MAX_LENGTH {
        return Err(GeneratorError::LengthTooLarge {
            requested: password_length,
            maximum: RANDOM_PASSWORD_MAX_LENGTH,
        });
    }

    if !divider.is_ascii() || divider.is_ascii_alphanumeric() {
        return Err(GeneratorError::GenerationFailed(
            "Divider must be an ASCII non-alphanumeric character".to_string(),
        ));
    }

    let mut rng = OsRng;

    loop {
        let mut pass_bytes = Vec::new();

        for s in 0..segments {
            for _ in 0..2 {
                let c1 = *CONSONANTS.choose(&mut rng).ok_or_else(|| {
                    GeneratorError::GenerationFailed("Empty consonants".to_string())
                })?;
                let v = *VOWELS
                    .choose(&mut rng)
                    .ok_or_else(|| GeneratorError::GenerationFailed("Empty vowels".to_string()))?;
                let c2 = *CONSONANTS.choose(&mut rng).ok_or_else(|| {
                    GeneratorError::GenerationFailed("Empty consonants".to_string())
                })?;
                pass_bytes.push(c1);
                pass_bytes.push(v);
                pass_bytes.push(c2);
            }
            if s < segments - 1 {
                let mut buf = [0; 4];
                pass_bytes.extend_from_slice(divider.encode_utf8(&mut buf).as_bytes());
            }
        }

        let pass_str = String::from_utf8(pass_bytes)
            .map_err(|_| GeneratorError::GenerationFailed("UTF-8 encoding failed".to_string()))?;

        let mut chars: Vec<char> = pass_str.chars().collect();
        let digit_candidates = structured_digit_candidate_indices(&chars, divider);

        let &digit_idx = digit_candidates.choose(&mut rng).ok_or_else(|| {
            GeneratorError::GenerationFailed("No valid digit candidate indices".to_string())
        })?;
        let random_digit = *NUMBER_CHARS
            .choose(&mut rng)
            .ok_or_else(|| GeneratorError::GenerationFailed("No numbers".to_string()))?
            as char;

        chars[digit_idx] = random_digit;

        let mut alpha_candidates = Vec::new();
        for (i, &c) in chars.iter().enumerate() {
            if c.is_ascii_alphabetic() {
                alpha_candidates.push(i);
            }
        }
        if !alpha_candidates.is_empty() {
            let &upper_idx = alpha_candidates.choose(&mut rng).ok_or_else(|| {
                GeneratorError::GenerationFailed("No valid uppercase candidate indices".to_string())
            })?;
            chars[upper_idx] = chars[upper_idx].to_ascii_uppercase();
        }

        let final_pass_str: String = chars.into_iter().collect();

        let lower_pass = final_pass_str.to_lowercase();
        let mut is_offensive = false;
        for &word in OFFENSIVE_WORDS {
            if lower_pass.contains(word) {
                is_offensive = true;
                break;
            }
        }

        if !is_offensive {
            return Ok(Zeroizing::new(final_pass_str));
        }
    }
}

pub fn generate_diceware(
    word_count: usize,
    separator: char,
) -> Result<DicewarePassphrase, GeneratorError> {
    if !separator.is_ascii() || separator.is_ascii_alphanumeric() {
        return Err(GeneratorError::GenerationFailed(
            "Separator must be an ASCII non-alphanumeric character".to_string(),
        ));
    }

    let word_count = word_count.max(DICEWARE_MIN_WORD_COUNT);
    if word_count > DICEWARE_MAX_WORD_COUNT {
        return Err(GeneratorError::LengthTooLarge {
            requested: word_count,
            maximum: DICEWARE_MAX_WORD_COUNT,
        });
    }

    let words = &*DICEWARE_WORDS;
    let mut rng = OsRng;
    let mut selected_words = Vec::with_capacity(word_count);
    let mut passphrase = Zeroizing::new(String::new());

    while selected_words.len() < word_count {
        let mut selected_word = None;

        for _ in 0..DICEWARE_MAX_SELECTION_ATTEMPTS {
            let index = rng.gen_range(0..DICEWARE_WORDLIST_SIZE);
            let word = words[index];

            if diceware_word_allowed(word, &selected_words) {
                selected_word = Some(word);
                break;
            }
        }

        let selected_word = selected_word.ok_or_else(|| {
            GeneratorError::GenerationFailed("Unable to select distinct Diceware word".to_string())
        })?;

        selected_words.push(selected_word);
    }

    for (index, word) in selected_words.iter().enumerate() {
        if index > 0 {
            passphrase.push(separator);
        }

        passphrase.push_str(word);
    }

    Ok(DicewarePassphrase {
        passphrase,
        entropy_bits: word_count as f64 * DICEWARE_BITS_PER_WORD,
        word_count,
    })
}

pub fn generate_default_diceware() -> Result<DicewarePassphrase, GeneratorError> {
    generate_diceware(DICEWARE_DEFAULT_WORD_COUNT, DICEWARE_DEFAULT_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_threshold_accepts_distinct_words() {
        assert!(!edit_distance_less_than(
            "panoramic",
            "handclap",
            DICEWARE_MIN_WORD_EDIT_DISTANCE
        ));
    }

    #[test]
    fn edit_distance_threshold_rejects_duplicates() {
        assert!(edit_distance_less_than(
            "panoramic",
            "panoramic",
            DICEWARE_MIN_WORD_EDIT_DISTANCE
        ));
    }

    #[test]
    fn edit_distance_threshold_rejects_near_duplicates() {
        assert!(edit_distance_less_than(
            "panoramic",
            "panoramix",
            DICEWARE_MIN_WORD_EDIT_DISTANCE
        ));
    }

    #[test]
    fn structured_digit_candidates_include_all_single_segment_positions() {
        let chars: Vec<char> = "bavtok".chars().collect();

        assert_eq!(
            structured_digit_candidate_indices(&chars, '-'),
            vec![0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn structured_digit_candidates_exclude_dividers_only() {
        let chars: Vec<char> = "bavtok-cymwer".chars().collect();

        assert_eq!(
            structured_digit_candidate_indices(&chars, '-'),
            vec![0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12]
        );
    }

    #[test]
    fn diceware_generation_rejects_duplicate_and_similar_words() {
        for _ in 0..100 {
            let generated = match generate_diceware(25, '|') {
                Ok(generated) => generated,
                Err(error) => panic!("Diceware generation failed: {error}"),
            };
            let words: Vec<&str> = generated.passphrase.split('|').collect();

            assert_eq!(words.len(), 25);

            for first_index in 0..words.len() {
                for second_index in (first_index + 1)..words.len() {
                    assert!(!edit_distance_less_than(
                        words[first_index],
                        words[second_index],
                        DICEWARE_MIN_WORD_EDIT_DISTANCE
                    ));
                }
            }
        }
    }
}
