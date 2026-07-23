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

pub mod keys;
pub mod ml_dsa;
pub mod ml_kem;

#[deprecated(note = "Use ml_dsa for FIPS 204 ML-DSA")]
pub use ml_dsa as dilithium;
#[deprecated(note = "Use ml_kem for FIPS 203 ML-KEM")]
pub use ml_kem as kyber;

pub use ml_kem::{
    MLKEM1024_CIPHERTEXT_LENGTH, MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM1024_SECRET_KEY_LENGTH,
    MLKEM1024_SHARED_SECRET_LENGTH, decapsulate_key, encapsulate_key,
};

#[deprecated(note = "Use MLKEM1024_CIPHERTEXT_LENGTH")]
pub use ml_kem::MLKEM1024_CIPHERTEXT_LENGTH as KYBER1024_CIPHERTEXT_LENGTH;
#[deprecated(note = "Use MLKEM1024_PUBLIC_KEY_LENGTH")]
pub use ml_kem::MLKEM1024_PUBLIC_KEY_LENGTH as KYBER1024_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLKEM1024_SECRET_KEY_LENGTH")]
pub use ml_kem::MLKEM1024_SECRET_KEY_LENGTH as KYBER1024_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLKEM1024_SHARED_SECRET_LENGTH")]
pub use ml_kem::MLKEM1024_SHARED_SECRET_LENGTH as KYBER1024_SHARED_SECRET_LENGTH;

pub use ml_dsa::{
    MAX_SIGNABLE_SIZE, MLDSA44_PUBLIC_KEY_LENGTH, MLDSA44_SECRET_KEY_LENGTH,
    MLDSA44_SIGNATURE_LENGTH, MLDSA65_PUBLIC_KEY_LENGTH, MLDSA65_SECRET_KEY_LENGTH,
    MLDSA65_SIGNATURE_LENGTH, MLDSA87_PUBLIC_KEY_LENGTH, MLDSA87_SECRET_KEY_LENGTH,
    MLDSA87_SIGNATURE_LENGTH, SIGN_CONTEXT_PAIRING, SIGN_CONTEXT_SYNC_CHALLENGE,
    sign_message_enhanced, verify_signature_enhanced,
};

#[deprecated(note = "Use MLDSA44_PUBLIC_KEY_LENGTH")]
pub use ml_dsa::MLDSA44_PUBLIC_KEY_LENGTH as DILITHIUM2_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA44_SECRET_KEY_LENGTH")]
pub use ml_dsa::MLDSA44_SECRET_KEY_LENGTH as DILITHIUM2_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA44_SIGNATURE_LENGTH")]
pub use ml_dsa::MLDSA44_SIGNATURE_LENGTH as DILITHIUM2_SIGNATURE_LENGTH;
#[deprecated(note = "Use MLDSA65_PUBLIC_KEY_LENGTH")]
pub use ml_dsa::MLDSA65_PUBLIC_KEY_LENGTH as DILITHIUM3_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA65_SECRET_KEY_LENGTH")]
pub use ml_dsa::MLDSA65_SECRET_KEY_LENGTH as DILITHIUM3_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA65_SIGNATURE_LENGTH")]
pub use ml_dsa::MLDSA65_SIGNATURE_LENGTH as DILITHIUM3_SIGNATURE_LENGTH;
#[deprecated(note = "Use MLDSA87_PUBLIC_KEY_LENGTH")]
pub use ml_dsa::MLDSA87_PUBLIC_KEY_LENGTH as DILITHIUM5_PUBLIC_KEY_LENGTH;
#[deprecated(note = "Use MLDSA87_SECRET_KEY_LENGTH")]
pub use ml_dsa::MLDSA87_SECRET_KEY_LENGTH as DILITHIUM5_SECRET_KEY_LENGTH;
#[deprecated(note = "Use MLDSA87_SIGNATURE_LENGTH")]
pub use ml_dsa::MLDSA87_SIGNATURE_LENGTH as DILITHIUM5_SIGNATURE_LENGTH;

#[deprecated(note = "Use generate_keypair_with_mldsa")]
pub use keys::generate_keypair_with_mldsa as generate_keypair_with_dilithium;
pub use keys::{generate_keypair, generate_keypair_with_mldsa};
