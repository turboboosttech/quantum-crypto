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
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_mlkem::mlkem1024::keypair as ml_kem_keypair;

use crate::{
    CombinedPublicKey, CombinedSecretKey, DilithiumPublicKey, DilithiumSecretKey, KeyError,
    types::DilithiumVersion,
};

pub fn generate_keypair(
    include_signing: bool,
) -> Result<(CombinedPublicKey, CombinedSecretKey), KeyError> {
    generate_keypair_with_mldsa(if include_signing {
        Some(DilithiumVersion::V5)
    } else {
        None
    })
}

pub fn generate_keypair_with_mldsa(
    dilithium_version: Option<DilithiumVersion>,
) -> Result<(CombinedPublicKey, CombinedSecretKey), KeyError> {
    let (kyber_pk, kyber_sk) = ml_kem_keypair();

    if let Some(version) = dilithium_version {
        let (dilithium_pk, dilithium_sk) = match version {
            DilithiumVersion::V2 => {
                let (pk, sk) = mldsa44::keypair();
                (
                    DilithiumPublicKey::V2(Box::new(pk)),
                    DilithiumSecretKey::V2(Box::new(sk)),
                )
            }
            DilithiumVersion::V3 => {
                let (pk, sk) = mldsa65::keypair();
                (
                    DilithiumPublicKey::V3(Box::new(pk)),
                    DilithiumSecretKey::V3(Box::new(sk)),
                )
            }
            DilithiumVersion::V5 => {
                let (pk, sk) = mldsa87::keypair();
                (
                    DilithiumPublicKey::V5(Box::new(pk)),
                    DilithiumSecretKey::V5(Box::new(sk)),
                )
            }
        };

        let public_key = CombinedPublicKey::new(kyber_pk, Some(dilithium_pk))?;
        let secret_key = CombinedSecretKey::new(kyber_sk, Some(dilithium_sk))?;
        Ok((public_key, secret_key))
    } else {
        let public_key = CombinedPublicKey::new(kyber_pk, None)?;
        let secret_key = CombinedSecretKey::new(kyber_sk, None)?;
        Ok((public_key, secret_key))
    }
}

#[deprecated(note = "Use generate_keypair_with_mldsa")]
pub fn generate_keypair_with_dilithium(
    dilithium_version: Option<DilithiumVersion>,
) -> Result<(CombinedPublicKey, CombinedSecretKey), KeyError> {
    generate_keypair_with_mldsa(dilithium_version)
}
