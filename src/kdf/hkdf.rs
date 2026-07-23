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
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::KeyError;

pub fn derive_subkey_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if output_length == 0 || output_length > 255 * 32 {
        return Err(KeyError::GenerationFailed(
            "Invalid HKDF output length".into(),
        ));
    }

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; output_length];
    hk.expand(info, &mut okm)
        .map_err(|_| KeyError::GenerationFailed("HKDF expand failed".into()))?;

    Ok(Zeroizing::new(okm))
}
