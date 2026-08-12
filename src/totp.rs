/*
 * Business Source License 1.1
 *
 * Licensor: TurboBoostTechnologies
 * Licensed Work: quantum-crypto 2026.s.3.0.1
 * Change Date: 2030-07-27
 * Change License: Apache License, Version 2.0
 *
 * See the LICENSE file for full text.
 */
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::TotpError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub fn generate_totp(
    secret: &[u8],
    unix_time_seconds: u64,
    period_seconds: u32,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<Zeroizing<String>, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if period_seconds == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    if !matches!(digits, 6 | 8) {
        return Err(TotpError::InvalidDigits);
    }

    let counter = unix_time_seconds / u64::from(period_seconds);
    let message = counter.to_be_bytes();
    macro_rules! tag {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(secret)
                .map_err(|_| TotpError::HmacFailed)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let tag = Zeroizing::new(match algorithm {
        TotpAlgorithm::Sha1 => tag!(Sha1),
        TotpAlgorithm::Sha256 => tag!(Sha256),
        TotpAlgorithm::Sha512 => tag!(Sha512),
    });
    let offset = usize::from(tag[tag.len() - 1] & 0x0f);
    let window = tag.get(offset..offset + 4).ok_or(TotpError::HmacFailed)?;
    let binary = u32::from_be_bytes([window[0], window[1], window[2], window[3]]) & 0x7fff_ffff;
    let modulus = 10_u32.checked_pow(digits).ok_or(TotpError::InvalidDigits)?;
    Ok(Zeroizing::new(format!(
        "{binary:0width$}",
        binary = binary % modulus,
        width = digits as usize
    )))
}
