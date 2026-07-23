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
use crate::errors::StreamingError;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const RECORD_HEADER_LEN: usize = 16;
pub(crate) const TAG_LEN: usize = 16;
const MAGIC: &[u8; 8] = b"QCSTREAM";
const KEY_INFO: &[u8] = b"quantum-crypto/stream/key\0";
const RECORD_AAD: &[u8] = b"quantum-crypto/stream/record\0";

#[derive(Clone)]
pub(crate) struct Header {
    pub bytes: [u8; HEADER_LEN],
    pub chunk_size: u32,
    pub total: u64,
    pub salt: [u8; 16],
    pub prefix: [u8; 16],
}

impl Header {
    pub fn generate(chunk_size: u32, total: u64) -> Result<Self, StreamingError> {
        let mut salt = [0; 16];
        let mut prefix = [0; 16];
        while salt == [0; 16] {
            OsRng
                .try_fill_bytes(&mut salt)
                .map_err(|_| StreamingError::RngError)?;
        }
        while prefix == [0; 16] {
            OsRng
                .try_fill_bytes(&mut prefix)
                .map_err(|_| StreamingError::RngError)?;
        }
        let mut bytes = [0; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&chunk_size.to_le_bytes());
        bytes[24..32].copy_from_slice(&total.to_le_bytes());
        bytes[32..48].copy_from_slice(&salt);
        bytes[48..64].copy_from_slice(&prefix);
        Ok(Self {
            bytes,
            chunk_size,
            total,
            salt,
            prefix,
        })
    }
    pub fn parse(bytes: [u8; HEADER_LEN]) -> Result<Self, StreamingError> {
        if &bytes[..8] != MAGIC {
            return Err(StreamingError::InvalidHeader);
        }
        if u16::from_le_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        ) != 1
        {
            return Err(StreamingError::UnsupportedFormat);
        }
        if u16::from_le_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        ) != 1
        {
            return Err(StreamingError::UnsupportedSuite);
        }
        if bytes[12..16] != [0; 4] || bytes[20..24] != [0; 4] {
            return Err(StreamingError::InvalidHeader);
        }
        let chunk_size = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        );
        if !(super::MIN_CHUNK_SIZE..=super::MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(StreamingError::InvalidChunkSize);
        }
        let total = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        );
        let salt = bytes[32..48]
            .try_into()
            .map_err(|_| StreamingError::InvalidHeader)?;
        let prefix = bytes[48..64]
            .try_into()
            .map_err(|_| StreamingError::InvalidHeader)?;
        if salt == [0; 16] || prefix == [0; 16] {
            return Err(StreamingError::InvalidHeader);
        }
        Ok(Self {
            bytes,
            chunk_size,
            total,
            salt,
            prefix,
        })
    }
}

pub(crate) fn validate_context(domain: &[u8], aad: &[u8]) -> Result<(), StreamingError> {
    if domain.is_empty() || domain.len() > 255 {
        return Err(StreamingError::InvalidDomain);
    }
    if aad.len() > 65_535 {
        return Err(StreamingError::AssociatedDataTooLarge);
    }
    Ok(())
}
pub(crate) fn derive_key(
    root: &[u8; 32],
    header: &Header,
) -> Result<Zeroizing<[u8; 32]>, StreamingError> {
    let hk = Hkdf::<Sha256>::new(Some(&header.salt), root);
    let mut key = Zeroizing::new([0; 32]);
    let mut info = Vec::with_capacity(KEY_INFO.len() + HEADER_LEN);
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(&header.bytes);
    hk.expand(&info, key.as_mut())
        .map_err(|_| StreamingError::KeyDerivationFailed)?;
    Ok(key)
}
pub(crate) fn record_header(sequence: u64, length: u32, final_record: bool) -> [u8; 16] {
    let mut h = [0; 16];
    h[..8].copy_from_slice(&sequence.to_le_bytes());
    h[8..12].copy_from_slice(&length.to_le_bytes());
    h[12] = u8::from(final_record);
    h
}
pub(crate) fn parse_record_header(h: &[u8; 16]) -> Result<(u64, u32, bool), StreamingError> {
    if h[12] & !1 != 0 || h[13..] != [0; 3] {
        return Err(StreamingError::InvalidRecord);
    }
    Ok((
        u64::from_le_bytes(
            h[..8]
                .try_into()
                .map_err(|_| StreamingError::InvalidRecord)?,
        ),
        u32::from_le_bytes(
            h[8..12]
                .try_into()
                .map_err(|_| StreamingError::InvalidRecord)?,
        ),
        h[12] == 1,
    ))
}
fn aad(context: super::StreamContext<'_>, header: &Header, record: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        RECORD_AAD.len() + 1 + context.domain.len() + 4 + context.aad.len() + 80,
    );
    out.extend_from_slice(RECORD_AAD);
    out.push(context.domain.len() as u8);
    out.extend_from_slice(context.domain);
    out.extend_from_slice(&(context.aad.len() as u32).to_le_bytes());
    out.extend_from_slice(context.aad);
    out.extend_from_slice(&header.bytes);
    out.extend_from_slice(record);
    out
}
pub(crate) fn crypt(
    encrypt: bool,
    key: &[u8; 32],
    header: &Header,
    record: &[u8; 16],
    context: super::StreamContext<'_>,
    data: &[u8],
) -> Result<Vec<u8>, StreamingError> {
    let sequence = u64::from_le_bytes(
        record[..8]
            .try_into()
            .map_err(|_| StreamingError::InvalidRecord)?,
    );
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&header.prefix);
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: data,
        aad: &aad(context, header, record),
    };
    if encrypt {
        cipher
            .encrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| StreamingError::AuthenticationFailed)
    } else {
        cipher
            .decrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| StreamingError::AuthenticationFailed)
    }
}
