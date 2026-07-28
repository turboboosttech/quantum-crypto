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
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::errors::StreamingError;

pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const RECORD_HEADER_LEN: usize = 16;
pub(crate) const TAG_LEN: usize = 16;

const MAGIC: &[u8; 8] = b"QCSTREAM";
const FORMAT_VERSION: u16 = 1;
const SUITE: u16 = 1;
const KEY_INFO: &[u8] = b"quantum-crypto/stream/key\0";
const RECORD_AAD: &[u8] = b"quantum-crypto/stream/record\0";

#[derive(Clone)]
pub(crate) struct Header {
    pub bytes: [u8; HEADER_LEN],
    pub chunk_size: u32,
    pub total_length: u64,
    pub salt: [u8; 16],
    pub nonce_prefix: [u8; 16],
}

impl Header {
    pub fn generate(chunk_size: u32, total_length: u64) -> Result<Self, StreamingError> {
        let mut salt = [0; 16];
        let mut nonce_prefix = [0; 16];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| StreamingError::RngError)?;
        OsRng
            .try_fill_bytes(&mut nonce_prefix)
            .map_err(|_| StreamingError::RngError)?;

        let mut bytes = [0; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&SUITE.to_le_bytes());
        bytes[16..20].copy_from_slice(&chunk_size.to_le_bytes());
        bytes[24..32].copy_from_slice(&total_length.to_le_bytes());
        bytes[32..48].copy_from_slice(&salt);
        bytes[48..64].copy_from_slice(&nonce_prefix);

        Ok(Self {
            bytes,
            chunk_size,
            total_length,
            salt,
            nonce_prefix,
        })
    }

    pub fn parse(bytes: [u8; HEADER_LEN]) -> Result<Self, StreamingError> {
        if &bytes[..8] != MAGIC {
            return Err(StreamingError::InvalidHeader);
        }

        let format_version = u16::from_le_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        );
        if format_version != FORMAT_VERSION {
            return Err(StreamingError::UnsupportedFormat);
        }

        let suite = u16::from_le_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        );
        if suite != SUITE {
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

        let total_length = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| StreamingError::InvalidHeader)?,
        );
        let salt = bytes[32..48]
            .try_into()
            .map_err(|_| StreamingError::InvalidHeader)?;
        let nonce_prefix = bytes[48..64]
            .try_into()
            .map_err(|_| StreamingError::InvalidHeader)?;

        Ok(Self {
            bytes,
            chunk_size,
            total_length,
            salt,
            nonce_prefix,
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
    root_key: &[u8; 32],
    header: &Header,
) -> Result<Zeroizing<[u8; 32]>, StreamingError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&header.salt), root_key);
    let mut key = Zeroizing::new([0; 32]);
    let mut info = Vec::with_capacity(KEY_INFO.len() + HEADER_LEN);
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(&header.bytes);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| StreamingError::KeyDerivationFailed)?;
    Ok(key)
}

pub(crate) fn record_header(
    sequence: u64,
    plaintext_length: u32,
    final_record: bool,
) -> [u8; RECORD_HEADER_LEN] {
    let mut header = [0; RECORD_HEADER_LEN];
    header[..8].copy_from_slice(&sequence.to_le_bytes());
    header[8..12].copy_from_slice(&plaintext_length.to_le_bytes());
    header[12] = u8::from(final_record);
    header
}

pub(crate) fn parse_record_header(
    header: &[u8; RECORD_HEADER_LEN],
) -> Result<(u64, u32, bool), StreamingError> {
    if header[12] & !1 != 0 || header[13..] != [0; 3] {
        return Err(StreamingError::InvalidRecord);
    }

    let sequence = u64::from_le_bytes(
        header[..8]
            .try_into()
            .map_err(|_| StreamingError::InvalidRecord)?,
    );
    let plaintext_length = u32::from_le_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| StreamingError::InvalidRecord)?,
    );

    Ok((sequence, plaintext_length, header[12] == 1))
}

fn associated_data(
    context: super::StreamContext<'_>,
    header: &Header,
    record_header: &[u8; RECORD_HEADER_LEN],
) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(
        RECORD_AAD.len()
            + 1
            + context.domain.len()
            + 4
            + context.aad.len()
            + HEADER_LEN
            + RECORD_HEADER_LEN,
    );
    associated_data.extend_from_slice(RECORD_AAD);
    associated_data.push(context.domain.len() as u8);
    associated_data.extend_from_slice(context.domain);
    associated_data.extend_from_slice(&(context.aad.len() as u32).to_le_bytes());
    associated_data.extend_from_slice(context.aad);
    associated_data.extend_from_slice(&header.bytes);
    associated_data.extend_from_slice(record_header);
    associated_data
}

fn nonce(
    header: &Header,
    record_header: &[u8; RECORD_HEADER_LEN],
) -> Result<[u8; 24], StreamingError> {
    let sequence = u64::from_le_bytes(
        record_header[..8]
            .try_into()
            .map_err(|_| StreamingError::InvalidRecord)?,
    );
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&header.nonce_prefix);
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    Ok(nonce)
}

pub(crate) fn encrypt_record(
    key: &[u8; 32],
    header: &Header,
    record_header: &[u8; RECORD_HEADER_LEN],
    context: super::StreamContext<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, StreamingError> {
    let nonce = nonce(header, record_header)?;
    let associated_data = associated_data(context, header, record_header);
    let payload = Payload {
        msg: plaintext,
        aad: &associated_data,
    };

    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| StreamingError::AuthenticationFailed)
}

pub(crate) fn decrypt_record(
    key: &[u8; 32],
    header: &Header,
    record_header: &[u8; RECORD_HEADER_LEN],
    context: super::StreamContext<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, StreamingError> {
    let nonce = nonce(header, record_header)?;
    let associated_data = associated_data(context, header, record_header);
    let payload = Payload {
        msg: ciphertext,
        aad: &associated_data,
    };

    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| StreamingError::AuthenticationFailed)
}
