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

mod protocol;

use protocol::{HEADER_LEN, Header, RECORD_HEADER_LEN, TAG_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::errors::StreamingError;

pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
pub const MIN_CHUNK_SIZE: u32 = 64 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct StreamContext<'a> {
    pub domain: &'a [u8],
    pub aad: &'a [u8],
}

pub struct EncryptStreamConfig<'a> {
    pub total_length: u64,
    pub context: StreamContext<'a>,
    pub chunk_size: u32,
    pub cancellation: CancellationToken,
}

impl<'a> EncryptStreamConfig<'a> {
    pub fn new(total_length: u64, context: StreamContext<'a>) -> Self {
        Self {
            total_length,
            context,
            chunk_size: DEFAULT_CHUNK_SIZE,
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_chunk_size(mut self, size: u32) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = token;
        self
    }
}

pub struct DecryptStreamConfig<'a> {
    pub context: StreamContext<'a>,
    pub cancellation: CancellationToken,
}

impl<'a> DecryptStreamConfig<'a> {
    pub fn new(context: StreamContext<'a>) -> Self {
        Self {
            context,
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = token;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSummary {
    pub plaintext_bytes: u64,
    pub records: u64,
}

fn check_cancellation(token: &CancellationToken) -> Result<(), StreamingError> {
    if token.is_cancelled() {
        Err(StreamingError::Cancelled)
    } else {
        Ok(())
    }
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    bytes: &mut [u8],
) -> Result<(), StreamingError> {
    reader.read_exact(bytes).await.map(|_| ()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            StreamingError::Truncated
        } else {
            StreamingError::Io(error)
        }
    })
}

pub async fn encrypt_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    root_key: &[u8; 32],
    config: EncryptStreamConfig<'_>,
) -> Result<StreamSummary, StreamingError> {
    protocol::validate_context(config.context.domain, config.context.aad)?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&config.chunk_size) {
        return Err(StreamingError::InvalidChunkSize);
    }
    check_cancellation(&config.cancellation)?;

    let header = Header::generate(config.chunk_size, config.total_length)?;
    let key = protocol::derive_key(root_key, &header)?;
    writer.write_all(&header.bytes).await?;

    let mut plaintext_bytes = 0u64;
    let mut sequence = 0u64;

    loop {
        check_cancellation(&config.cancellation)?;

        let remaining = config
            .total_length
            .checked_sub(plaintext_bytes)
            .ok_or(StreamingError::CounterOverflow)?;
        let plaintext_length = remaining.min(u64::from(config.chunk_size));
        let final_record = remaining <= u64::from(config.chunk_size);
        let buffer_length =
            usize::try_from(plaintext_length).map_err(|_| StreamingError::CounterOverflow)?;
        let mut plaintext = Zeroizing::new(vec![0; buffer_length]);

        if let Err(error) = reader.read_exact(plaintext.as_mut_slice()).await {
            return if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Err(StreamingError::LengthMismatch)
            } else {
                Err(StreamingError::Io(error))
            };
        }

        if final_record {
            let mut probe = Zeroizing::new([0]);
            if reader.read(probe.as_mut()).await? != 0 {
                return Err(StreamingError::LengthExceeded);
            }
        }

        let record_header =
            protocol::record_header(sequence, plaintext_length as u32, final_record);
        let ciphertext = protocol::encrypt_record(
            &key,
            &header,
            &record_header,
            config.context,
            plaintext.as_ref(),
        )?;
        writer.write_all(&record_header).await?;
        writer.write_all(&ciphertext).await?;

        plaintext_bytes = plaintext_bytes
            .checked_add(plaintext_length)
            .ok_or(StreamingError::CounterOverflow)?;
        sequence = sequence
            .checked_add(1)
            .ok_or(StreamingError::CounterOverflow)?;

        if final_record {
            break;
        }
    }

    check_cancellation(&config.cancellation)?;
    writer.flush().await?;

    Ok(StreamSummary {
        plaintext_bytes,
        records: sequence,
    })
}

pub async fn decrypt_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut staging_writer: W,
    root_key: &[u8; 32],
    config: DecryptStreamConfig<'_>,
) -> Result<StreamSummary, StreamingError> {
    protocol::validate_context(config.context.domain, config.context.aad)?;
    check_cancellation(&config.cancellation)?;

    let mut header_bytes = [0; HEADER_LEN];
    read_exact(&mut reader, &mut header_bytes).await?;
    let header = Header::parse(header_bytes)?;
    let key = protocol::derive_key(root_key, &header)?;
    let mut plaintext_bytes = 0u64;
    let mut expected_sequence = 0u64;

    loop {
        check_cancellation(&config.cancellation)?;

        let mut record_header = [0; RECORD_HEADER_LEN];
        read_exact(&mut reader, &mut record_header).await?;
        let (sequence, plaintext_length, final_record) =
            protocol::parse_record_header(&record_header)?;

        if sequence != expected_sequence {
            return Err(StreamingError::SequenceMismatch);
        }
        if plaintext_length > header.chunk_size {
            return Err(StreamingError::InvalidRecord);
        }

        let remaining = header
            .total_length
            .checked_sub(plaintext_bytes)
            .ok_or(StreamingError::LengthExceeded)?;
        if u64::from(plaintext_length) > remaining {
            return Err(StreamingError::LengthExceeded);
        }

        let should_be_final = remaining <= u64::from(header.chunk_size);
        if final_record != should_be_final {
            return Err(StreamingError::LengthMismatch);
        }
        if !final_record && plaintext_length != header.chunk_size {
            return Err(StreamingError::InvalidRecord);
        }
        if final_record && u64::from(plaintext_length) != remaining {
            return Err(StreamingError::LengthMismatch);
        }

        let ciphertext_length = usize::try_from(plaintext_length)
            .map_err(|_| StreamingError::CounterOverflow)?
            .checked_add(TAG_LEN)
            .ok_or(StreamingError::CounterOverflow)?;
        let mut ciphertext = vec![0; ciphertext_length];
        read_exact(&mut reader, &mut ciphertext).await?;

        let plaintext = Zeroizing::new(protocol::decrypt_record(
            &key,
            &header,
            &record_header,
            config.context,
            &ciphertext,
        )?);
        check_cancellation(&config.cancellation)?;
        staging_writer.write_all(plaintext.as_ref()).await?;

        plaintext_bytes = plaintext_bytes
            .checked_add(u64::from(plaintext_length))
            .ok_or(StreamingError::CounterOverflow)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(StreamingError::CounterOverflow)?;

        if final_record {
            let mut probe = [0];
            if reader.read(&mut probe).await? != 0 {
                return Err(StreamingError::TrailingData);
            }
            break;
        }
    }

    if plaintext_bytes != header.total_length {
        return Err(StreamingError::LengthMismatch);
    }

    check_cancellation(&config.cancellation)?;
    staging_writer.flush().await?;

    Ok(StreamSummary {
        plaintext_bytes,
        records: expected_sequence,
    })
}
