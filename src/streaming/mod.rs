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
mod protocol;

use crate::errors::StreamingError;
use protocol::{HEADER_LEN, Header, RECORD_HEADER_LEN, TAG_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

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
fn cancelled(token: &CancellationToken) -> Result<(), StreamingError> {
    if token.is_cancelled() {
        Err(StreamingError::Cancelled)
    } else {
        Ok(())
    }
}
async fn exact<R: AsyncRead + Unpin>(r: &mut R, b: &mut [u8]) -> Result<(), StreamingError> {
    r.read_exact(b).await.map(|_| ()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            StreamingError::Truncated
        } else {
            StreamingError::Io(e)
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
    cancelled(&config.cancellation)?;
    let header = Header::generate(config.chunk_size, config.total_length)?;
    let key = protocol::derive_key(root_key, &header)?;
    writer.write_all(&header.bytes).await?;
    let mut done = 0u64;
    let mut sequence = 0u64;
    loop {
        cancelled(&config.cancellation)?;
        let remaining = config
            .total_length
            .checked_sub(done)
            .ok_or(StreamingError::CounterOverflow)?;
        let length = remaining.min(u64::from(config.chunk_size));
        let final_record = remaining <= u64::from(config.chunk_size);
        let size = usize::try_from(length).map_err(|_| StreamingError::CounterOverflow)?;
        let mut plain = Zeroizing::new(vec![0; size]);
        if let Err(e) = reader.read_exact(plain.as_mut()).await {
            return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Err(StreamingError::LengthMismatch)
            } else {
                Err(StreamingError::Io(e))
            };
        }
        if final_record {
            let mut probe = Zeroizing::new([0]);
            if reader.read(probe.as_mut()).await? != 0 {
                return Err(StreamingError::LengthExceeded);
            }
        }
        let rh = protocol::record_header(sequence, length as u32, final_record);
        let encrypted = protocol::crypt(true, &key, &header, &rh, config.context, plain.as_ref())?;
        writer.write_all(&rh).await?;
        writer.write_all(&encrypted).await?;
        done = done
            .checked_add(length)
            .ok_or(StreamingError::CounterOverflow)?;
        sequence = sequence
            .checked_add(1)
            .ok_or(StreamingError::CounterOverflow)?;
        if final_record {
            break;
        }
    }
    cancelled(&config.cancellation)?;
    writer.flush().await?;
    Ok(StreamSummary {
        plaintext_bytes: done,
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
    cancelled(&config.cancellation)?;
    let mut hb = [0; HEADER_LEN];
    exact(&mut reader, &mut hb).await?;
    let header = Header::parse(hb)?;
    let key = protocol::derive_key(root_key, &header)?;
    let mut done = 0u64;
    let mut expected = 0u64;
    loop {
        cancelled(&config.cancellation)?;
        let mut rh = [0; RECORD_HEADER_LEN];
        exact(&mut reader, &mut rh).await?;
        let (sequence, length, final_record) = protocol::parse_record_header(&rh)?;
        if sequence != expected {
            return Err(StreamingError::SequenceMismatch);
        }
        if length > header.chunk_size {
            return Err(StreamingError::InvalidRecord);
        }
        let remaining = header
            .total
            .checked_sub(done)
            .ok_or(StreamingError::LengthExceeded)?;
        if u64::from(length) > remaining {
            return Err(StreamingError::LengthExceeded);
        }
        let should_final = remaining <= u64::from(header.chunk_size);
        if final_record != should_final {
            return Err(StreamingError::LengthMismatch);
        }
        if !final_record && length != header.chunk_size {
            return Err(StreamingError::InvalidRecord);
        }
        if final_record && u64::from(length) != remaining {
            return Err(StreamingError::LengthMismatch);
        }
        let cipher_len = usize::try_from(length)
            .map_err(|_| StreamingError::CounterOverflow)?
            .checked_add(TAG_LEN)
            .ok_or(StreamingError::CounterOverflow)?;
        let mut encrypted = vec![0; cipher_len];
        exact(&mut reader, &mut encrypted).await?;
        let plain = Zeroizing::new(protocol::crypt(
            false,
            &key,
            &header,
            &rh,
            config.context,
            &encrypted,
        )?);
        cancelled(&config.cancellation)?;
        staging_writer.write_all(plain.as_ref()).await?;
        done = done
            .checked_add(u64::from(length))
            .ok_or(StreamingError::CounterOverflow)?;
        expected = expected
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
    if done != header.total {
        return Err(StreamingError::LengthMismatch);
    }
    cancelled(&config.cancellation)?;
    staging_writer.flush().await?;
    Ok(StreamSummary {
        plaintext_bytes: done,
        records: expected,
    })
}
