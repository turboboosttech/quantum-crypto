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
use quantum_crypto::{
    DEFAULT_CHUNK_SIZE, DecryptStreamConfig, EncryptStreamConfig, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    StreamContext, StreamingError, decrypt_stream, encrypt_stream,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

const HEADER: usize = 64;
const RH: usize = 16;
const TAG: usize = 16;
const KEY: [u8; 32] = [3; 32];
fn context<'a>() -> StreamContext<'a> {
    StreamContext {
        domain: b"test.object",
        aad: b"identity",
    }
}
async fn encrypt(plain: &[u8], chunk: u32) -> Vec<u8> {
    let mut wire = Vec::new();
    encrypt_stream(
        plain,
        &mut wire,
        &KEY,
        EncryptStreamConfig::new(plain.len() as u64, context()).with_chunk_size(chunk),
    )
    .await
    .unwrap();
    wire
}
async fn error(wire: &[u8]) -> StreamingError {
    decrypt_stream(wire, Vec::new(), &KEY, DecryptStreamConfig::new(context()))
        .await
        .unwrap_err()
}
fn first_record_len(wire: &[u8]) -> usize {
    u32::from_le_bytes(wire[HEADER + 8..HEADER + 12].try_into().unwrap()) as usize
}
fn records(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = HEADER;
    while offset < wire.len() {
        let len = u32::from_le_bytes(wire[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let end = offset + RH + len + TAG;
        out.push(wire[offset..end].to_vec());
        offset = end;
    }
    out
}

#[tokio::test]
async fn wire_vector_is_canonical() {
    let wire = encrypt(b"abc", MIN_CHUNK_SIZE).await;
    assert_eq!(&wire[..8], b"QCSTREAM");
    assert_eq!(&wire[8..12], &[1, 0, 1, 0]);
    assert_eq!(&wire[12..16], &[0; 4]);
    assert_eq!(
        u32::from_le_bytes(wire[16..20].try_into().unwrap()),
        MIN_CHUNK_SIZE
    );
    assert_eq!(&wire[20..24], &[0; 4]);
    assert_eq!(u64::from_le_bytes(wire[24..32].try_into().unwrap()), 3);
    assert_ne!(&wire[32..48], &[0; 16]);
    assert_ne!(&wire[48..64], &[0; 16]);
    assert_eq!(&wire[64..72], &[0; 8]);
    assert_eq!(first_record_len(&wire), 3);
    assert_eq!(wire[76], 1);
    assert_eq!(&wire[77..80], &[0; 3]);
}

#[tokio::test]
async fn round_trip_lengths_0_1_chunk_minus_1_chunk_chunk_plus_1_and_multi() {
    for length in [
        0,
        1,
        MIN_CHUNK_SIZE - 1,
        MIN_CHUNK_SIZE,
        MIN_CHUNK_SIZE + 1,
        MIN_CHUNK_SIZE * 2 + 7,
    ] {
        let plain = vec![7; length as usize];
        let wire = encrypt(&plain, MIN_CHUNK_SIZE).await;
        let mut output = Vec::new();
        let summary = decrypt_stream(
            wire.as_slice(),
            &mut output,
            &KEY,
            DecryptStreamConfig::new(context()),
        )
        .await
        .unwrap();
        assert_eq!(plain, output);
        assert_eq!(summary.plaintext_bytes, length as u64);
    }
}

#[test]
fn default_chunk_is_4_mib() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 4 * 1024 * 1024);
}

#[tokio::test]
async fn custom_chunk_bounds() {
    for size in [0, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, u32::MAX] {
        assert!(matches!(
            encrypt_stream(
                &[][..],
                Vec::new(),
                &KEY,
                EncryptStreamConfig::new(0, context()).with_chunk_size(size)
            )
            .await,
            Err(StreamingError::InvalidChunkSize)
        ));
    }
    for size in [MIN_CHUNK_SIZE, MAX_CHUNK_SIZE] {
        assert!(
            encrypt_stream(
                &[][..],
                Vec::new(),
                &KEY,
                EncryptStreamConfig::new(0, context()).with_chunk_size(size)
            )
            .await
            .is_ok()
        );
    }
}

#[tokio::test]
async fn rejects_short_and_long_plaintext() {
    assert!(matches!(
        encrypt_stream(
            &b"x"[..],
            Vec::new(),
            &KEY,
            EncryptStreamConfig::new(2, context())
        )
        .await,
        Err(StreamingError::LengthMismatch)
    ));
    let mut overlength_wire = Vec::new();
    assert!(matches!(
        encrypt_stream(
            &b"xx"[..],
            &mut overlength_wire,
            &KEY,
            EncryptStreamConfig::new(1, context())
        )
        .await,
        Err(StreamingError::LengthExceeded)
    ));
    assert!(
        decrypt_stream(
            overlength_wire.as_slice(),
            Vec::new(),
            &KEY,
            DecryptStreamConfig::new(context())
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn rejects_wrong_key_domain_and_aad() {
    let wire = encrypt(b"x", MIN_CHUNK_SIZE).await;
    for (key, ctx) in [
        ([4; 32], context()),
        (
            KEY,
            StreamContext {
                domain: b"wrong",
                aad: b"identity",
            },
        ),
        (
            KEY,
            StreamContext {
                domain: b"test.object",
                aad: b"wrong",
            },
        ),
    ] {
        assert!(matches!(
            decrypt_stream(
                wire.as_slice(),
                Vec::new(),
                &key,
                DecryptStreamConfig::new(ctx)
            )
            .await,
            Err(StreamingError::AuthenticationFailed)
        ));
    }
}

#[tokio::test]
async fn rejects_each_header_field_mutation() {
    let original = encrypt(b"x", MIN_CHUNK_SIZE).await;
    for (index, expected) in [
        (0, StreamingError::InvalidHeader),
        (8, StreamingError::UnsupportedFormat),
        (10, StreamingError::UnsupportedSuite),
        (12, StreamingError::InvalidHeader),
        (16, StreamingError::AuthenticationFailed),
        (20, StreamingError::InvalidHeader),
        (24, StreamingError::LengthExceeded),
        (32, StreamingError::AuthenticationFailed),
        (48, StreamingError::AuthenticationFailed),
    ] {
        let mut wire = original.clone();
        wire[index] ^= 1;
        assert_eq!(
            std::mem::discriminant(&error(&wire).await),
            std::mem::discriminant(&expected),
            "header byte {index} returned the wrong rejection class"
        );
    }
    for range in [32..48, 48..64] {
        let mut wire = original.clone();
        wire[range].fill(0);
        assert!(matches!(error(&wire).await, StreamingError::InvalidHeader));
    }
}

#[tokio::test]
async fn rejects_record_header_reserved_and_unknown_flags() {
    let original = encrypt(b"x", MIN_CHUNK_SIZE).await;
    for index in [76, 77, 78, 79] {
        let mut wire = original.clone();
        wire[index] |= if index == 76 { 2 } else { 1 };
        assert!(matches!(error(&wire).await, StreamingError::InvalidRecord));
    }
}

#[tokio::test]
async fn rejects_ciphertext_and_tag_mutation() {
    let original = encrypt(b"abc", MIN_CHUNK_SIZE).await;
    for index in [HEADER + RH, original.len() - 1] {
        let mut wire = original.clone();
        wire[index] ^= 1;
        assert!(matches!(
            error(&wire).await,
            StreamingError::AuthenticationFailed
        ));
    }
}

#[tokio::test]
async fn rejects_reordered_duplicated_and_missing_records() {
    let original = encrypt(&vec![1; MIN_CHUNK_SIZE as usize + 1], MIN_CHUNK_SIZE).await;
    let rs = records(&original);
    let mut reordered = original[..HEADER].to_vec();
    reordered.extend(&rs[1]);
    reordered.extend(&rs[0]);
    assert!(matches!(
        error(&reordered).await,
        StreamingError::SequenceMismatch
    ));
    let mut duplicate = original[..HEADER].to_vec();
    duplicate.extend(&rs[0]);
    duplicate.extend(&rs[0]);
    duplicate.extend(&rs[1]);
    assert!(matches!(
        error(&duplicate).await,
        StreamingError::SequenceMismatch
    ));
    let mut dropped = original[..HEADER].to_vec();
    dropped.extend(&rs[1]);
    assert!(matches!(
        error(&dropped).await,
        StreamingError::SequenceMismatch
    ));
}

#[tokio::test]
async fn rejects_early_missing_and_duplicate_final() {
    let original = encrypt(&vec![1; MIN_CHUNK_SIZE as usize + 1], MIN_CHUNK_SIZE).await;
    let mut early = original.clone();
    early[76] = 1;
    assert!(matches!(
        error(&early).await,
        StreamingError::LengthMismatch
    ));
    let final_offset = HEADER + RH + MIN_CHUNK_SIZE as usize + TAG;
    let mut missing = original.clone();
    missing[final_offset + 12] = 0;
    assert!(matches!(
        error(&missing).await,
        StreamingError::LengthMismatch
    ));
    let mut duplicate = original.clone();
    duplicate.extend_from_slice(&original[final_offset..]);
    assert!(matches!(
        error(&duplicate).await,
        StreamingError::TrailingData
    ));
}

#[tokio::test]
async fn rejects_truncation_at_every_byte() {
    let wire = encrypt(b"boundary", MIN_CHUNK_SIZE).await;
    for end in 0..wire.len() {
        assert!(matches!(
            error(&wire[..end]).await,
            StreamingError::Truncated
        ));
    }
}

#[tokio::test]
async fn rejects_trailing_byte_and_record() {
    let original = encrypt(b"x", MIN_CHUNK_SIZE).await;
    let mut byte = original.clone();
    byte.push(0);
    assert!(matches!(error(&byte).await, StreamingError::TrailingData));
    let mut record = original.clone();
    record.extend_from_slice(&original[HEADER..]);
    assert!(matches!(error(&record).await, StreamingError::TrailingData));
}

#[tokio::test]
async fn rejects_noncanonical_partial_nonfinal() {
    let mut wire = encrypt(&vec![1; MIN_CHUNK_SIZE as usize + 1], MIN_CHUNK_SIZE).await;
    wire[72..76].copy_from_slice(&(MIN_CHUNK_SIZE - 1).to_le_bytes());
    assert!(matches!(error(&wire).await, StreamingError::InvalidRecord));
}

struct ShortIo {
    data: Vec<u8>,
    pos: usize,
    limit: usize,
    fail_at: Option<usize>,
}
impl AsyncRead for ShortIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.fail_at == Some(self.pos) {
            return Poll::Ready(Err(io::Error::other("injected")));
        }
        if self.pos == self.data.len() {
            return Poll::Ready(Ok(()));
        }
        let n = self
            .limit
            .min(buf.remaining())
            .min(self.data.len() - self.pos);
        buf.put_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ShortIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = self.limit.min(buf.len());
        self.data.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn short_reads_and_writes_round_trip() {
    let plain = vec![5; MIN_CHUNK_SIZE as usize + 3];
    let reader = ShortIo {
        data: plain.clone(),
        pos: 0,
        limit: 3,
        fail_at: None,
    };
    let mut sink = ShortIo {
        data: vec![],
        pos: 0,
        limit: 5,
        fail_at: None,
    };
    encrypt_stream(
        reader,
        &mut sink,
        &KEY,
        EncryptStreamConfig::new(plain.len() as u64, context()).with_chunk_size(MIN_CHUNK_SIZE),
    )
    .await
    .unwrap();
    let reader = ShortIo {
        data: sink.data,
        pos: 0,
        limit: 7,
        fail_at: None,
    };
    let mut output = Vec::new();
    decrypt_stream(
        reader,
        &mut output,
        &KEY,
        DecryptStreamConfig::new(context()),
    )
    .await
    .unwrap();
    assert_eq!(output, plain);
}

#[tokio::test]
async fn preserves_non_eof_io_errors() {
    let reader = ShortIo {
        data: vec![0; 64],
        pos: 0,
        limit: 1,
        fail_at: Some(10),
    };
    assert!(matches!(
        decrypt_stream(
            reader,
            Vec::new(),
            &KEY,
            DecryptStreamConfig::new(context())
        )
        .await,
        Err(StreamingError::Io(_))
    ));
}

#[tokio::test]
async fn cancellation_never_reports_success() {
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        encrypt_stream(
            &[][..],
            Vec::new(),
            &KEY,
            EncryptStreamConfig::new(0, context()).with_cancellation(token.clone())
        )
        .await,
        Err(StreamingError::Cancelled)
    ));
    assert!(matches!(
        decrypt_stream(
            &[][..],
            Vec::new(),
            &KEY,
            DecryptStreamConfig::new(context()).with_cancellation(token)
        )
        .await,
        Err(StreamingError::Cancelled)
    ));
}

#[tokio::test]
async fn does_not_write_unauthenticated_record() {
    let mut wire = encrypt(b"x", MIN_CHUNK_SIZE).await;
    wire[HEADER + RH] ^= 1;
    let mut output = Vec::new();
    assert!(matches!(
        decrypt_stream(
            wire.as_slice(),
            &mut output,
            &KEY,
            DecryptStreamConfig::new(context())
        )
        .await,
        Err(StreamingError::AuthenticationFailed)
    ));
    assert!(output.is_empty());
}

#[tokio::test]
async fn staging_sink_is_not_committed_on_late_failure() {
    let mut wire = encrypt(&vec![1; MIN_CHUNK_SIZE as usize + 1], MIN_CHUNK_SIZE).await;
    *wire.last_mut().unwrap() ^= 1;
    let mut staging = Vec::new();
    assert!(matches!(
        decrypt_stream(
            wire.as_slice(),
            &mut staging,
            &KEY,
            DecryptStreamConfig::new(context())
        )
        .await,
        Err(StreamingError::AuthenticationFailed)
    ));
    assert_eq!(staging.len(), MIN_CHUNK_SIZE as usize);
}
