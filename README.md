# quantum-crypto

Post-quantum and symmetric cryptography for the 9Secure password manager.

## Components

- Argon2id for password-based key derivation
- HKDF-SHA256 for purpose-specific subkeys
- HMAC-SHA256 for container integrity
- XChaCha20-Poly1305 for authenticated encryption
- ML-KEM (FIPS 203) for caller-owned session establishment
- ML-DSA (FIPS 204) for pairing and session transcript authentication
- CSPRNG password generation
- Exact-length authenticated symmetric streaming for finite attachments and sync records

## Authenticated streaming

`encrypt_stream` and `decrypt_stream` accept an existing 32-byte symmetric root key. The wire format is one canonical 64-byte header followed by contiguous authenticated records. The declared plaintext length is exact. The default record plaintext size is 4 MiB, with explicit sizes from 64 KiB through 16 MiB.

Callers provide a domain and canonical object AAD. Use stable, distinct domains such as `9core.vault-attachment` and `9core.sync-record`. Include a unique operation ID or monotonic generation in AAD and reject replay or rollback before committing plaintext. ML-KEM establishment and ML-DSA transcript authentication happen separately. Their ciphertexts and signatures are not embedded in the stream.

Decryption authenticates each record before writing it, but the whole object is valid only after the final record, exact length, and trailing EOF are verified. Write to staging storage, commit or rename only after `decrypt_stream` returns `Ok`, and discard staging output on every error or cancellation. Never decrypt directly into live vault or sync state.

Unlimited sync is represented by any number of independently encrypted finite records, each with a fresh header and stable per-record AAD. Fresh random headers make nonce reuse negligibly likely but do not prevent replay. Interrupted objects restart with a fresh header.

Bound every untrusted encoded key or vault blob before deserialization. Combined-key deserialization validates key lengths, but generic Serde cannot guarantee allocation limits for every format. Enforce device-safe Argon2 reconstruction limits before running the KDF.

See [`src/streaming/README.md`](src/streaming/README.md) and [`spec.md`](spec.md).

## Audits

Public audit reports, when available, are published in [`audits/`](audits/).

## Security

Report security issues according to [`SECURITY.md`](SECURITY.md).

## License

This project is source-available under the Business Source License 1.1. See [`LICENSE`](licensing/LICENSE).
