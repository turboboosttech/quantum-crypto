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

## Audits

Public audit reports, when available, are published in [`audits/`](audits/).

## Security

Report security issues according to [`SECURITY.md`](SECURITY.md).

## License

This project is source-available under the Business Source License 1.1. See [`LICENSE`](licensing/LICENSE).
