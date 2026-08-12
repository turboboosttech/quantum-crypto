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
use std::fmt;

use p256::{
    SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::errors::P256Error;

pub const P256_PUBLIC_KEY_LENGTH: usize = 65;
pub const P256_MAX_MESSAGE_SIZE: usize = 10_000_000;

pub struct P256KeyPair {
    private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    public_key_sec1: [u8; P256_PUBLIC_KEY_LENGTH],
}

impl P256KeyPair {
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.private_key_pkcs8_der
    }

    pub const fn public_key_sec1(&self) -> &[u8; P256_PUBLIC_KEY_LENGTH] {
        &self.public_key_sec1
    }

    pub fn into_private_key_pkcs8_der(self) -> Zeroizing<Vec<u8>> {
        self.private_key_pkcs8_der
    }
}

impl fmt::Debug for P256KeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P256KeyPair")
            .field("private_key_pkcs8_der", &"<redacted>")
            .field("public_key_sec1", &self.public_key_sec1)
            .finish()
    }
}

pub fn generate_p256_keypair() -> Result<P256KeyPair, P256Error> {
    let signing_key = SigningKey::random(&mut OsRng);
    let secret_key = SecretKey::from_slice(&signing_key.to_bytes())
        .map_err(|_| P256Error::KeyGenerationFailed)?;
    let private_key = secret_key
        .to_pkcs8_der()
        .map_err(|_| P256Error::KeyGenerationFailed)?;
    let public_key_sec1 = encode_public_key(signing_key.verifying_key())?;

    Ok(P256KeyPair {
        private_key_pkcs8_der: Zeroizing::new(private_key.as_bytes().to_vec()),
        public_key_sec1,
    })
}

pub fn p256_public_key_from_pkcs8(
    private_key_pkcs8_der: &[u8],
) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], P256Error> {
    let signing_key = decode_private_key(private_key_pkcs8_der)?;
    encode_public_key(signing_key.verifying_key())
}

pub fn sign_es256_der(private_key_pkcs8_der: &[u8], message: &[u8]) -> Result<Vec<u8>, P256Error> {
    validate_message_size(message)?;
    let signing_key = decode_private_key(private_key_pkcs8_der)?;
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn verify_es256_der(
    public_key_sec1: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), P256Error> {
    validate_message_size(message)?;

    if public_key_sec1.len() != P256_PUBLIC_KEY_LENGTH || public_key_sec1[0] != 0x04 {
        return Err(P256Error::InvalidPublicKey);
    }

    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| P256Error::InvalidPublicKey)?;
    let signature = Signature::from_der(signature_der).map_err(|_| P256Error::InvalidSignature)?;

    if signature.to_der().as_bytes() != signature_der {
        return Err(P256Error::InvalidSignature);
    }

    verifying_key
        .verify(message, &signature)
        .map_err(|_| P256Error::VerificationFailed)
}

fn decode_private_key(private_key_pkcs8_der: &[u8]) -> Result<SigningKey, P256Error> {
    SigningKey::from_pkcs8_der(private_key_pkcs8_der).map_err(|_| P256Error::InvalidPrivateKey)
}

fn encode_public_key(
    verifying_key: &VerifyingKey,
) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], P256Error> {
    verifying_key
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| P256Error::InvalidPublicKey)
}

fn validate_message_size(message: &[u8]) -> Result<(), P256Error> {
    if message.len() > P256_MAX_MESSAGE_SIZE {
        return Err(P256Error::MessageTooLong {
            size: message.len(),
            max: P256_MAX_MESSAGE_SIZE,
        });
    }

    Ok(())
}
