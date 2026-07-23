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
use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;
use zeroize::Zeroizing;

pub mod key_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bytes::<D, 4897>(deserializer)
    }
}

pub(crate) mod public_key_bytes {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bytes::<D, 1568>(deserializer)
    }
}

pub(crate) mod secret_key_bytes {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_secret_bytes::<D, 3168>(deserializer)
    }
}

pub(crate) mod public_dilithium_bytes {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bytes::<D, 2593>(deserializer)
    }
}

pub(crate) mod secret_dilithium_bytes {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_secret_bytes::<D, 4897>(deserializer)
    }
}

fn deserialize_bytes<'de, D, const MAX: usize>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BytesVisitor::<MAX>)
}

fn deserialize_secret_bytes<'de, D, const MAX: usize>(
    deserializer: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(SecretBytesVisitor::<MAX>)
}

struct BytesVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BytesVisitor<MAX> {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX} key bytes")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if bytes.len() > MAX {
            return Err(E::custom("encoded key exceeds maximum length"));
        }
        Ok(bytes.to_vec())
    }

    fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_bytes(bytes)
    }

    fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if bytes.len() > MAX {
            return Err(E::custom("encoded key exceeds maximum length"));
        }
        Ok(bytes)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = bounded_capacity::<A::Error, MAX>(sequence.size_hint())?;
        let mut bytes = Vec::with_capacity(capacity);
        while let Some(byte) = sequence.next_element()? {
            if bytes.len() == MAX {
                return Err(A::Error::custom("encoded key exceeds maximum length"));
            }
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

struct SecretBytesVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for SecretBytesVisitor<MAX> {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX} secret key bytes")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if bytes.len() > MAX {
            return Err(E::custom("encoded secret key exceeds maximum length"));
        }
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_bytes(bytes)
    }

    fn visit_byte_buf<E>(self, mut bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if bytes.len() > MAX {
            use zeroize::Zeroize;
            bytes.zeroize();
            return Err(E::custom("encoded secret key exceeds maximum length"));
        }
        Ok(Zeroizing::new(bytes))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = bounded_capacity::<A::Error, MAX>(sequence.size_hint())?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        while let Some(byte) = sequence.next_element()? {
            if bytes.len() == MAX {
                return Err(A::Error::custom(
                    "encoded secret key exceeds maximum length",
                ));
            }
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

fn bounded_capacity<E, const MAX: usize>(size_hint: Option<usize>) -> Result<usize, E>
where
    E: Error,
{
    match size_hint {
        Some(size) if size > MAX => Err(E::custom("encoded key exceeds maximum length")),
        Some(size) => Ok(size),
        None => Ok(0),
    }
}
