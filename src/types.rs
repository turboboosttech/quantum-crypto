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

use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_mlkem::mlkem1024::{PublicKey as KyberPublicKey, SecretKey as KyberSecretKey};
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey},
    sign::{PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::KeyError;
use crate::asymmetric::ml_dsa::{
    MLDSA44_PUBLIC_KEY_LENGTH, MLDSA44_SECRET_KEY_LENGTH, MLDSA65_PUBLIC_KEY_LENGTH,
    MLDSA65_SECRET_KEY_LENGTH, MLDSA87_PUBLIC_KEY_LENGTH, MLDSA87_SECRET_KEY_LENGTH,
};
use crate::asymmetric::ml_kem::{MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM1024_SECRET_KEY_LENGTH};

#[derive(Clone)]
pub enum DilithiumPublicKey {
    V2(Box<mldsa44::PublicKey>),
    V3(Box<mldsa65::PublicKey>),
    V5(Box<mldsa87::PublicKey>),
}

impl fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2(_) => write!(f, "DilithiumPublicKey::V2(...)"),
            Self::V3(_) => write!(f, "DilithiumPublicKey::V3(...)"),
            Self::V5(_) => write!(f, "DilithiumPublicKey::V5(...)"),
        }
    }
}

#[derive(Clone)]
pub enum DilithiumSecretKey {
    V2(Box<mldsa44::SecretKey>),
    V3(Box<mldsa65::SecretKey>),
    V5(Box<mldsa87::SecretKey>),
}

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2(_) => write!(f, "DilithiumSecretKey::V2(...)"),
            Self::V3(_) => write!(f, "DilithiumSecretKey::V3(...)"),
            Self::V5(_) => write!(f, "DilithiumSecretKey::V5(...)"),
        }
    }
}

impl SignPublicKeyTrait for DilithiumPublicKey {
    fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumPublicKey::V2(pk) => pk.as_bytes(),
            DilithiumPublicKey::V3(pk) => pk.as_bytes(),
            DilithiumPublicKey::V5(pk) => pk.as_bytes(),
        }
    }

    fn from_bytes(_bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
        Err(pqcrypto_traits::Error::BadLength {
            name: "DilithiumPublicKey",
            actual: _bytes.len(),
            expected: 0, // We don't have a single expected length
        })
    }
}

impl SignSecretKeyTrait for DilithiumSecretKey {
    fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumSecretKey::V2(sk) => sk.as_bytes(),
            DilithiumSecretKey::V3(sk) => sk.as_bytes(),
            DilithiumSecretKey::V5(sk) => sk.as_bytes(),
        }
    }

    fn from_bytes(_bytes: &[u8]) -> Result<Self, pqcrypto_traits::Error> {
        Err(pqcrypto_traits::Error::BadLength {
            name: "DilithiumSecretKey",
            actual: _bytes.len(),
            expected: 0, // We don't have a single expected length
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CombinedPublicKey {
    #[serde(with = "crate::serialization::key_bytes")]
    kyber: Vec<u8>,
    #[serde(with = "self::serde_option_dilithium")]
    dilithium: Option<(DilithiumVersion, Vec<u8>)>,
}

#[derive(Clone, Serialize)]
pub struct CombinedSecretKey {
    #[serde(with = "crate::serialization::key_bytes")]
    kyber: Vec<u8>,
    #[serde(with = "self::serde_option_dilithium")]
    dilithium: Option<(DilithiumVersion, Vec<u8>)>,
}

#[derive(Deserialize)]
struct CombinedPublicKeyWire {
    #[serde(deserialize_with = "crate::serialization::public_key_bytes::deserialize")]
    kyber: Vec<u8>,
    #[serde(deserialize_with = "self::serde_option_dilithium::deserialize_public")]
    dilithium: Option<(DilithiumVersion, Vec<u8>)>,
}

#[derive(Deserialize)]
struct CombinedSecretKeyWire {
    #[serde(deserialize_with = "crate::serialization::secret_key_bytes::deserialize")]
    kyber: Zeroizing<Vec<u8>>,
    #[serde(deserialize_with = "self::serde_option_dilithium::deserialize_secret")]
    dilithium: Option<(DilithiumVersion, Zeroizing<Vec<u8>>)>,
}

impl<'de> Deserialize<'de> for CombinedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CombinedPublicKeyWire::deserialize(deserializer)?;
        if wire.kyber.len() != MLKEM1024_PUBLIC_KEY_LENGTH {
            return Err(serde::de::Error::custom("invalid ML-KEM public key length"));
        }
        if let Some((version, bytes)) = &wire.dilithium {
            if bytes.len() != version.public_key_length() {
                return Err(serde::de::Error::custom("invalid ML-DSA public key length"));
            }
        }
        Ok(Self {
            kyber: wire.kyber,
            dilithium: wire.dilithium,
        })
    }
}

impl<'de> Deserialize<'de> for CombinedSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut wire = CombinedSecretKeyWire::deserialize(deserializer)?;
        if wire.kyber.len() != MLKEM1024_SECRET_KEY_LENGTH {
            return Err(serde::de::Error::custom("invalid ML-KEM secret key length"));
        }
        if let Some((version, bytes)) = &wire.dilithium {
            if bytes.len() != version.secret_key_length() {
                return Err(serde::de::Error::custom("invalid ML-DSA secret key length"));
            }
        }

        let kyber = std::mem::take(&mut *wire.kyber);
        let dilithium = wire
            .dilithium
            .as_mut()
            .map(|(version, bytes)| (*version, std::mem::take(&mut **bytes)));
        Ok(Self { kyber, dilithium })
    }
}

impl fmt::Debug for CombinedSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CombinedSecretKey")
            .field(
                "kyber",
                &format_args!("<redacted: {} bytes>", self.kyber.len()),
            )
            .field(
                "dilithium",
                &self.dilithium.as_ref().map(|(version, bytes)| {
                    format_args!("<redacted: {:?}, {} bytes>", version, bytes.len()).to_string()
                }),
            )
            .finish()
    }
}

impl Zeroize for CombinedSecretKey {
    fn zeroize(&mut self) {
        self.kyber.zeroize();
        if let Some((_, ref mut bytes)) = self.dilithium {
            bytes.zeroize();
        }
    }
}

impl Drop for CombinedSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CombinedPublicKey {
    pub fn new(
        kyber: KyberPublicKey,
        dilithium: Option<DilithiumPublicKey>,
    ) -> Result<Self, KeyError> {
        let kyber_bytes = kyber.as_bytes();
        if kyber_bytes.len() != MLKEM1024_PUBLIC_KEY_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_PUBLIC_KEY_LENGTH,
                actual: kyber_bytes.len(),
            });
        }

        let dilithium_bytes = if let Some(dilithium_key) = dilithium {
            let (version, bytes) = match dilithium_key {
                DilithiumPublicKey::V2(pk) => {
                    let bytes = pk.as_bytes().to_vec();
                    if bytes.len() != MLDSA44_PUBLIC_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA44_PUBLIC_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V2, bytes)
                }
                DilithiumPublicKey::V3(pk) => {
                    let bytes = pk.as_bytes().to_vec();
                    if bytes.len() != MLDSA65_PUBLIC_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA65_PUBLIC_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V3, bytes)
                }
                DilithiumPublicKey::V5(pk) => {
                    let bytes = pk.as_bytes().to_vec();
                    if bytes.len() != MLDSA87_PUBLIC_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA87_PUBLIC_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V5, bytes)
                }
            };
            Some((version, bytes))
        } else {
            None
        };

        Ok(Self {
            kyber: kyber_bytes.to_vec(),
            dilithium: dilithium_bytes,
        })
    }

    pub fn kyber(&self) -> Result<KyberPublicKey, KeyError> {
        if self.kyber.len() != MLKEM1024_PUBLIC_KEY_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_PUBLIC_KEY_LENGTH,
                actual: self.kyber.len(),
            });
        }
        KyberPublicKey::from_bytes(&self.kyber).map_err(|_| KeyError::DeserializationError)
    }

    pub fn ml_kem(&self) -> Result<KyberPublicKey, KeyError> {
        self.kyber()
    }

    pub fn dilithium(&self) -> Result<Option<DilithiumPublicKey>, KeyError> {
        match &self.dilithium {
            Some((version, bytes)) => {
                let pk = match version {
                    DilithiumVersion::V2 => {
                        if bytes.len() != MLDSA44_PUBLIC_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA44_PUBLIC_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumPublicKey::V2(Box::new(
                            mldsa44::PublicKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                    DilithiumVersion::V3 => {
                        if bytes.len() != MLDSA65_PUBLIC_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA65_PUBLIC_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumPublicKey::V3(Box::new(
                            mldsa65::PublicKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                    DilithiumVersion::V5 => {
                        if bytes.len() != MLDSA87_PUBLIC_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA87_PUBLIC_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumPublicKey::V5(Box::new(
                            mldsa87::PublicKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                };
                Ok(Some(pk))
            }
            None => Ok(None),
        }
    }

    pub fn ml_dsa(&self) -> Result<Option<DilithiumPublicKey>, KeyError> {
        self.dilithium()
    }
}

impl CombinedSecretKey {
    pub fn new(
        kyber: KyberSecretKey,
        dilithium: Option<DilithiumSecretKey>,
    ) -> Result<Self, KeyError> {
        let kyber_bytes = kyber.as_bytes();
        if kyber_bytes.len() != MLKEM1024_SECRET_KEY_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_SECRET_KEY_LENGTH,
                actual: kyber_bytes.len(),
            });
        }

        let dilithium_bytes = if let Some(dilithium_key) = dilithium {
            let (version, bytes) = match dilithium_key {
                DilithiumSecretKey::V2(ref sk) => {
                    let bytes = sk.as_bytes().to_vec();
                    if bytes.len() != MLDSA44_SECRET_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA44_SECRET_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V2, bytes)
                }
                DilithiumSecretKey::V3(ref sk) => {
                    let bytes = sk.as_bytes().to_vec();
                    if bytes.len() != MLDSA65_SECRET_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA65_SECRET_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V3, bytes)
                }
                DilithiumSecretKey::V5(ref sk) => {
                    let bytes = sk.as_bytes().to_vec();
                    if bytes.len() != MLDSA87_SECRET_KEY_LENGTH {
                        return Err(KeyError::InvalidLength {
                            expected: MLDSA87_SECRET_KEY_LENGTH,
                            actual: bytes.len(),
                        });
                    }
                    (DilithiumVersion::V5, bytes)
                }
            };
            Some((version, bytes))
        } else {
            None
        };

        Ok(Self {
            kyber: kyber_bytes.to_vec(),
            dilithium: dilithium_bytes,
        })
    }

    pub fn kyber(&self) -> Result<KyberSecretKey, KeyError> {
        if self.kyber.len() != MLKEM1024_SECRET_KEY_LENGTH {
            return Err(KeyError::InvalidLength {
                expected: MLKEM1024_SECRET_KEY_LENGTH,
                actual: self.kyber.len(),
            });
        }
        KyberSecretKey::from_bytes(&self.kyber).map_err(|_| KeyError::DeserializationError)
    }

    pub fn ml_kem(&self) -> Result<KyberSecretKey, KeyError> {
        self.kyber()
    }

    pub fn dilithium(&self) -> Result<Option<DilithiumSecretKey>, KeyError> {
        match &self.dilithium {
            Some((version, bytes)) => {
                let sk = match version {
                    DilithiumVersion::V2 => {
                        if bytes.len() != MLDSA44_SECRET_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA44_SECRET_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumSecretKey::V2(Box::new(
                            mldsa44::SecretKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                    DilithiumVersion::V3 => {
                        if bytes.len() != MLDSA65_SECRET_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA65_SECRET_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumSecretKey::V3(Box::new(
                            mldsa65::SecretKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                    DilithiumVersion::V5 => {
                        if bytes.len() != MLDSA87_SECRET_KEY_LENGTH {
                            return Err(KeyError::InvalidLength {
                                expected: MLDSA87_SECRET_KEY_LENGTH,
                                actual: bytes.len(),
                            });
                        }
                        DilithiumSecretKey::V5(Box::new(
                            mldsa87::SecretKey::from_bytes(bytes)
                                .map_err(|_| KeyError::DeserializationError)?,
                        ))
                    }
                };
                Ok(Some(sk))
            }
            None => Ok(None),
        }
    }

    pub fn ml_dsa(&self) -> Result<Option<DilithiumSecretKey>, KeyError> {
        self.dilithium()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumVersion {
    V2,
    V3,
    V5,
}

impl DilithiumVersion {
    fn public_key_length(self) -> usize {
        match self {
            Self::V2 => MLDSA44_PUBLIC_KEY_LENGTH,
            Self::V3 => MLDSA65_PUBLIC_KEY_LENGTH,
            Self::V5 => MLDSA87_PUBLIC_KEY_LENGTH,
        }
    }

    fn secret_key_length(self) -> usize {
        match self {
            Self::V2 => MLDSA44_SECRET_KEY_LENGTH,
            Self::V3 => MLDSA65_SECRET_KEY_LENGTH,
            Self::V5 => MLDSA87_SECRET_KEY_LENGTH,
        }
    }
}

pub mod serde_option_dilithium {
    use super::DilithiumVersion;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    type SecretDilithium = Option<(DilithiumVersion, Zeroizing<Vec<u8>>)>;

    pub fn serialize<S>(
        value: &Option<(DilithiumVersion, Vec<u8>)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some((version, bytes)) => {
                let mut combined = Zeroizing::new(Vec::with_capacity(1 + bytes.len()));
                combined.push(match version {
                    DilithiumVersion::V2 => 2,
                    DilithiumVersion::V3 => 3,
                    DilithiumVersion::V5 => 5,
                });
                combined.extend(bytes);
                serializer.serialize_some(combined.as_slice())
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<(DilithiumVersion, Vec<u8>)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<Vec<u8>>::deserialize(deserializer)?;
        match opt {
            Some(mut bytes) => {
                if bytes.is_empty() {
                    return Err(serde::de::Error::custom("empty Dilithium key"));
                }
                let version_byte = bytes.remove(0);
                let version = match version_byte {
                    2 => DilithiumVersion::V2,
                    3 => DilithiumVersion::V3,
                    5 => DilithiumVersion::V5,
                    _ => return Err(serde::de::Error::custom("invalid Dilithium version")),
                };
                Ok(Some((version, bytes)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn deserialize_public<'de, D>(
        deserializer: D,
    ) -> Result<Option<(DilithiumVersion, Vec<u8>)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionVisitor;

        impl<'de> serde::de::Visitor<'de> for OptionVisitor {
            type Value = Option<Vec<u8>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an optional ML-DSA public key")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                crate::serialization::public_dilithium_bytes::deserialize(deserializer).map(Some)
            }
        }

        let opt = deserializer.deserialize_option(OptionVisitor)?;
        decode_public(opt)
    }

    pub(crate) fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretDilithium, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionVisitor;

        impl<'de> serde::de::Visitor<'de> for OptionVisitor {
            type Value = SecretDilithium;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an optional ML-DSA secret key")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes =
                    crate::serialization::secret_dilithium_bytes::deserialize(deserializer)?;
                decode_secret::<D::Error>(bytes).map(Some)
            }
        }

        deserializer.deserialize_option(OptionVisitor)
    }

    fn decode_public<E>(opt: Option<Vec<u8>>) -> Result<Option<(DilithiumVersion, Vec<u8>)>, E>
    where
        E: serde::de::Error,
    {
        match opt {
            Some(mut bytes) => {
                if bytes.is_empty() {
                    return Err(E::custom("empty Dilithium key"));
                }
                let version_byte = bytes.remove(0);
                Ok(Some((decode_version::<E>(version_byte)?, bytes)))
            }
            None => Ok(None),
        }
    }

    fn decode_secret<E>(
        mut bytes: Zeroizing<Vec<u8>>,
    ) -> Result<(DilithiumVersion, Zeroizing<Vec<u8>>), E>
    where
        E: serde::de::Error,
    {
        if bytes.is_empty() {
            return Err(E::custom("empty Dilithium key"));
        }
        bytes.rotate_left(1);
        let version_byte = bytes
            .pop()
            .ok_or_else(|| E::custom("empty Dilithium key"))?;
        Ok((decode_version::<E>(version_byte)?, bytes))
    }

    fn decode_version<E>(version: u8) -> Result<DilithiumVersion, E>
    where
        E: serde::de::Error,
    {
        match version {
            2 => Ok(DilithiumVersion::V2),
            3 => Ok(DilithiumVersion::V3),
            5 => Ok(DilithiumVersion::V5),
            _ => Err(E::custom("invalid Dilithium version")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2idParams {
    pub const SERIALIZED_LEN: usize = 12;
    const MIN_M_COST: u32 = 8; // 8 KiB minimum
    const MAX_M_COST: u32 = 1_048_576; // 1 GiB maximum
    const MIN_T_COST: u32 = 1;
    const MAX_T_COST: u32 = 16;
    const MIN_P_COST: u32 = 1;
    const MAX_P_COST: u32 = 64;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.m_cost < Self::MIN_M_COST {
            return Err("Memory cost too low");
        }
        if self.m_cost > Self::MAX_M_COST {
            return Err("Memory cost too high");
        }

        if self.t_cost < Self::MIN_T_COST {
            return Err("Time cost too low");
        }
        if self.t_cost > Self::MAX_T_COST {
            return Err("Time cost too high");
        }

        if self.p_cost < Self::MIN_P_COST {
            return Err("Parallelism too low");
        }
        if self.p_cost > Self::MAX_P_COST {
            return Err("Parallelism too high");
        }

        if self.m_cost < 8 * self.p_cost {
            return Err("Memory cost must be at least 8 times parallelism");
        }

        Ok(())
    }

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, &'static str> {
        let params = Self {
            m_cost,
            t_cost,
            p_cost,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn to_le_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0u8; Self::SERIALIZED_LEN];
        bytes[0..4].copy_from_slice(&self.m_cost.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.p_cost.to_le_bytes());
        bytes
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err("Invalid Argon2id parameter length");
        }

        let params = Self {
            m_cost: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            t_cost: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            p_cost: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        };
        params.validate()?;
        Ok(params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Argon2idPresetInfo {
    pub preset: Argon2idPreset,
    pub name: &'static str,
    pub memory: &'static str,
    pub memory_mib: u32,
    pub params: Argon2idParams,
    pub target_use_case: &'static str,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Argon2idPreset {
    Low,
    #[default]
    Medium,
    High,
    Maximum,
    Custom(Argon2idParams),
}

#[derive(Debug)]
pub struct RootKeyResult {
    pub key: Zeroizing<Vec<u8>>,
    pub source: RootKeySource,
}

impl RootKeyResult {
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn source(&self) -> &RootKeySource {
        &self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootKeySource {
    MlKem {
        ciphertext: Vec<u8>,
    },
    Argon2id {
        salt: Vec<u8>,
        params: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct Argon2idKeyResult {
    pub key: Zeroizing<Vec<u8>>,
    pub salt: Vec<u8>,
    pub params: Vec<u8>,
}
