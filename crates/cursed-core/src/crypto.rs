use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CryptoKey<const N: usize>(#[serde(with = "serde_bytes")] pub [u8; N]);

pub type Ed25519Pk = CryptoKey<32>;
pub type Ed25519Sig = CryptoKey<64>;
pub type X25519Pk = CryptoKey<32>;
pub type Nonce24 = CryptoKey<24>;
pub type SymmetricKey = CryptoKey<32>;

pub const XCHACHA20_NONCE_SIZE: usize = 24;
pub const ED25519_KEY_SIZE: usize = 32;
pub const ED25519_SIG_SIZE: usize = 64;

pub struct ProtocolNonce<const N: usize>([u8; N]);
pub type XChaCha20Nonce = ProtocolNonce<XCHACHA20_NONCE_SIZE>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

impl<const N: usize> CryptoKey<N> {
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != N {
            return Err(CryptoError::InvalidLength {
                expected: N,
                got: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8; N] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| CryptoError::InvalidLength {
                expected: N,
                got: s.len(),
            })?;
        Self::try_from_slice(&bytes)
    }
}

impl<const N: usize> Deref for CryptoKey<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
