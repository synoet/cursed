use crate::crypto::{Ed25519Pk, Ed25519Sig, Nonce24, X25519Pk};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct TomeId(pub Uuid);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RuneId(pub Uuid);

pub struct Tome {
    pub id: TomeId,
    pub name: Option<String>,
    pub rune_headers: HashMap<RuneId, RuneHeader>,
    pub rune_contents: HashMap<RuneId, Vec<u8>>,
}

/// Small metadata that travels with each encrypted block.
/// Doesn't reveal content, but shows people how to interact with block
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuneHeader {
    /// Uuid of the tome that this rune belongs to
    pub tome_id: TomeId,
    /// Uuid of the rune itself
    pub rune_id: RuneId,
    /// Public Signing Key of the keeper that created this rune
    /// This should be used to verify the authenticity of
    /// messages relating to this rune
    pub keeper_signing_pk: Ed25519Pk,
    /// Length of the content of the rune
    pub content_len: u32,
    /// Nonce used to encrypt the content of the rune
    pub nonce: Nonce24,
    pub content_type: String,
    pub epoch: u32,
    /// Digest of the content of the rune
    pub digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct RuneAnnounce {
    pub header: RuneHeader,
    /// The keeper's signature of the header
    /// Uses the keepers signing private key to sign the header
    /// Recipients can use the `keeper_signing_pk` to verify the signature
    pub keeper_sig: Ed25519Sig,
    /// Number of expected chunks for the rune
    pub total_chunks: u32,
}

#[derive(Serialize, Deserialize)]
pub struct RuneChunk {
    pub block_id: Uuid,
    pub idx: u32,
    pub chunk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct UnlockRequest {
    pub tome_id: TomeId,
    pub rune_id: RuneId,
    /// The requester's public assymetric signing key
    /// The recipient keeper will use this to generate a secret key to
    /// wrap the encrypted rune key
    pub requester_pk_x25519: X25519Pk,
    /// The requester's public assymteric signing key
    /// Can be used in the future to verify the requester's identity
    /// or block them from requesting this rune ?
    pub requester_pk_ed25519: Ed25519Pk,
    pub keeper_pk_ed25519: Ed25519Pk,
}

#[derive(Serialize, Deserialize)]
pub struct UnlockGrant {
    pub rune_id: RuneId,
    /// This is an ephemeral public key of the owner's keeper's encryption key
    /// The keeper who requested the rune, will use this to generate a secret key
    /// to unwrap the encrypted rune key `wrapped_kb`
    ///This key is ephemeral, to protect past communications.
    pub eph_pk_x25519: X25519Pk,
    /// The rune key used to encrypt the content of the rune is encrypted and wrapped
    /// using the secret key generated with the requester's public key and the keeper's secret key
    pub wrapped_kb: Vec<u8>,
    pub wrapped_nonce: Nonce24,
    /// Verify the authenticity of the wrapped key
    pub wrapped_sig: Ed25519Sig,
    /// The requester's public assymteric signing key
    pub requester_pk_ed25519: Ed25519Pk,
}

#[derive(Serialize, Deserialize)]
pub enum Frame {
    Announce(RuneAnnounce),
    Chunk(RuneChunk),
    UnlockRequest(UnlockRequest),
    UnlockGrant(UnlockGrant),
}

impl Frame {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
