use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::SignerMut};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, ops::Deref};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{
    crypto::{CryptoKey, Ed25519Pk, Nonce24, SymmetricKey, X25519Pk},
    protocol::{RuneHeader, RuneId, TomeId, UnlockGrant, UnlockRequest},
};

pub struct Keeper {
    signing_key: SigningKey,
    encryption_secret: StaticSecret,
    owned_rune_keys: HashMap<RuneId, SymmetricKey>,
}

#[derive(thiserror::Error, Debug)]
pub enum KeeperError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid key")]
    InvalidKey,
    #[error("missing key")]
    MissingKey,
}

impl Default for Keeper {
    fn default() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let encryption_secret = StaticSecret::random_from_rng(OsRng);

        Self {
            signing_key,
            encryption_secret,
            owned_rune_keys: HashMap::new(),
        }
    }
}

impl Keeper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_rune(
        &mut self,
        tome_id: TomeId,
        content: &[u8],
    ) -> Result<(RuneHeader, Vec<u8>), KeeperError> {
        let rune_id = RuneId(Uuid::new_v4());
        let rune_key: SymmetricKey = SymmetricKey::generate();
        let nonce = Nonce24::generate();
        let cipher = XChaCha20Poly1305::new(rune_key.deref().into());
        let encrypted = cipher
            .encrypt(XNonce::from_slice(&*nonce), content)
            .map_err(|_| KeeperError::EncryptionFailed)?;

        let header = RuneHeader {
            tome_id,
            rune_id: rune_id.clone(),
            keeper_signing_pk: Ed25519Pk::from_bytes(self.signing_key.verifying_key().to_bytes()),
            content_len: encrypted.len() as u32,
            nonce,
            content_type: "application/octet-stream".to_string(),
            epoch: 0,
            digest: Sha256::digest(&encrypted).into(),
        };

        self.owned_rune_keys.insert(rune_id.clone(), rune_key);

        Ok((header, encrypted))
    }

    pub fn request_rune(&self, tome_id: TomeId, rune_id: RuneId) -> UnlockRequest {
        let public_key = PublicKey::from(&self.encryption_secret).to_bytes();

        UnlockRequest {
            tome_id,
            rune_id,
            requester_pk_x25519: X25519Pk::from_bytes(public_key),
            requester_pk_ed25519: Ed25519Pk::from_bytes(
                self.signing_key.verifying_key().to_bytes(),
            ),
        }
    }

    pub fn grant_rune(&mut self, request: UnlockRequest) -> Result<UnlockGrant, KeeperError> {
        let rune_key = self
            .owned_rune_keys
            .get(&request.rune_id)
            .ok_or(KeeperError::MissingKey)?;

        let requester_pk = PublicKey::from(request.requester_pk_x25519.0);

        // Generate a new ephemeral key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Generate a shared ephemeral secret from the requester's public key and the ephemeral secret
        let shared_secret = ephemeral_secret.diffie_hellman(&requester_pk);
        let key = Key::from_slice(shared_secret.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = Nonce24::generate();

        let wrapped_kb = cipher
            .encrypt(XNonce::from_slice(&*nonce), rune_key.deref().as_slice())
            .map_err(|_| KeeperError::EncryptionFailed)?;

        let signature = self.signing_key.sign(wrapped_kb.as_slice());

        Ok(UnlockGrant {
            rune_id: request.rune_id,
            eph_pk_x25519: CryptoKey::<32>(ephemeral_public.to_bytes()),
            wrapped_kb,
            wrapped_nonce: nonce,
            wrapped_sig: CryptoKey::<64>(signature.to_bytes()),
            requester_pk_ed25519: request.requester_pk_ed25519,
        })
    }

    /// Accepts the rune grant from the rune owner
    /// If successful, this [Keeper] will be able to decrypt the rune
    pub fn accept_grant(
        &mut self,
        header: &RuneHeader,
        grant: UnlockGrant,
    ) -> Result<(), KeeperError> {
        let owner_pk = PublicKey::from(grant.eph_pk_x25519.0);

        // Generate a shared secret from the owner's encryption secret and the ephemeral public key
        let shared_secret = self.encryption_secret.diffie_hellman(&owner_pk);
        let shared_secret_key = Key::from_slice(shared_secret.as_bytes());
        let cipher = XChaCha20Poly1305::new(shared_secret_key);

        let nonce = XNonce::from_slice(grant.wrapped_nonce.0.as_slice());

        let decrypted_kb = cipher
            .decrypt(nonce, grant.wrapped_kb.as_slice())
            .map_err(|_| KeeperError::DecryptionFailed)?;

        let owner_signing_key = VerifyingKey::from_bytes(&header.keeper_signing_pk.0)
            .map_err(|_| KeeperError::InvalidKey)?;

        let wrapped_sig = Signature::from_bytes(&grant.wrapped_sig.0);

        // Verify that the owner's signing key signed the wrapped key
        owner_signing_key
            .verify_strict(&grant.wrapped_kb, &wrapped_sig)
            .map_err(|_| KeeperError::InvalidSignature)?;

        let unwrapped_rune_key = SymmetricKey::try_from_slice(decrypted_kb.as_slice())
            .map_err(|_| KeeperError::InvalidKey)?;

        self.owned_rune_keys
            .insert(grant.rune_id, unwrapped_rune_key);

        Ok(())
    }

    pub fn decrypt_rune(
        &self,
        header: &RuneHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeeperError> {
        let rune_key = self
            .owned_rune_keys
            .get(&header.rune_id)
            .ok_or(KeeperError::MissingKey)?;
        let cipher = XChaCha20Poly1305::new(rune_key.deref().into());
        let rune_content_nonce = XNonce::from_slice(header.nonce.0.as_slice());

        let decrypted = cipher
            .decrypt(rune_content_nonce, ciphertext)
            .map_err(|_| KeeperError::DecryptionFailed)?;

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_full_protocol_flow() {
        let tome_id = TomeId(Uuid::new_v4());

        let mut alice = Keeper::new();
        let mut bob = Keeper::new();
        let alice_content = b"Alice's secret data";
        let bob_content = b"Bob's secret data";

        let (rune_header, rune_content) = alice.create_rune(tome_id.clone(), alice_content).unwrap();

        let (bob_rune_header, bob_rune_content) = bob.create_rune(tome_id.clone(), bob_content).unwrap();

        let bob_request = bob.request_rune(tome_id.clone(), rune_header.clone().rune_id);

        let alice_grant = alice.grant_rune(bob_request).unwrap();

        bob.accept_grant(&rune_header, alice_grant).unwrap();

        let bob_decrypted = bob
            .decrypt_rune(&rune_header.clone(), &rune_content)
            .unwrap();

        let alice_decrypted = alice
            .decrypt_rune(&rune_header.clone(), &rune_content)
            .unwrap();

        assert_eq!(bob_decrypted, alice_content);
        assert_eq!(alice_decrypted, alice_content);

        let alice_bob_decrypted = alice.decrypt_rune(&bob_rune_header, &bob_rune_content);
        assert!(alice_bob_decrypted.is_err());
        assert!(matches!(
            alice_bob_decrypted.unwrap_err(),
            KeeperError::MissingKey
        ));

        let alice_request = alice.request_rune(tome_id.clone(), bob_rune_header.clone().rune_id);
        let bob_grant = bob.grant_rune(alice_request).unwrap();
        alice.accept_grant(&bob_rune_header, bob_grant).unwrap();

        let alice_decrypted = alice
            .decrypt_rune(&bob_rune_header.clone(), &bob_rune_content)
            .unwrap();

        assert_eq!(alice_decrypted, bob_content);
    }
}
