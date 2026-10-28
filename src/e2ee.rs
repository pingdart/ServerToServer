use std::collections::HashMap;

use anyhow::{bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::Verifier;

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::identity::SdsIdentityKeyPair;

/// User End-to-End Cryptographic Identity
pub struct UserCryptoIdentity {
    pub identity_keypair: SdsIdentityKeyPair, // Ed25519 for identity & signing
    pub dh_secret_key: [u8; 32],              // X25519 private key
    pub dh_public_key: [u8; 32],              // X25519 public key
}

impl UserCryptoIdentity {
    pub fn generate() -> Self {
        let identity_keypair = SdsIdentityKeyPair::generate();
        let mut dh_secret_key = [0u8; 32];
        OsRng.fill_bytes(&mut dh_secret_key);

        // Derive X25519 public key from private key
        let dh_public_key = derive_x25519_public(&dh_secret_key);

        Self {
            identity_keypair,
            dh_secret_key,
            dh_public_key,
        }
    }

    pub fn public_identity_hex(&self) -> String {
        self.identity_keypair.public_key_hex()
    }

    pub fn dh_public_hex(&self) -> String {
        hex_encode(&self.dh_public_key)
    }

    /// Generates a Prekey Bundle from an existing signed prekey secret
    pub fn generate_prekey_bundle_from_secret(
        &self,
        signed_prekey_secret: &[u8; 32],
    ) -> PrekeyBundle {
        let signed_prekey_public = derive_x25519_public(signed_prekey_secret);

        // Sign the signed prekey with the user's Ed25519 identity key
        let sig_bytes = self.identity_keypair.sign(&signed_prekey_public);

        PrekeyBundle {
            identity_pubkey_hex: self.public_identity_hex(),
            dh_identity_pubkey_hex: self.dh_public_hex(),
            signed_prekey_hex: hex_encode(&signed_prekey_public),
            signed_prekey_signature_hex: hex_encode(&sig_bytes),
        }
    }

    /// Generates a new random signed prekey secret along with its signed Prekey Bundle
    pub fn generate_prekey_bundle(&self) -> ([u8; 32], PrekeyBundle) {
        let mut signed_prekey_secret = [0u8; 32];
        OsRng.fill_bytes(&mut signed_prekey_secret);
        let bundle = self.generate_prekey_bundle_from_secret(&signed_prekey_secret);
        (signed_prekey_secret, bundle)
    }

    /// Computes safety number fingerprint for verification in client UI
    pub fn compute_safety_fingerprint(alice_pubkey: &[u8], bob_pubkey: &[u8]) -> String {
        let mut hasher = Sha256::new();
        if alice_pubkey < bob_pubkey {
            hasher.update(alice_pubkey);
            hasher.update(bob_pubkey);
        } else {
            hasher.update(bob_pubkey);
            hasher.update(alice_pubkey);
        }
        let digest = hasher.finalize();
        // Format as 12-digit safety number grouped in blocks of 4
        let num1 = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 10000;
        let num2 = u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]) % 10000;
        let num3 = u32::from_be_bytes([digest[8], digest[9], digest[10], digest[11]]) % 10000;
        format!("{:04} {:04} {:04}", num1, num2, num3)
    }
}

/// Prekey Bundle published to SDS identity servers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyBundle {
    pub identity_pubkey_hex: String,
    pub dh_identity_pubkey_hex: String,
    pub signed_prekey_hex: String,
    pub signed_prekey_signature_hex: String,
}

impl PrekeyBundle {
    /// Cryptographically verifies that the signed prekey is authentic and signed by the user's Ed25519 identity key
    pub fn verify_signature(&self) -> Result<bool> {
        self.verify_signature_against_identity(None)
    }

    /// Cryptographically verifies that the signed prekey is authentic and signed by an expected/trusted identity key
    pub fn verify_signature_against_identity(
        &self,
        expected_identity_pubkey_hex: Option<&str>,
    ) -> Result<bool> {
        if let Some(expected) = expected_identity_pubkey_hex {
            if !self.identity_pubkey_hex.eq_ignore_ascii_case(expected) {
                bail!(
                    "Identity key mismatch in prekey bundle: expected '{}', found '{}'",
                    expected,
                    self.identity_pubkey_hex
                );
            }
        }
        let identity_pubkey_bytes = hex_decode_32(&self.identity_pubkey_hex)?;
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(&identity_pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid identity public key in prekey bundle: {}", e))?;

        let signed_prekey_bytes = hex_decode_32(&self.signed_prekey_hex)?;
        let sig_bytes = hex_decode_64(&self.signed_prekey_signature_hex)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        Ok(verifier.verify(&signed_prekey_bytes, &signature).is_ok())
    }
}

/// User-to-User Encrypted Message Envelope (Zero Server Visibility)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eeMessageEnvelope {
    pub sender_sds_id: String,
    pub recipient_sds_id: String,
    pub ephemeral_dh_pubkey_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub sequence_number: u64,
    pub timestamp_ms: u64,
}

impl E2eeMessageEnvelope {
    /// Canonical Associated Data (AD) passed into ChaCha20-Poly1305 AEAD
    pub fn associated_data(&self) -> Vec<u8> {
        Self::compute_associated_data(
            &self.sender_sds_id,
            &self.recipient_sds_id,
            self.sequence_number,
            self.timestamp_ms,
        )
    }

    pub fn compute_associated_data(
        sender_sds_id: &str,
        recipient_sds_id: &str,
        sequence_number: u64,
        timestamp_ms: u64,
    ) -> Vec<u8> {
        format!(
            "sds-v1:ad:{}:{}:{}:{}",
            sender_sds_id, recipient_sds_id, sequence_number, timestamp_ms
        )
        .into_bytes()
    }

    /// Sender encrypts plaintext message for recipient using recipient's prekey bundle
    pub fn encrypt_for_recipient(
        sender_sds_id: &str,
        recipient_sds_id: &str,
        recipient_prekey: &PrekeyBundle,
        plaintext: &[u8],
        sequence_number: u64,
        timestamp_ms: u64,
    ) -> Result<Self> {
        Self::encrypt_for_recipient_with_trust(
            sender_sds_id,
            recipient_sds_id,
            recipient_prekey,
            None,
            plaintext,
            sequence_number,
            timestamp_ms,
        )
    }

    /// Sender encrypts with explicit expected recipient identity key verification
    pub fn encrypt_for_recipient_with_trust(
        sender_sds_id: &str,
        recipient_sds_id: &str,
        recipient_prekey: &PrekeyBundle,
        expected_recipient_identity_hex: Option<&str>,
        plaintext: &[u8],
        sequence_number: u64,
        timestamp_ms: u64,
    ) -> Result<Self> {
        // 0. Authenticate recipient prekey bundle signature against expected identity
        if !recipient_prekey.verify_signature_against_identity(expected_recipient_identity_hex)? {
            bail!(
                "Recipient prekey bundle signature verification failed: forged or untrusted prekey"
            );
        }

        // 1. Generate ephemeral X25519 keypair for sender
        let mut ephemeral_secret = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_secret);
        let ephemeral_public = derive_x25519_public(&ephemeral_secret);

        // 2. Decode recipient signed prekey
        let recipient_prekey_bytes = hex_decode_32(&recipient_prekey.signed_prekey_hex)?;

        // 3. Compute Diffie-Hellman shared secret
        let shared_secret = compute_ecdh_shared_secret(&ephemeral_secret, &recipient_prekey_bytes);

        // 4. Derive symmetric 256-bit encryption key using RFC 5869 HKDF-SHA256
        let symmetric_key = derive_symmetric_key(&shared_secret, b"sds-v1-e2ee-message");

        // 5. Generate 12-byte random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 6. Encrypt plaintext with ChaCha20-Poly1305 (AEAD) authenticating associated data
        let ad = Self::compute_associated_data(
            sender_sds_id,
            recipient_sds_id,
            sequence_number,
            timestamp_ms,
        );
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &ad,
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| anyhow::anyhow!("Cipher init error: {}", e))?;
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(Self {
            sender_sds_id: sender_sds_id.to_string(),
            recipient_sds_id: recipient_sds_id.to_string(),
            ephemeral_dh_pubkey_hex: hex_encode(&ephemeral_public),
            nonce_hex: hex_encode(&nonce_bytes),
            ciphertext_hex: hex_encode(&ciphertext),
            sequence_number,
            timestamp_ms,
        })
    }

    /// Recipient decrypts message envelope using their private prekey
    pub fn decrypt_as_recipient(
        &self,
        recipient_signed_prekey_secret: &[u8; 32],
    ) -> Result<Vec<u8>> {
        // 1. Decode sender's ephemeral public key
        let sender_ephemeral_bytes = hex_decode_32(&self.ephemeral_dh_pubkey_hex)?;

        // 2. Compute identical Diffie-Hellman shared secret
        let shared_secret =
            compute_ecdh_shared_secret(recipient_signed_prekey_secret, &sender_ephemeral_bytes);

        // 3. Derive symmetric key using RFC 5869 HKDF-SHA256
        let symmetric_key = derive_symmetric_key(&shared_secret, b"sds-v1-e2ee-message");

        // 4. Decode nonce and ciphertext
        let nonce_bytes = hex_decode_12(&self.nonce_hex)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = hex_decode_var(&self.ciphertext_hex)?;

        // 5. Decrypt and verify Poly1305 MAC over Associated Data (AD)
        let ad = self.associated_data();
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext.as_slice(),
            aad: &ad,
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| anyhow::anyhow!("Cipher init error: {}", e))?;
        let plaintext = cipher.decrypt(nonce, payload).map_err(|e| {
            anyhow::anyhow!("Decryption / AEAD metadata verification failed: {}", e)
        })?;

        Ok(plaintext)
    }
}

// Cryptographic Diffie-Hellman operations using X25519
fn derive_x25519_public(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = X25519Secret::from(*secret_bytes);
    let public = X25519Public::from(&secret);
    *public.as_bytes()
}

fn compute_ecdh_shared_secret(
    my_secret_bytes: &[u8; 32],
    peer_public_bytes: &[u8; 32],
) -> [u8; 32] {
    let my_secret = X25519Secret::from(*my_secret_bytes);
    let peer_public = X25519Public::from(*peer_public_bytes);
    let shared = my_secret.diffie_hellman(&peer_public);
    *shared.as_bytes()
}

/// Standard RFC 5869 HKDF-SHA256 Key Derivation Function (Extract & Expand)
fn derive_symmetric_key(shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode_32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("Expected 64 hex characters for 32 bytes, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn hex_decode_64(s: &str) -> Result<[u8; 64]> {
    if s.len() != 128 {
        bail!("Expected 128 hex characters for 64 bytes, got {}", s.len());
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn hex_decode_12(s: &str) -> Result<[u8; 12]> {
    if s.len() != 24 {
        bail!("Expected 24 hex characters for 12 bytes, got {}", s.len());
    }
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn hex_decode_var(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("Hex string length must be even");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?);
    }
    Ok(out)
}

fn decrypt_with_key(
    key: &[u8; 32],
    nonce_hex: &str,
    ciphertext_hex: &str,
    ad: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes = hex_decode_12(nonce_hex)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex_decode_var(ciphertext_hex)?;

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Cipher init error: {}", e))?;
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext.as_slice(),
        aad: ad,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Decryption / AEAD metadata verification failed: {}", e))?;

    Ok(plaintext)
}

/// HKDF-SHA256 Chain Key Ratchet Step (RFC 5869)
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::new(None, chain_key);
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    hk.expand(b"sds-v1-ck-chain-step", &mut new_ck)
        .expect("valid HKDF length");
    hk.expand(b"sds-v1-ck-msg-key", &mut mk)
        .expect("valid HKDF length");
    (new_ck, mk)
}

/// HKDF-SHA256 Root Key Ratchet Step (RFC 5869)
fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(root_key), dh_out);
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    hk.expand(b"sds-v1-rk-root-step", &mut new_rk)
        .expect("valid HKDF length");
    hk.expand(b"sds-v1-rk-chain-step", &mut new_ck)
        .expect("valid HKDF length");
    (new_rk, new_ck)
}

/// Double Ratchet Encrypted Message Header & Ciphertext
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetMessage {
    pub sender_dh_pubkey_hex: String,
    pub seq_num: u32,
    pub prev_chain_len: u32,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl RatchetMessage {
    pub fn associated_data(&self) -> Vec<u8> {
        format!(
            "sds-v1:ratchet-ad:{}:{}:{}",
            self.sender_dh_pubkey_hex, self.seq_num, self.prev_chain_len
        )
        .into_bytes()
    }
}

/// Double Ratchet Session State Machine
/// Provides End-to-End Encryption with forward secrecy and post-compromise break-in recovery.
pub struct DoubleRatchetSession {
    pub local_dh_secret: [u8; 32],
    pub local_dh_public: [u8; 32],
    pub remote_dh_public: Option<[u8; 32]>,
    pub root_key: [u8; 32],
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    pub send_count: u32,
    pub recv_count: u32,
    pub prev_send_count: u32,
    pub skipped_message_keys: HashMap<(String, u32), [u8; 32]>,
}

impl DoubleRatchetSession {
    /// Initialize Alice (the party initiating the session after X3DH exchange)
    pub fn init_sender(shared_secret: &[u8; 32], bob_dh_public: &[u8; 32]) -> Self {
        let mut local_dh_secret = [0u8; 32];
        OsRng.fill_bytes(&mut local_dh_secret);
        let local_dh_public = derive_x25519_public(&local_dh_secret);

        // DH ratchet step with Bob's DH public key
        let dh_out = compute_ecdh_shared_secret(&local_dh_secret, bob_dh_public);
        let (root_key, send_chain_key) = kdf_rk(shared_secret, &dh_out);

        Self {
            local_dh_secret,
            local_dh_public,
            remote_dh_public: Some(*bob_dh_public),
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Initialize Bob (the party receiving the initial session setup)
    pub fn init_receiver(shared_secret: &[u8; 32], bob_dh_secret: &[u8; 32]) -> Self {
        let local_dh_public = derive_x25519_public(bob_dh_secret);

        Self {
            local_dh_secret: *bob_dh_secret,
            local_dh_public,
            remote_dh_public: None,
            root_key: *shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Encrypt a message using the current sending chain key
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        let current_ck = self
            .send_chain_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Send chain key not initialized"))?;

        let (new_ck, mk) = kdf_ck(current_ck);
        self.send_chain_key = Some(new_ck);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ad = format!(
            "sds-v1:ratchet-ad:{}:{}:{}",
            hex_encode(&self.local_dh_public),
            self.send_count,
            self.prev_send_count
        )
        .into_bytes();

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &ad,
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&mk)
            .map_err(|e| anyhow::anyhow!("Cipher init error: {}", e))?;
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

        let msg = RatchetMessage {
            sender_dh_pubkey_hex: hex_encode(&self.local_dh_public),
            seq_num: self.send_count,
            prev_chain_len: self.prev_send_count,
            nonce_hex: hex_encode(&nonce_bytes),
            ciphertext_hex: hex_encode(&ciphertext),
        };

        self.send_count += 1;
        Ok(msg)
    }

    /// Decrypt a received message, performing a DH ratchet step if a new DH key is observed
    pub fn ratchet_decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        let sender_dh_bytes = hex_decode_32(&msg.sender_dh_pubkey_hex)?;
        let ad = msg.associated_data();

        // Check if message key was previously skipped (out-of-order delivery)
        let skipped_key_lookup = (msg.sender_dh_pubkey_hex.clone(), msg.seq_num);
        if let Some(mk) = self.skipped_message_keys.remove(&skipped_key_lookup) {
            return decrypt_with_key(&mk, &msg.nonce_hex, &msg.ciphertext_hex, &ad);
        }

        // If sender sent a new DH public key, perform DH ratchet step
        let is_new_dh = match self.remote_dh_public {
            Some(curr) => curr != sender_dh_bytes,
            None => true,
        };

        if is_new_dh {
            // Skip any missing message keys in the previous receive chain
            if self.recv_chain_key.is_some() {
                self.skip_message_keys(msg.prev_chain_len)?;
            }

            // DH Ratchet Step: Derive new receive chain
            let dh_recv = compute_ecdh_shared_secret(&self.local_dh_secret, &sender_dh_bytes);
            let (new_rk, recv_ck) = kdf_rk(&self.root_key, &dh_recv);
            self.root_key = new_rk;
            self.recv_chain_key = Some(recv_ck);

            // Generate new local ephemeral DH key for reply sending chain
            let mut new_dh_secret = [0u8; 32];
            OsRng.fill_bytes(&mut new_dh_secret);
            let new_dh_public = derive_x25519_public(&new_dh_secret);
            self.local_dh_secret = new_dh_secret;
            self.local_dh_public = new_dh_public;

            let dh_send = compute_ecdh_shared_secret(&self.local_dh_secret, &sender_dh_bytes);
            let (new_rk2, send_ck) = kdf_rk(&self.root_key, &dh_send);
            self.root_key = new_rk2;
            self.send_chain_key = Some(send_ck);

            self.remote_dh_public = Some(sender_dh_bytes);
            self.prev_send_count = self.send_count;
            self.send_count = 0;
            self.recv_count = 0;
        }

        // Skip any messages in current chain up to msg.seq_num
        self.skip_message_keys(msg.seq_num)?;

        // Step receive chain key to derive message key
        let curr_recv_ck = self
            .recv_chain_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Recv chain key not initialized"))?;
        let (new_ck, mk) = kdf_ck(curr_recv_ck);
        self.recv_chain_key = Some(new_ck);
        self.recv_count += 1;

        decrypt_with_key(&mk, &msg.nonce_hex, &msg.ciphertext_hex, &ad)
    }

    fn skip_message_keys(&mut self, until_seq: u32) -> Result<()> {
        if self.recv_count + 1000 < until_seq {
            bail!("Too many messages to skip (exceeds 1000)");
        }
        if let Some(remote_dh) = self.remote_dh_public {
            let remote_hex = hex_encode(&remote_dh);
            while self.recv_count < until_seq {
                let curr_ck = self
                    .recv_chain_key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Recv chain key missing"))?;
                let (new_ck, mk) = kdf_ck(curr_ck);
                self.recv_chain_key = Some(new_ck);
                self.skipped_message_keys
                    .insert((remote_hex.clone(), self.recv_count), mk);
                self.recv_count += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2ee_encrypt_decrypt_roundtrip() {
        // Alice & Bob identity setup
        let _alice = UserCryptoIdentity::generate();
        let bob = UserCryptoIdentity::generate();
        let (bob_prekey_secret, bob_bundle) = bob.generate_prekey_bundle();

        assert!(bob_bundle.verify_signature().unwrap());

        let message = b"Confidential cross-server E2EE message over SDS transport!";

        // Alice encrypts for Bob
        let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
            "ALICE_7K9M",
            "BOB_9P4X",
            &bob_bundle,
            message,
            1,
            1_700_000_000_000,
        )
        .expect("Encryption failed");

        // Bob decrypts with his private prekey
        let decrypted = envelope
            .decrypt_as_recipient(&bob_prekey_secret)
            .expect("Decryption failed");

        assert_eq!(decrypted, message);

        // Tamper test 1: Tampered signed prekey signature fails prekey verification
        let mut forged_bundle = bob_bundle.clone();
        forged_bundle.signed_prekey_signature_hex = hex_encode(&[0x99u8; 64]);
        assert!(E2eeMessageEnvelope::encrypt_for_recipient(
            "ALICE_7K9M",
            "BOB_9P4X",
            &forged_bundle,
            message,
            1,
            1_700_000_000_000,
        )
        .is_err());

        // Tamper test 2: Altering ciphertext must fail authentication (Poly1305 MAC)
        let mut tampered = envelope.clone();
        tampered.ciphertext_hex = format!("00{}", &tampered.ciphertext_hex[2..]);
        assert!(tampered.decrypt_as_recipient(&bob_prekey_secret).is_err());
    }

    #[test]
    fn test_signed_prekey_rotation_and_verification() {
        let bob = UserCryptoIdentity::generate();

        // 1. Initial signed prekey bundle
        let (prekey_secret_v1, bundle_v1) = bob.generate_prekey_bundle();
        assert!(bundle_v1.verify_signature().unwrap());

        // 2. Prekey rotation: Bob issues a new signed prekey bundle v2
        let (prekey_secret_v2, bundle_v2) = bob.generate_prekey_bundle();
        assert!(bundle_v2.verify_signature().unwrap());
        assert_ne!(bundle_v1.signed_prekey_hex, bundle_v2.signed_prekey_hex);
        assert_eq!(bundle_v1.identity_pubkey_hex, bundle_v2.identity_pubkey_hex);

        // 3. Alice encrypts to Bob's rotated prekey bundle v2
        let msg = b"Message addressed to rotated prekey";
        let env_v2 = E2eeMessageEnvelope::encrypt_for_recipient(
            "ALICE_ID",
            "BOB_ID",
            &bundle_v2,
            msg,
            100,
            1_700_000_100,
        )
        .expect("Encrypt to rotated prekey");

        // 4. Bob successfully decrypts using prekey secret v2
        let decrypted = env_v2.decrypt_as_recipient(&prekey_secret_v2).unwrap();
        assert_eq!(decrypted, msg);

        // 5. Old retired prekey secret v1 fails to decrypt message encrypted to v2
        assert!(env_v2.decrypt_as_recipient(&prekey_secret_v1).is_err());
    }

    #[test]
    fn test_safety_number_fingerprint() {
        let alice_pub = [0xAA; 32];
        let bob_pub = [0xBB; 32];

        let fp1 = UserCryptoIdentity::compute_safety_fingerprint(&alice_pub, &bob_pub);
        let fp2 = UserCryptoIdentity::compute_safety_fingerprint(&bob_pub, &alice_pub);

        // Fingerprint must be commutative and 12 digits formatted as XXXX XXXX XXXX
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 14); // 4 + 1 + 4 + 1 + 4 = 14 chars
    }

    #[test]
    fn test_double_ratchet_two_way_and_forward_secrecy() {
        let initial_shared_secret = [0x42u8; 32];
        let mut bob_dh_secret = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_secret);
        let bob_dh_public = derive_x25519_public(&bob_dh_secret);

        let mut alice_session =
            DoubleRatchetSession::init_sender(&initial_shared_secret, &bob_dh_public);
        let mut bob_session =
            DoubleRatchetSession::init_receiver(&initial_shared_secret, &bob_dh_secret);

        // 1. Alice sends message 1 to Bob
        let msg1 = alice_session
            .ratchet_encrypt(b"Hello Bob from Alice!")
            .expect("Encrypt msg1");
        let dec1 = bob_session.ratchet_decrypt(&msg1).expect("Decrypt msg1");
        assert_eq!(dec1, b"Hello Bob from Alice!");

        // 2. Alice sends message 2 to Bob (symmetric chain step)
        let msg2 = alice_session
            .ratchet_encrypt(b"Second message in chain")
            .expect("Encrypt msg2");
        let dec2 = bob_session.ratchet_decrypt(&msg2).expect("Decrypt msg2");
        assert_eq!(dec2, b"Second message in chain");

        // 3. Bob replies to Alice (DH ratchet step!)
        let reply1 = bob_session
            .ratchet_encrypt(b"Hello Alice! Ratchet step triggered.")
            .expect("Encrypt reply1");
        let dec_reply1 = alice_session
            .ratchet_decrypt(&reply1)
            .expect("Decrypt reply1");
        assert_eq!(dec_reply1, b"Hello Alice! Ratchet step triggered.");

        // 4. Alice replies back to Bob (second DH ratchet step, full break-in recovery)
        let reply2 = alice_session
            .ratchet_encrypt(b"Post-compromise security verified.")
            .expect("Encrypt reply2");
        let dec_reply2 = bob_session
            .ratchet_decrypt(&reply2)
            .expect("Decrypt reply2");
        assert_eq!(dec_reply2, b"Post-compromise security verified.");
    }

    #[test]
    fn test_double_ratchet_out_of_order_delivery() {
        let initial_shared_secret = [0x99u8; 32];
        let mut bob_dh_secret = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_secret);
        let bob_dh_public = derive_x25519_public(&bob_dh_secret);

        let mut alice_session =
            DoubleRatchetSession::init_sender(&initial_shared_secret, &bob_dh_public);
        let mut bob_session =
            DoubleRatchetSession::init_receiver(&initial_shared_secret, &bob_dh_secret);

        // Alice produces 3 messages
        let m1 = alice_session.ratchet_encrypt(b"Message 1").unwrap();
        let m2 = alice_session.ratchet_encrypt(b"Message 2").unwrap();
        let m3 = alice_session.ratchet_encrypt(b"Message 3").unwrap();

        // Deliver m3 first (out-of-order)
        let d3 = bob_session
            .ratchet_decrypt(&m3)
            .expect("Decrypt m3 out of order");
        assert_eq!(d3, b"Message 3");

        // Deliver m1 second
        let d1 = bob_session
            .ratchet_decrypt(&m1)
            .expect("Decrypt m1 from skipped store");
        assert_eq!(d1, b"Message 1");

        // Deliver m2 third
        let d2 = bob_session
            .ratchet_decrypt(&m2)
            .expect("Decrypt m2 from skipped store");
        assert_eq!(d2, b"Message 2");
    }
}
