use anyhow::{bail, Result};
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventType {
    AuthSuccess,
    AuthFailure,
    KeyRotated,
    NodeQuarantined,
    NodeAdmitted,
    ReplayDetected,
    RateLimited,
    SessionRevoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub index: u64,
    pub timestamp_ms: u64,
    pub event_type: AuditEventType,
    pub actor: String,
    pub details: String,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AuditLogEntry {
    pub fn compute_hash(
        index: u64,
        timestamp_ms: u64,
        event_type: &AuditEventType,
        actor: &str,
        details: &str,
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(index.to_be_bytes());
        hasher.update(timestamp_ms.to_be_bytes());
        hasher.update(format!("{:?}", event_type).as_bytes());
        hasher.update(actor.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(prev_hash);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/// Cryptographically Verifiable, Append-Only Tamper-Evident Audit Hash Chain
pub struct AuditLogChain {
    entries: Vec<AuditLogEntry>,
    current_head: [u8; 32],
}

impl Default for AuditLogChain {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogChain {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_head: [0u8; 32], // Genesis anchor
        }
    }

    pub fn append(
        &mut self,
        event_type: AuditEventType,
        actor: &str,
        details: &str,
        timestamp_ms: u64,
    ) -> &AuditLogEntry {
        let index = self.entries.len() as u64;
        let prev_hash = self.current_head;
        let entry_hash = AuditLogEntry::compute_hash(
            index,
            timestamp_ms,
            &event_type,
            actor,
            details,
            &prev_hash,
        );

        self.current_head = entry_hash;
        self.entries.push(AuditLogEntry {
            index,
            timestamp_ms,
            event_type,
            actor: actor.to_string(),
            details: details.to_string(),
            prev_hash,
            entry_hash,
        });

        self.entries.last().unwrap()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn head_hash(&self) -> [u8; 32] {
        self.current_head
    }

    /// Verifies complete chain integrity from genesis to current head
    pub fn verify_chain_integrity(&self) -> Result<()> {
        let mut expected_prev = [0u8; 32];

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.index != i as u64 {
                bail!("Log sequence mismatch at index {}", i);
            }
            if entry.prev_hash != expected_prev {
                bail!(
                    "Broken cryptographic chain at index {}: invalid prev_hash",
                    i
                );
            }

            let expected_hash = AuditLogEntry::compute_hash(
                entry.index,
                entry.timestamp_ms,
                &entry.event_type,
                &entry.actor,
                &entry.details,
                &entry.prev_hash,
            );

            if entry.entry_hash != expected_hash {
                bail!(
                    "Tampered audit entry detected at index {}: hash mismatch",
                    i
                );
            }

            expected_prev = entry.entry_hash;
        }

        if expected_prev != self.current_head {
            bail!("Head hash mismatch in audit chain");
        }

        Ok(())
    }

    /// Creates an externally verifiable signed checkpoint of the current audit head
    pub fn create_signed_checkpoint(
        &self,
        epoch_ms: u64,
        authority_keypair: &crate::identity::SdsIdentityKeyPair,
    ) -> SignedAuditCheckpoint {
        let log_index = self.entries.len() as u64;
        let head_hash_hex = hex_encode(&self.current_head);

        let mut hasher = Sha256::new();
        hasher.update(epoch_ms.to_be_bytes());
        hasher.update(log_index.to_be_bytes());
        hasher.update(head_hash_hex.as_bytes());
        let digest = hasher.finalize();

        let sig_bytes = authority_keypair.sign(&digest);

        SignedAuditCheckpoint {
            epoch_ms,
            log_index,
            head_hash_hex,
            authority_pubkey_hex: authority_keypair.public_key_hex(),
            signature_hex: hex_encode(&sig_bytes),
        }
    }
}

/// Signed Audit Checkpoint for anchoring to external ledgers / separate trust domains
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAuditCheckpoint {
    pub epoch_ms: u64,
    pub log_index: u64,
    pub head_hash_hex: String,
    pub authority_pubkey_hex: String,
    pub signature_hex: String,
}

impl SignedAuditCheckpoint {
    pub fn verify(&self) -> Result<bool> {
        let pubkey_bytes = hex_decode_32(&self.authority_pubkey_hex)?;
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid authority key: {}", e))?;

        let sig_bytes = hex_decode_64(&self.signature_hex)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let mut hasher = Sha256::new();
        hasher.update(self.epoch_ms.to_be_bytes());
        hasher.update(self.log_index.to_be_bytes());
        hasher.update(self.head_hash_hex.as_bytes());
        let digest = hasher.finalize();

        Ok(verifier.verify(&digest, &signature).is_ok())
    }

    /// Verifies that a checkpoint is valid, strictly newer than a previously known checkpoint,
    /// and matches the verifier's expected authority key (preventing stale rollback/truncation).
    pub fn verify_against_anchored_state(
        &self,
        trusted_authority_pubkey_hex: &str,
        previous_anchored_epoch_ms: u64,
        previous_anchored_index: u64,
    ) -> Result<bool> {
        if !self
            .authority_pubkey_hex
            .eq_ignore_ascii_case(trusted_authority_pubkey_hex)
        {
            bail!("Authority key mismatch: checkpoint was signed by untrusted authority");
        }
        if self.epoch_ms <= previous_anchored_epoch_ms || self.log_index < previous_anchored_index {
            bail!(
                "Stale or rolled-back checkpoint detected: checkpoint epoch {}/index {} <= anchored epoch {}/index {}",
                self.epoch_ms, self.log_index, previous_anchored_epoch_ms, previous_anchored_index
            );
        }
        self.verify()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_integrity_and_tamper_detection() {
        let mut chain = AuditLogChain::new();

        chain.append(
            AuditEventType::AuthSuccess,
            "user1@alpha.ucall.net",
            "Handshake completed over QUIC",
            1_700_000_000,
        );
        chain.append(
            AuditEventType::KeyRotated,
            "admin@beta.ucall.net",
            "Authority key rotated with signature chain",
            1_700_000_100,
        );
        chain.append(
            AuditEventType::NodeQuarantined,
            "security@sds.net",
            "Rogue node gamma isolated due to invalid signature",
            1_700_000_200,
        );

        assert_eq!(chain.len(), 3);
        assert!(chain.verify_chain_integrity().is_ok());

        // Tamper test: modify entry 1 details
        chain.entries[1].details = "Tampered details".to_string();
        assert!(chain.verify_chain_integrity().is_err());
    }

    #[test]
    fn test_signed_audit_checkpoint_external_anchoring() {
        let authority = crate::identity::SdsIdentityKeyPair::generate();
        let mut chain = AuditLogChain::new();

        chain.append(
            AuditEventType::AuthSuccess,
            "user1@alpha.ucall.net",
            "QUIC session established",
            1_700_000_000,
        );

        let checkpoint = chain.create_signed_checkpoint(1_700_000_500, &authority);
        assert!(checkpoint.verify().unwrap());
        assert_eq!(checkpoint.log_index, 1);

        // Tampered checkpoint fails verification
        let mut tampered = checkpoint.clone();
        tampered.epoch_ms = 1_700_000_501;
        assert!(!tampered.verify().unwrap());
    }
}
