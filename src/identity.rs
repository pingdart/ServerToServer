use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Cryptographic Ed25519 Identity Keypair
pub struct SdsIdentityKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SdsIdentityKeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(self.verifying_key.as_bytes())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verifiable SDS Profile Record signed by domain authority or user
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdsVerifiedProfile {
    pub sds_id: String,
    pub canonical_domain: String,
    pub display_name: String,
    pub app_name: String,
    pub public_key_hex: String,
    pub timestamp_rfc3339: String,
    pub signature_hex: String,
}

impl SdsVerifiedProfile {
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        // Deterministic format: "sds-v1:profile:<sds_id>:<canonical_domain>:<display_name>:<app_name>:<pubkey>:<timestamp>"
        format!(
            "sds-v1:profile:{}:{}:{}:{}:{}:{}",
            self.sds_id,
            self.canonical_domain,
            self.display_name,
            self.app_name,
            self.public_key_hex,
            self.timestamp_rfc3339
        )
        .into_bytes()
    }

    pub fn sign_new(
        sds_id: String,
        canonical_domain: String,
        display_name: String,
        app_name: String,
        keypair: &SdsIdentityKeyPair,
        timestamp_rfc3339: String,
    ) -> Self {
        let pubkey_hex = keypair.public_key_hex();
        let mut record = Self {
            sds_id,
            canonical_domain,
            display_name,
            app_name,
            public_key_hex: pubkey_hex,
            timestamp_rfc3339,
            signature_hex: String::new(),
        };

        let message = record.canonical_signing_bytes();
        let sig_bytes = keypair.sign(&message);
        record.signature_hex = hex_encode(&sig_bytes);
        record
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let pubkey_bytes = hex_decode_32(&self.public_key_hex)?;
        let verifier = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;

        let sig_bytes = hex_decode_64(&self.signature_hex)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let message = self.canonical_signing_bytes();
        Ok(verifier.verify(&message, &signature).is_ok())
    }
}

/// Signed Server Endpoint Record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdsEndpointRecord {
    pub canonical_domain: String,
    pub host: String,
    pub port: u16,
    pub protocol: String, // "quic", "udp-direct"
    pub authority_pubkey_hex: String,
    pub signature_hex: String,
}

impl SdsEndpointRecord {
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        format!(
            "sds-v1:endpoint:{}:{}:{}:{}:{}",
            self.canonical_domain, self.host, self.port, self.protocol, self.authority_pubkey_hex
        )
        .into_bytes()
    }

    pub fn sign_new(
        canonical_domain: String,
        host: String,
        port: u16,
        protocol: String,
        authority_keypair: &SdsIdentityKeyPair,
    ) -> Self {
        let authority_pubkey_hex = authority_keypair.public_key_hex();
        let mut endpoint = Self {
            canonical_domain,
            host,
            port,
            protocol,
            authority_pubkey_hex,
            signature_hex: String::new(),
        };

        let message = endpoint.canonical_signing_bytes();
        let sig_bytes = authority_keypair.sign(&message);
        endpoint.signature_hex = hex_encode(&sig_bytes);
        endpoint
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let pubkey_bytes = hex_decode_32(&self.authority_pubkey_hex)?;
        let verifier = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid authority public key: {}", e))?;

        let sig_bytes = hex_decode_64(&self.signature_hex)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let message = self.canonical_signing_bytes();
        Ok(verifier.verify(&message, &signature).is_ok())
    }
}

/// Cryptographic Chain-of-Custody Server Key Rotation Certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdsKeyRotationCertificate {
    pub domain: String,
    pub old_public_key_hex: String,
    pub new_public_key_hex: String,
    pub epoch: u64,
    pub timestamp_ms: u64,
    pub signature_by_old_key_hex: String,
}

impl SdsKeyRotationCertificate {
    pub fn sign_rotation(
        domain: &str,
        old_keypair: &SdsIdentityKeyPair,
        new_public_key_hex: &str,
        epoch: u64,
        timestamp_ms: u64,
    ) -> Self {
        let old_pub_hex = old_keypair.public_key_hex();
        let payload = format!(
            "sds-key-rotation:{}:{}:{}:{}:{}",
            domain.to_lowercase(),
            old_pub_hex,
            new_public_key_hex,
            epoch,
            timestamp_ms
        );
        let sig = old_keypair.sign(payload.as_bytes());
        Self {
            domain: domain.to_lowercase(),
            old_public_key_hex: old_pub_hex,
            new_public_key_hex: new_public_key_hex.to_string(),
            epoch,
            timestamp_ms,
            signature_by_old_key_hex: hex_encode(&sig),
        }
    }

    pub fn verify_rotation(&self) -> Result<bool> {
        let old_pub_bytes = hex_decode_32(&self.old_public_key_hex)?;
        let verifier = VerifyingKey::from_bytes(&old_pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid old public key: {}", e))?;
        let sig_bytes = hex_decode_64(&self.signature_by_old_key_hex)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let payload = format!(
            "sds-key-rotation:{}:{}:{}:{}:{}",
            self.domain.to_lowercase(),
            self.old_public_key_hex,
            self.new_public_key_hex,
            self.epoch,
            self.timestamp_ms
        );
        Ok(verifier.verify(payload.as_bytes(), &signature).is_ok())
    }
}

// Minimal hex helpers without extra dependencies
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
    fn test_profile_signing_and_verification() {
        let keypair = SdsIdentityKeyPair::generate();
        let profile = SdsVerifiedProfile::sign_new(
            "7K9M2P4X8B".to_string(),
            "server.example.com".to_string(),
            "User 2".to_string(),
            "UCall".to_string(),
            &keypair,
            "2026-10-28T05:30:00Z".to_string(),
        );

        assert!(profile.verify_signature().unwrap());

        // Tamper test: altering name must fail verification
        let mut tampered = profile.clone();
        tampered.display_name = "Imposter User".to_string();
        assert!(!tampered.verify_signature().unwrap());
    }

    #[test]
    fn test_endpoint_signing_and_verification() {
        let authority = SdsIdentityKeyPair::generate();
        let endpoint = SdsEndpointRecord::sign_new(
            "pingdart.com".to_string(),
            "sds.pingdart.com".to_string(),
            4433,
            "quic".to_string(),
            &authority,
        );

        assert!(endpoint.verify_signature().unwrap());

        // Tamper port
        let mut tampered = endpoint.clone();
        tampered.port = 8443;
        assert!(!tampered.verify_signature().unwrap());
    }

    #[test]
    fn test_key_rotation_chain_of_custody_and_tamper_detection() {
        let old_key = SdsIdentityKeyPair::generate();
        let new_key = SdsIdentityKeyPair::generate();
        let rogue_key = SdsIdentityKeyPair::generate();

        let cert = SdsKeyRotationCertificate::sign_rotation(
            "matrix.example.com",
            &old_key,
            &new_key.public_key_hex(),
            2,
            1700000000000,
        );

        // 1. Valid certificate passes verification
        assert!(cert.verify_rotation().unwrap());

        // 2. Tampered new key fails verification
        let mut tampered_cert = cert.clone();
        tampered_cert.new_public_key_hex = rogue_key.public_key_hex();
        assert!(!tampered_cert.verify_rotation().unwrap());

        // 3. Rollback / altered domain fails verification
        let mut wrong_domain = cert.clone();
        wrong_domain.domain = "other.domain.com".to_string();
        assert!(!wrong_domain.verify_rotation().unwrap());
    }
}
