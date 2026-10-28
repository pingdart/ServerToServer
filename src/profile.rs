use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::identity::SdsIdentityKeyPair;

/// Verifiable Signed Application Profile published by an SDS domain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdsAppProfile {
    pub protocol: String,
    pub protocol_version: String,
    pub domain: String,
    pub sds_id: String,
    pub app_id: String,
    pub app_name: String,
    pub app_logo_url: String,
    pub app_logo_hash_sha256: String,
    pub website: String,
    pub server_identity: String,
    pub capabilities: Vec<String>,
    pub signature: String,
}

impl SdsAppProfile {
    /// Deterministic canonical signing string for signature calculation
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut caps = self.capabilities.clone();
        caps.sort();
        let caps_joined = caps.join(",");

        format!(
            "SDS-APP-PROFILE-v1:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.domain,
            self.sds_id,
            self.app_id,
            self.app_name,
            self.app_logo_url,
            self.app_logo_hash_sha256,
            self.website,
            self.server_identity,
            caps_joined
        )
        .into_bytes()
    }

    /// Signs an application profile with the server authority's Ed25519 keypair
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        domain: String,
        sds_id: String,
        app_id: String,
        app_name: String,
        app_logo_url: String,
        app_logo_bytes: &[u8],
        website: String,
        capabilities: Vec<String>,
        authority_keypair: &SdsIdentityKeyPair,
    ) -> Self {
        // Calculate SHA-256 integrity hash of logo
        let mut hasher = Sha256::new();
        hasher.update(app_logo_bytes);
        let logo_hash = hex_encode(&hasher.finalize());

        let server_identity = authority_keypair.public_key_hex();

        let mut profile = Self {
            protocol: "SDS".to_string(),
            protocol_version: "1.0".to_string(),
            domain,
            sds_id,
            app_id,
            app_name,
            app_logo_url,
            app_logo_hash_sha256: logo_hash,
            website,
            server_identity,
            capabilities,
            signature: String::new(),
        };

        let message = profile.canonical_signing_bytes();
        let sig_bytes = authority_keypair.sign(&message);
        profile.signature = hex_encode(&sig_bytes);
        profile
    }

    /// Verifies the cryptographic signature of the profile against `server_identity`
    pub fn verify_signature(&self) -> Result<bool> {
        let pubkey_bytes = hex_decode_32(&self.server_identity)?;
        let verifier = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid authority public key: {}", e))?;

        let sig_bytes = hex_decode_64(&self.signature)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let message = self.canonical_signing_bytes();
        Ok(verifier.verify(&message, &signature).is_ok())
    }

    /// Validates URL safety against SSRF, intranet exposure, and DNS rebinding
    pub fn validate_url_safety(&self) -> Result<()> {
        if !self.app_logo_url.starts_with("https://") {
            bail!("Logo URL must use HTTPS: {}", self.app_logo_url);
        }

        let after_scheme = &self.app_logo_url[8..];
        let host_part = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);

        // Strip port if present
        let host = if host_part.starts_with('[') {
            // IPv6 with brackets: [::1]:8080 or [::1]
            let end_bracket = host_part
                .find(']')
                .ok_or_else(|| anyhow::anyhow!("Malformed IPv6 host"))?;
            &host_part[1..end_bracket]
        } else if let Some(colon_pos) = host_part.find(':') {
            &host_part[..colon_pos]
        } else {
            host_part
        };

        let host_lower = host.to_lowercase();

        // 1. Block common string representations of loopback and metadata hosts
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower.ends_with(".local")
            || host_lower == "metadata.google.internal"
            || host_lower == "instance-data"
        {
            bail!("Logo URL points to forbidden host: {}", host);
        }

        // 2. Parse as IP address if applicable
        if let Ok(ip) = IpAddr::from_str(&host_lower) {
            Self::validate_ip_address_safety(&ip)?;
        }

        Ok(())
    }

    /// Evaluates IP address safety against loopback, private networks, cloud metadata, and IPv4-mapped IPv6
    pub fn validate_ip_address_safety(ip: &IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => Self::validate_ipv4_safety(ipv4),
            IpAddr::V6(ipv6) => Self::validate_ipv6_safety(ipv6),
        }
    }

    fn validate_ipv4_safety(ipv4: &Ipv4Addr) -> Result<()> {
        let octets = ipv4.octets();

        // Loopback 127.0.0.0/8
        if ipv4.is_loopback() || octets[0] == 127 {
            bail!("SSRF blocked: IPv4 loopback address {}", ipv4);
        }

        // Unspecified 0.0.0.0/8 or Broadcast
        if ipv4.is_unspecified() || octets[0] == 0 || ipv4.is_broadcast() {
            bail!(
                "SSRF blocked: IPv4 unspecified or broadcast address {}",
                ipv4
            );
        }

        // RFC 1918 Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
        {
            bail!("SSRF blocked: RFC 1918 private IPv4 address {}", ipv4);
        }

        // Cloud Metadata & Link-Local: 169.254.0.0/16
        if octets[0] == 169 && octets[1] == 254 {
            bail!("SSRF blocked: Cloud metadata / link-local address {}", ipv4);
        }

        // Carrier-Grade NAT: 100.64.0.0/10
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            bail!("SSRF blocked: Shared CGNAT address {}", ipv4);
        }

        Ok(())
    }

    fn validate_ipv6_safety(ipv6: &Ipv6Addr) -> Result<()> {
        let segments = ipv6.segments();

        // IPv6 Loopback ::1
        if ipv6.is_loopback() || *ipv6 == Ipv6Addr::LOCALHOST {
            bail!("SSRF blocked: IPv6 loopback address {}", ipv6);
        }

        // IPv6 Unspecified ::
        if ipv6.is_unspecified() {
            bail!("SSRF blocked: IPv6 unspecified address {}", ipv6);
        }

        // IPv6 Link-Local fe80::/10
        if (segments[0] & 0xffc0) == 0xfe80 {
            bail!("SSRF blocked: IPv6 link-local address {}", ipv6);
        }

        // IPv6 Unique Local Address (ULA) fc00::/7 (fc00:: - fdff::)
        if (segments[0] & 0xfe00) == 0xfc00 {
            bail!(
                "SSRF blocked: IPv6 unique local (ULA) private address {}",
                ipv6
            );
        }

        // IPv4-mapped IPv6 ::ffff:a.b.c.d
        if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
            return Self::validate_ipv4_safety(&mapped_v4);
        }

        Ok(())
    }

    /// Destination IP validation performed at connection-time to defeat DNS rebinding (TOCTOU)
    pub fn validate_connection_target(resolved_ip: &IpAddr) -> Result<()> {
        Self::validate_ip_address_safety(resolved_ip)
    }

    /// Verifies the binary integrity of the downloaded logo image against the signed hash
    pub fn verify_logo_integrity(&self, downloaded_image_bytes: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(downloaded_image_bytes);
        let actual_hash = hex_encode(&hasher.finalize());
        actual_hash.eq_ignore_ascii_case(&self.app_logo_hash_sha256)
    }
}

/// Cache for verified application profiles with TTL management
pub struct AppProfileCache {
    ttl: Duration,
    entries: HashMap<String, (SdsAppProfile, Instant)>,
}

impl AppProfileCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, profile: SdsAppProfile) {
        self.entries
            .insert(domain.to_lowercase(), (profile, Instant::now()));
    }

    pub fn get(&self, domain: &str) -> Option<&SdsAppProfile> {
        if let Some((profile, cached_at)) = self.entries.get(&domain.to_lowercase()) {
            if cached_at.elapsed() < self.ttl {
                return Some(profile);
            }
        }
        None
    }
}

// Minimal hex helpers
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
    fn test_signed_app_profile_verification_and_logo_integrity() {
        let authority = SdsIdentityKeyPair::generate();
        let logo_bytes = b"PNG_IMAGE_BINARY_MOCK_DATA";

        let profile = SdsAppProfile::sign_new(
            "chat.example.com".to_string(),
            "7K9M2P4X8B".to_string(),
            "example-chat".to_string(),
            "Example Chat".to_string(),
            "https://cdn.example.com/assets/logo.png".to_string(),
            logo_bytes,
            "https://example.com".to_string(),
            vec![
                "messaging".to_string(),
                "voice".to_string(),
                "video".to_string(),
                "e2ee".to_string(),
            ],
            &authority,
        );

        // 1. Signature check passes
        assert!(profile.verify_signature().unwrap());

        // 2. URL safety check passes
        assert!(profile.validate_url_safety().is_ok());

        // 3. Logo integrity check passes with authentic bytes
        assert!(profile.verify_logo_integrity(logo_bytes));

        // 4. Logo integrity fails if attacker swapped image
        assert!(!profile.verify_logo_integrity(b"FORGED_IMAGE_BYTES"));

        // 5. Tampered app name fails signature check
        let mut tampered = profile.clone();
        tampered.app_name = "Phishing Chat Imposter".to_string();
        assert!(!tampered.verify_signature().unwrap());
    }

    #[test]
    fn test_ssrf_url_protection() {
        let authority = SdsIdentityKeyPair::generate();
        let make_profile = |url: &str| {
            SdsAppProfile::sign_new(
                "chat.example.com".to_string(),
                "7K9M2P4X8B".to_string(),
                "test-app".to_string(),
                "Test App".to_string(),
                url.to_string(),
                b"data",
                "https://example.com".to_string(),
                vec![],
                &authority,
            )
        };

        // 1. Plain HTTP is forbidden
        assert!(make_profile("http://example.com/logo.png")
            .validate_url_safety()
            .is_err());

        // 2. Localhost strings
        assert!(make_profile("https://localhost:8080/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://api.localhost/logo.png")
            .validate_url_safety()
            .is_err());

        // 3. IPv4 loopback & private subnets
        assert!(make_profile("https://127.0.0.1/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://10.0.0.1/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://172.16.0.1/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://192.168.1.1/logo.png")
            .validate_url_safety()
            .is_err());

        // 4. Cloud Metadata (AWS/GCP)
        assert!(make_profile("https://169.254.169.254/latest/meta-data")
            .validate_url_safety()
            .is_err());

        // 5. IPv6 Loopback & ULA private
        assert!(make_profile("https://[::1]/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://[fd00::1]/logo.png")
            .validate_url_safety()
            .is_err());

        // 6. IPv4-Mapped IPv6
        assert!(make_profile("https://[::ffff:127.0.0.1]/logo.png")
            .validate_url_safety()
            .is_err());
        assert!(make_profile("https://[::ffff:169.254.169.254]/logo.png")
            .validate_url_safety()
            .is_err());

        // 7. Legitimate public HTTPS CDN passes
        assert!(make_profile("https://cdn.example.com/assets/logo.png")
            .validate_url_safety()
            .is_ok());

        // 8. Connection-time destination IP validation (Anti-DNS Rebinding)
        assert!(SdsAppProfile::validate_connection_target(&"127.0.0.1".parse().unwrap()).is_err());
        assert!(SdsAppProfile::validate_connection_target(&"::1".parse().unwrap()).is_err());
        assert!(
            SdsAppProfile::validate_connection_target(&"169.254.169.254".parse().unwrap()).is_err()
        );
        assert!(
            SdsAppProfile::validate_connection_target(&"93.184.216.34".parse().unwrap()).is_ok()
        );
    }
}
