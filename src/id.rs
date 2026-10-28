use crate::canonical::normalize_domain;
use crate::checksum::{calculate_checksum, encode_value, verify_checksum};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainIdResult {
    pub formatted_id: String, // e.g. "Q2KE-9Y5F-G8"
    pub raw_id: String,       // e.g. "Q2KE9Y5FG8"
    pub canonical_domain: String,
    pub payload: String,  // 8 chars
    pub checksum: String, // 2 chars
}

pub const DEFAULT_PAYLOAD_CHARS: usize = 8; // 8 payload + 2 checksum = 10 chars

/// Generates a unique, deterministic 10-character SDS Domain ID
/// using Crockford Base32 (8 chars payload + 2 chars checksum).
pub fn generate_domain_id(input_domain: &str) -> Result<DomainIdResult> {
    generate_domain_id_tiered(input_domain, 0, DEFAULT_PAYLOAD_CHARS)
}

/// Generates a deterministic ID with salt for collision resolution (10 chars default).
pub fn generate_domain_id_with_salt(input_domain: &str, salt: u32) -> Result<DomainIdResult> {
    generate_domain_id_tiered(input_domain, salt, DEFAULT_PAYLOAD_CHARS)
}

/// Expandable tiered generator:
/// - payload_chars = 8 -> 10 characters total (Default: 1.1 Trillion capacity)
/// - payload_chars = 10 -> 12 characters total (Expanded: 1.12 Quadrillion capacity)
/// - payload_chars = 12 -> 14 characters total (Enterprise: 1.15 Quintillion capacity)
pub fn generate_domain_id_tiered(
    input_domain: &str,
    salt: u32,
    payload_chars: usize,
) -> Result<DomainIdResult> {
    let canonical = normalize_domain(input_domain)?;

    let seed = if salt == 0 {
        canonical.clone()
    } else {
        format!("{}#{}", canonical, salt)
    };

    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    // Extract bitstream from SHA-256 (256 bits available)
    let mut bits: Vec<u8> = Vec::with_capacity(256);
    for &b in hash.iter() {
        for bit_idx in (0..8).rev() {
            bits.push((b >> bit_idx) & 1);
        }
    }

    let mut chars = Vec::with_capacity(payload_chars);
    for i in 0..payload_chars {
        let mut digit: usize = 0;
        for j in 0..5 {
            let bit = bits.get(i * 5 + j).copied().unwrap_or(0);
            digit = (digit << 1) | (bit as usize);
        }
        chars.push(encode_value(digit));
    }
    let payload: String = chars.into_iter().collect();

    let (c1, c2) = calculate_checksum(&payload);
    let checksum = format!("{}{}", c1, c2);
    let raw_id = format!("{}{}", payload, checksum);
    let formatted_id = raw_id.clone();

    Ok(DomainIdResult {
        formatted_id,
        raw_id,
        canonical_domain: canonical,
        payload,
        checksum,
    })
}

/// Validates whether a candidate string is a well-formed SDS Domain ID.
pub fn validate_domain_id(code: &str) -> Result<bool, String> {
    match verify_checksum(code) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(e.to_string()),
    }
}
