use crate::dns::DnsSnapshot;
use serde::{Deserialize, Serialize};

/// Proposed DNS records for developer domain setup
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordRecommendation {
    pub record_type: String, // "SRV", "TXT", "A", "AAAA"
    pub name: String,
    pub value: String,
    pub ttl: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSetupGuide {
    pub canonical_domain: String,
    pub sds_id: String,
    pub server_hostname: String,
    pub server_ipv4: String,
    pub quic_port: u16,
    pub authority_pubkey_hex: String,
    pub recommended_records: Vec<DnsRecordRecommendation>,
}

impl DnsSetupGuide {
    pub fn generate(
        canonical_domain: &str,
        sds_id: &str,
        server_hostname: &str,
        server_ipv4: &str,
        quic_port: u16,
        authority_pubkey_hex: &str,
    ) -> Self {
        let recommended_records = vec![
            DnsRecordRecommendation {
                record_type: "SRV".to_string(),
                name: format!("_sds._udp.{}", canonical_domain),
                value: format!("10 10 {} {}.", quic_port, server_hostname),
                ttl: 3600,
                description:
                    "Advertises the SDS QUIC/UDP service endpoint and port to federated servers"
                        .to_string(),
            },
            DnsRecordRecommendation {
                record_type: "TXT".to_string(),
                name: format!("_sds.{}", canonical_domain),
                value: format!(
                    "v=sds1; id={}; k=ed25519; p={}",
                    sds_id, authority_pubkey_hex
                ),
                ttl: 3600,
                description:
                    "Domain ownership proof, SDS ID verification, and authority identity key"
                        .to_string(),
            },
            DnsRecordRecommendation {
                record_type: "A".to_string(),
                name: server_hostname.to_string(),
                value: server_ipv4.to_string(),
                ttl: 3600,
                description: "Resolves the SDS service hostname to your server IPv4 address"
                    .to_string(),
            },
        ];

        Self {
            canonical_domain: canonical_domain.to_string(),
            sds_id: sds_id.to_string(),
            server_hostname: server_hostname.to_string(),
            server_ipv4: server_ipv4.to_string(),
            quic_port,
            authority_pubkey_hex: authority_pubkey_hex.to_string(),
            recommended_records,
        }
    }
}

/// Verification result for developer DNS deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsVerificationReport {
    pub is_ready_for_federation: bool,
    pub sds_txt_verified: bool,
    pub a_record_verified: bool,
    pub authority_key_matched: bool,
    pub detected_sds_id: Option<String>,
    pub issues: Vec<String>,
}

pub struct DnsVerificationEngine;

impl DnsVerificationEngine {
    pub fn verify_snapshot(
        expected_domain: &str,
        expected_sds_id: &str,
        expected_pubkey: &str,
        snapshot: &DnsSnapshot,
    ) -> DnsVerificationReport {
        let mut sds_txt_verified = false;
        let mut authority_key_matched = false;
        let mut detected_sds_id = None;
        let mut issues = Vec::new();

        // 1. Inspect TXT records
        for txt in &snapshot.txt_records {
            if txt.contains("v=sds1") {
                sds_txt_verified = true;
                if txt.contains(expected_sds_id) {
                    detected_sds_id = Some(expected_sds_id.to_string());
                }
                if txt.contains(expected_pubkey) {
                    authority_key_matched = true;
                }
            }
        }

        if !sds_txt_verified {
            issues.push(format!(
                "Missing _sds.{} TXT record with 'v=sds1' verification tag",
                expected_domain
            ));
        } else if !authority_key_matched {
            issues.push(format!(
                "TXT record does not match expected authority public key: {}",
                expected_pubkey
            ));
        }

        // 2. Inspect A/AAAA records
        let a_record_verified = !snapshot.a_records.is_empty();
        if !a_record_verified {
            issues.push(format!(
                "No IPv4 (A) records resolved for domain '{}'",
                expected_domain
            ));
        }

        let is_ready_for_federation =
            sds_txt_verified && authority_key_matched && a_record_verified;

        DnsVerificationReport {
            is_ready_for_federation,
            sds_txt_verified,
            a_record_verified,
            authority_key_matched,
            detected_sds_id,
            issues,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_wizard_record_generation() {
        let guide = DnsSetupGuide::generate(
            "chat.example.com",
            "7K9M2P4X8B",
            "sds.example.com",
            "203.0.113.5",
            4433,
            "7a4f9b8c00112233445566778899aabbccddeeff00112233445566778899aabb",
        );

        assert_eq!(guide.recommended_records.len(), 3);
        assert_eq!(guide.recommended_records[0].record_type, "SRV");
        assert_eq!(
            guide.recommended_records[0].name,
            "_sds._udp.chat.example.com"
        );
        assert_eq!(
            guide.recommended_records[0].value,
            "10 10 4433 sds.example.com."
        );

        assert_eq!(guide.recommended_records[1].record_type, "TXT");
        assert_eq!(guide.recommended_records[1].name, "_sds.chat.example.com");
        assert!(guide.recommended_records[1].value.contains("v=sds1"));
        assert!(guide.recommended_records[1].value.contains("7K9M2P4X8B"));
    }

    #[test]
    fn test_dns_verification_engine_pass_and_fail() {
        let snapshot = DnsSnapshot {
            a_records: vec!["203.0.113.5".to_string()],
            txt_records: vec!["v=sds1; id=7K9M2P4X8B; k=ed25519; p=7a4f9b8c_valid_key".to_string()],
            ..Default::default()
        };

        let report = DnsVerificationEngine::verify_snapshot(
            "chat.example.com",
            "7K9M2P4X8B",
            "7a4f9b8c_valid_key",
            &snapshot,
        );

        assert!(report.is_ready_for_federation);
        assert!(report.sds_txt_verified);
        assert!(report.authority_key_matched);
        assert!(report.issues.is_empty());

        // Test missing TXT fail
        let empty_snapshot = DnsSnapshot::default();
        let fail_report = DnsVerificationEngine::verify_snapshot(
            "chat.example.com",
            "7K9M2P4X8B",
            "7a4f9b8c_valid_key",
            &empty_snapshot,
        );

        assert!(!fail_report.is_ready_for_federation);
        assert!(!fail_report.issues.is_empty());
    }
}
