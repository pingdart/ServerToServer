use sds_core::dns::DnsSnapshot;
use sds_core::dns_wizard::*;
use sds_core::e2ee::*;
use sds_core::federation::*;
use sds_core::identity::SdsIdentityKeyPair;
use sds_core::profile::*;
use std::net::SocketAddr;
use std::time::Duration;

#[test]
fn test_end_to_end_cross_server_federated_flow() {
    // 1. Setup Server 1 (Domain A) and Server 2 (Domain B)
    let mut server_a_router = FederationRouter::new("domain-a.com");
    let server_b_addr: SocketAddr = "198.51.100.88:4433".parse().unwrap();
    server_a_router.register_peer_node("domain-b.com", "9P4X8B1122", Some(server_b_addr));

    // 2. Setup User 1 on Domain A and User 3 on Domain B
    let _user1 = UserCryptoIdentity::generate();
    let user3 = UserCryptoIdentity::generate();

    // User 3 generates and publishes prekey bundle
    let (user3_signed_prekey_secret, user3_bundle) = user3.generate_prekey_bundle();

    // 3. User 1 composes message and encrypts E2EE for User 3
    let secret_chat = b"Hello User 3 from Server 1! Completely private across servers.";
    let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
        "USER1_DOMA",
        "USER3_DOMB",
        &user3_bundle,
        secret_chat,
        1,
        1_700_000_100_000,
    )
    .expect("E2EE encryption must succeed");

    // 4. Server 1 routes message envelope
    let route_status =
        server_a_router.route_envelope("msg-federated-01", "domain-b.com", envelope.clone());
    assert_eq!(
        route_status,
        MessageDeliveryStatus::QueuedForFederatedServer
    );

    // 5. Envelope arrives at Server 2, delivered to User 3
    // User 3 decrypts message with their private key
    // Neither Server 1 nor Server 2 had access to plaintext!
    let decrypted = envelope
        .decrypt_as_recipient(&user3_signed_prekey_secret)
        .expect("User 3 must successfully decrypt E2EE envelope");

    assert_eq!(decrypted, secret_chat);
}

#[test]
fn test_app_profile_discovery_and_cache() {
    let authority = SdsIdentityKeyPair::generate();
    let logo_data = b"MOCK_PNG_IMAGE_BYTES_12345";

    let profile = SdsAppProfile::sign_new(
        "chat.example.com".to_string(),
        "7K9M2P4X8B".to_string(),
        "example-chat".to_string(),
        "Example Chat".to_string(),
        "https://example.com/logo.png".to_string(),
        logo_data,
        "https://example.com".to_string(),
        vec![
            "messaging".to_string(),
            "voice".to_string(),
            "video".to_string(),
            "e2ee".to_string(),
        ],
        &authority,
    );

    // Verify signature & logo integrity
    assert!(profile.verify_signature().unwrap());
    assert!(profile.validate_url_safety().is_ok());
    assert!(profile.verify_logo_integrity(logo_data));

    // Cache test
    let mut cache = AppProfileCache::new(Duration::from_secs(60));
    cache.insert("chat.example.com", profile.clone());

    let cached = cache.get("chat.example.com").expect("Must be in cache");
    assert_eq!(cached.app_name, "Example Chat");
    assert_eq!(cached.domain, "chat.example.com");
}

#[test]
fn test_dns_wizard_and_verification_pipeline() {
    // Generate records for a developer deploying chat.example.com
    let guide = DnsSetupGuide::generate(
        "chat.example.com",
        "7K9M2P4X8B",
        "sds.example.com",
        "203.0.113.10",
        4433,
        "7a4f9b8c00112233",
    );

    assert_eq!(guide.recommended_records.len(), 3);
    assert!(guide
        .recommended_records
        .iter()
        .any(|r| r.record_type == "SRV"));
    assert!(guide
        .recommended_records
        .iter()
        .any(|r| r.record_type == "TXT"));
    assert!(guide
        .recommended_records
        .iter()
        .any(|r| r.record_type == "A"));

    // Simulate DNS inspection
    let snapshot = DnsSnapshot {
        a_records: vec!["203.0.113.10".to_string()],
        txt_records: vec!["v=sds1; id=7K9M2P4X8B; k=ed25519; p=7a4f9b8c00112233".to_string()],
        ..Default::default()
    };

    let report = DnsVerificationEngine::verify_snapshot(
        "chat.example.com",
        "7K9M2P4X8B",
        "7a4f9b8c00112233",
        &snapshot,
    );

    assert!(report.is_ready_for_federation);
    assert!(report.sds_txt_verified);
    assert!(report.authority_key_matched);
    assert_eq!(report.detected_sds_id, Some("7K9M2P4X8B".to_string()));
}
