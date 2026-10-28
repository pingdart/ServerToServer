use sds_core::frame::*;
use sds_core::identity::*;
use sds_core::replay::*;
use sds_core::transport::*;
use std::net::SocketAddr;
use std::time::Duration;

#[test]
fn test_conformance_binary_wire_format_specification() {
    let raw_payload = b"UCall E2EE Audio NALU Frame Chunk".to_vec();
    let mut frame = SdsFrame::new_datagram(
        TYPE_MEDIA_AUDIO_OPUS,
        0x01, // sub_type
        2,    // stream 2 (audio)
        99999,
        100, // 100ms lifetime budget
        raw_payload.clone(),
    );
    frame.auth_tag = Some([0xAA; 16]);

    // 1. Serialization
    let wire_bytes = frame.to_bytes();

    // Verify header byte layout per RFC SPEC Section 10 (Exact 28 Bytes)
    assert_eq!(HEADER_SIZE, 28);
    assert_eq!(&wire_bytes[0..3], &[0x53, 0x44, 0x53]); // Word 0: "SDS"
    assert_eq!(wire_bytes[3], 0x01); // Version 1
    assert_eq!(wire_bytes[4] & FLAG_IS_DATAGRAM, FLAG_IS_DATAGRAM); // Word 1: Flags
    assert_eq!(wire_bytes[4] & FLAG_AUTH_TAG, FLAG_AUTH_TAG);
    assert_eq!(wire_bytes[5], 0x01); // Sub-type

    let frame_type = u16::from_be_bytes([wire_bytes[6], wire_bytes[7]]);
    assert_eq!(frame_type, TYPE_MEDIA_AUDIO_OPUS);

    let stream_id =
        u32::from_be_bytes([wire_bytes[8], wire_bytes[9], wire_bytes[10], wire_bytes[11]]);
    assert_eq!(stream_id, 2);

    let lifetime_ms = u16::from_be_bytes([wire_bytes[24], wire_bytes[25]]);
    assert_eq!(lifetime_ms, 100);

    // 2. Deserialization & validation
    let decoded = SdsFrame::from_bytes(&wire_bytes).expect("Should parse valid wire frame");
    assert_eq!(decoded.frame_type, TYPE_MEDIA_AUDIO_OPUS);
    assert_eq!(decoded.sub_type, 0x01);
    assert_eq!(decoded.stream_id, 2);
    assert_eq!(decoded.sequence_num, 99999);
    assert_eq!(decoded.lifetime_ms, 100);
    assert_eq!(decoded.payload, raw_payload);
    assert_eq!(decoded.auth_tag, Some([0xAA; 16]));
}

#[test]
fn test_conformance_0rtt_replay_protection() {
    let mut register = ReplayStrikeRegister::new();

    // 1. Gating test: state-mutating calls cannot run in 0-RTT
    assert_eq!(
        register.validate_0rtt_operation(TYPE_CALL_INVITE),
        Err(ERR_0RTT_OPERATION_FORBIDDEN)
    );
    assert_eq!(
        register.validate_0rtt_operation(TYPE_MSG_OFFLINE_SYNC_REQ),
        Err(ERR_0RTT_OPERATION_FORBIDDEN)
    );

    // Read-only profile queries are allowed in 0-RTT
    assert!(register
        .validate_0rtt_operation(TYPE_RESOLVE_PROFILE_REQ)
        .is_ok());

    // 2. Server-bounded ticket & idempotency key test
    let ticket = "resumption-token-001";
    let idempotency_key = "idemp-uuid-1234";
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let future_expiry = now_ms + 10_000;

    assert!(register
        .check_and_register_0rtt_request(ticket, future_expiry, idempotency_key)
        .is_ok());
    // Duplicate submission of same ticket must be rejected
    assert_eq!(
        register.check_and_register_0rtt_request(ticket, future_expiry, "diff-key"),
        Err(ERR_REPLAY_DETECTED)
    );
    // Duplicate idempotency key must be rejected
    assert_eq!(
        register.check_and_register_0rtt_request("other-ticket", future_expiry, idempotency_key),
        Err(ERR_REPLAY_DETECTED)
    );
}

#[test]
fn test_conformance_media_deadline_drop_behavior() {
    let mut session = SdsTransportSession::new(101, 0xFEEDBEEF);
    session.complete_handshake();

    // Ingest datagram with 20ms lifetime budget
    let expired_frame = SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0, 2, 1, 20, vec![1, 2, 3]);
    // Ingest datagram with 500ms lifetime budget
    let fresh_frame = SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0, 2, 2, 500, vec![4, 5, 6]);

    session.ingest_media_datagram(expired_frame);
    session.ingest_media_datagram(fresh_frame);

    // Wait 25ms so that the first packet's lifetime budget is exceeded
    std::thread::sleep(Duration::from_millis(25));

    let playable = session
        .dequeue_playable_media()
        .expect("Should dequeue fresh frame");
    assert_eq!(playable.sequence_num, 2);
    // Frame 1 dropped automatically per lifetime budget rule
    assert_eq!(session.metrics.dropped_deadline_packets, 1);
}

#[test]
fn test_conformance_connection_migration_without_drop() {
    let mut session = SdsTransportSession::new(202, 0x1234567890ABCDEF);
    let remote: SocketAddr = "203.0.113.10:4433".parse().unwrap();
    session.set_endpoint(remote);
    session.connect_direct("192.168.1.15:50000".parse().unwrap());
    session.complete_handshake();

    assert_eq!(session.state, TransportState::SessionActive);
    assert_eq!(session.metrics.migration_count, 0);

    // Mobile switches from Wi-Fi to 5G / LTE network
    let lte_ip: SocketAddr = "172.56.21.80:54321".parse().unwrap();
    session
        .migrate_connection(lte_ip)
        .expect("Migration must succeed under valid CID");

    assert_eq!(session.state, TransportState::SessionActive);
    assert_eq!(session.local_addr, Some(lte_ip));
    assert_eq!(session.metrics.migration_count, 1);
    // CID remains identical
    assert_eq!(session.connection_id, 0x1234567890ABCDEF);
}

#[test]
fn test_conformance_ed25519_profile_and_endpoint_verification() {
    let authority = SdsIdentityKeyPair::generate();

    // 1. Signed User Profile
    let user_profile = SdsVerifiedProfile::sign_new(
        "7K9M2P4X8B".to_string(),
        "server.example.com".to_string(),
        "User 2".to_string(),
        "UCall".to_string(),
        &authority,
        "2026-10-28T05:40:00Z".to_string(),
    );

    assert!(user_profile.verify_signature().unwrap());

    // 2. Tampered Profile Detection
    let mut forged_profile = user_profile.clone();
    forged_profile.sds_id = "FAKE123456".to_string();
    assert!(!forged_profile.verify_signature().unwrap());

    // 3. Signed Endpoint
    let endpoint = SdsEndpointRecord::sign_new(
        "server.example.com".to_string(),
        "sds-node1.example.com".to_string(),
        4433,
        "quic".to_string(),
        &authority,
    );
    assert!(endpoint.verify_signature().unwrap());
}
