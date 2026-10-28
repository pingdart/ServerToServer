use sds_core::e2ee::*;
use sds_core::federation::*;
use sds_core::identity::SdsIdentityKeyPair;
use sds_core::profile::*;
use std::net::SocketAddr;

#[test]
fn test_three_server_mesh_interoperability_and_e2ee() {
    // =========================================================================
    // 1. Setup Three Independent Servers with Unique Domains & Ed25519 Keys
    // =========================================================================
    let server_a_authority = SdsIdentityKeyPair::generate();
    let server_b_authority = SdsIdentityKeyPair::generate();
    let server_c_authority = SdsIdentityKeyPair::generate();

    let mut router_a = FederationRouter::new("alpha.ucall.net");
    let mut router_b = FederationRouter::new("beta.ucall.net");
    let mut router_c = FederationRouter::new("gamma.ucall.net");

    let addr_a: SocketAddr = "192.0.2.1:4433".parse().unwrap();
    let addr_b: SocketAddr = "198.51.100.2:4433".parse().unwrap();
    let addr_c: SocketAddr = "203.0.113.3:4433".parse().unwrap();

    // Register mesh topology
    router_a.register_peer_node("beta.ucall.net", "BETA223344", Some(addr_b));
    router_a.register_peer_node("gamma.ucall.net", "GAMMA33445", Some(addr_c));

    router_b.register_peer_node("alpha.ucall.net", "ALPHA11223", Some(addr_a));
    router_b.register_peer_node("gamma.ucall.net", "GAMMA33445", Some(addr_c));

    router_c.register_peer_node("alpha.ucall.net", "ALPHA11223", Some(addr_a));
    router_c.register_peer_node("beta.ucall.net", "BETA223344", Some(addr_b));

    // Register local users on each server
    router_a.register_local_user("user-1");
    router_b.register_local_user("user-2");
    router_c.register_local_user("user-3");

    // =========================================================================
    // 2. Publish Signed Application Profiles for Each Server
    // =========================================================================
    let logo_data = b"MOCK_PNG_BYTE_STREAM_FOR_APP_LOGO";

    let profile_a = SdsAppProfile::sign_new(
        "alpha.ucall.net".to_string(),
        "ALPHA11223".to_string(),
        "alpha-chat".to_string(),
        "Alpha Secure Messenger".to_string(),
        "https://alpha.ucall.net/logo.png".to_string(),
        logo_data,
        "https://alpha.ucall.net".to_string(),
        vec![
            "messaging".to_string(),
            "voice".to_string(),
            "video".to_string(),
            "e2ee".to_string(),
        ],
        &server_a_authority,
    );

    let profile_b = SdsAppProfile::sign_new(
        "beta.ucall.net".to_string(),
        "BETA223344".to_string(),
        "beta-team".to_string(),
        "Beta Enterprise Voice".to_string(),
        "https://beta.ucall.net/logo.png".to_string(),
        logo_data,
        "https://beta.ucall.net".to_string(),
        vec![
            "messaging".to_string(),
            "voice".to_string(),
            "video".to_string(),
            "e2ee".to_string(),
        ],
        &server_b_authority,
    );

    let profile_c = SdsAppProfile::sign_new(
        "gamma.ucall.net".to_string(),
        "GAMMA33445".to_string(),
        "gamma-portal".to_string(),
        "Gamma Global Connect".to_string(),
        "https://gamma.ucall.net/logo.png".to_string(),
        logo_data,
        "https://gamma.ucall.net".to_string(),
        vec![
            "messaging".to_string(),
            "voice".to_string(),
            "video".to_string(),
            "e2ee".to_string(),
        ],
        &server_c_authority,
    );

    // Verify all profiles cryptographically before client UI acceptance
    assert!(profile_a.verify_signature().unwrap());
    assert!(profile_b.verify_signature().unwrap());
    assert!(profile_c.verify_signature().unwrap());
    assert_eq!(profile_a.app_name, "Alpha Secure Messenger");
    assert_eq!(profile_b.app_name, "Beta Enterprise Voice");
    assert_eq!(profile_c.app_name, "Gamma Global Connect");

    // =========================================================================
    // 3. User Crypto Identities & Prekey Bundles (User 1, User 2, User 3)
    // =========================================================================
    let _user1 = UserCryptoIdentity::generate();
    let _user2 = UserCryptoIdentity::generate();
    let user3 = UserCryptoIdentity::generate();

    let (user3_secret_prekey, user3_bundle) = user3.generate_prekey_bundle();

    // =========================================================================
    // 4. Cross-Server E2EE Message: User 1 (Server A) -> User 3 (Server C)
    // =========================================================================
    let secret_payload = b"Top secret across Server A and Server C via SDS Mesh!";
    let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
        "USER1_ALPHA",
        "USER3_GAMMA",
        &user3_bundle,
        secret_payload,
        1,
        1_700_000_100_000,
    )
    .expect("User 1 E2EE encryption must succeed");

    // Server A receives envelope and routes toward Server C
    let status_a = router_a.route_envelope("msg-mesh-001", "gamma.ucall.net", envelope.clone());
    assert_eq!(status_a, MessageDeliveryStatus::QueuedForFederatedServer);

    // Server C receives envelope and delivers to local User 3
    let status_c = router_c.route_envelope("msg-mesh-001", "gamma.ucall.net", envelope.clone());
    assert_eq!(status_c, MessageDeliveryStatus::DeliveredDirect);

    // Neither Server A nor Server C could read plaintext
    let decrypted = envelope
        .decrypt_as_recipient(&user3_secret_prekey)
        .expect("User 3 decrypts E2EE message");
    assert_eq!(decrypted, secret_payload);

    // =========================================================================
    // 5. Offline & Stateless Policy Handling
    // =========================================================================
    // Under pure stateless SDS SDK: an unroutable destination returns UserServerUnavailable (no disk queue)
    let mut router_a_isolated = FederationRouter::new("alpha.ucall.net");
    let status_offline =
        router_a_isolated.route_envelope("msg-offline-002", "beta.ucall.net", envelope.clone());
    assert_eq!(status_offline, MessageDeliveryStatus::UserServerUnavailable);
    assert_eq!(router_a_isolated.outbound_queue_len(), 0);

    // When the application enables in-memory transit retry:
    router_a_isolated.enable_in_memory_retry = true;
    let status_retry =
        router_a_isolated.route_envelope("msg-retry-003", "beta.ucall.net", envelope.clone());
    assert_eq!(
        status_retry,
        MessageDeliveryStatus::QueuedForFederatedServer
    );
    assert_eq!(router_a_isolated.outbound_queue_len(), 1);

    // Drain queue after reconnecting link to Server B
    let drained = router_a_isolated.drain_outbound_queue();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].destination_domain, "beta.ucall.net");
    assert_eq!(router_a_isolated.outbound_queue_len(), 0);

    // =========================================================================
    // 6. Duplicate Delivery Suppression (Idempotent Routing)
    // =========================================================================
    let status_dup1 =
        router_b.route_envelope("msg-dup-check-99", "beta.ucall.net", envelope.clone());
    assert_eq!(status_dup1, MessageDeliveryStatus::DeliveredDirect);

    // Resubmitting identical envelope ID triggers duplicate suppression
    let status_dup2 =
        router_b.route_envelope("msg-dup-check-99", "beta.ucall.net", envelope.clone());
    assert_eq!(status_dup2, MessageDeliveryStatus::DuplicateIgnored);
}
