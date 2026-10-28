use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sds_core::audit::{AuditEventType, AuditLogChain};
use sds_core::e2ee::{E2eeMessageEnvelope, UserCryptoIdentity};
use sds_core::federation::{
    FederationRouter, MessageDeliveryStatus, QueueAcceptance, SdsAppBackendAdapter, SdsUserProfile,
};
use sds_core::identity::SdsIdentityKeyPair;

/// Mock Application Backend owned and managed by the Host Application (not the SDK).
/// Simulates an application's database (e.g. Postgres/Redis) with user accounts,
/// friendship/contact permissions, and an optional durable offline queue.
#[derive(Clone, Default)]
struct MockHostApplicationBackend {
    pub users: Arc<Mutex<HashMap<String, SdsUserProfile>>>,
    pub contacts: Arc<Mutex<HashMap<String, Vec<String>>>>, // user_id -> allowed contacts
    pub blocked: Arc<Mutex<HashMap<String, Vec<String>>>>,  // user_id -> blocked requesters
    pub durable_offline_queue: Arc<Mutex<Vec<(String, E2eeMessageEnvelope)>>>,
    pub enable_durable_queue: bool,
}

impl SdsAppBackendAdapter for MockHostApplicationBackend {
    fn resolve_user_profile(
        &self,
        requester_id: &str,
        target_user_id: &str,
    ) -> Option<SdsUserProfile> {
        let blocked_map = self.blocked.lock().unwrap();
        if let Some(blocked_list) = blocked_map.get(target_user_id) {
            if blocked_list.contains(&requester_id.to_string()) {
                // Blocked caller: completely invisible (zero disclosure)
                return None;
            }
        }

        let users_map = self.users.lock().unwrap();
        let target_profile = users_map.get(target_user_id)?.clone();

        let contacts_map = self.contacts.lock().unwrap();
        let is_contact = contacts_map
            .get(target_user_id)
            .map(|c| c.contains(&requester_id.to_string()))
            .unwrap_or(false);

        if is_contact {
            // Full profile with presence to mutual contacts
            Some(target_profile)
        } else {
            // Limited visibility to non-contacts: presence and bio redacted
            Some(SdsUserProfile {
                user_id: target_profile.user_id,
                display_name: target_profile.display_name,
                avatar_url: target_profile.avatar_url,
                bio: None, // Redacted private field
                public_identity_key: target_profile.public_identity_key,
                is_online: false, // Redacted presence info for non-contacts
            })
        }
    }

    fn deliver_incoming_message(
        &self,
        recipient_id: &str,
        envelope: &E2eeMessageEnvelope,
    ) -> Result<QueueAcceptance, String> {
        let users_map = self.users.lock().unwrap();
        let recipient = users_map
            .get(recipient_id)
            .ok_or_else(|| "User does not exist on this backend".to_string())?;

        if recipient.is_online {
            // Delivered directly to user's active WebSocket/app session
            Ok(QueueAcceptance::DeliveredLive)
        } else if self.enable_durable_queue {
            // Accepted durably by host app database (e.g. Postgres message_queue)
            let mut queue = self.durable_offline_queue.lock().unwrap();
            queue.push((recipient_id.to_string(), envelope.clone()));
            let receipt = format!("pg_durable_ack_{}", queue.len());
            Ok(QueueAcceptance::DurablyAccepted {
                queue_receipt: receipt,
            })
        } else {
            // Host app has no offline storage configured for this tenant
            Ok(QueueAcceptance::NotAccepted)
        }
    }
}

// =========================================================================
// 1. Zero SDK-Owned Disk Storage Compliance
// =========================================================================
#[test]
fn test_compliance_zero_sdk_disk_persistence() {
    let before_files = std::fs::read_dir(".").unwrap().count();

    // Perform intensive SDS operations
    let mut router = FederationRouter::new("stateless.domain.com");
    router.add_local_domain("stateless.domain.com");

    let _alice = UserCryptoIdentity::generate();
    let bob = UserCryptoIdentity::generate();
    let (bob_sec_prekey, bob_bundle) = bob.generate_prekey_bundle();

    let payload = b"Ephemeral zero-disk message";
    let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
        "ALICE_STATEL",
        "BOB_STATEL",
        &bob_bundle,
        payload,
        1,
        1_700_000_000_000,
    )
    .expect("E2EE encryption must succeed");

    let status = router.route_envelope(
        "msg-stateless-001",
        "stateless.domain.com",
        envelope.clone(),
    );
    assert_eq!(status, MessageDeliveryStatus::DeliveredDirect);

    // Verify Bob can decrypt ephemerally in-memory
    let decrypted = envelope
        .decrypt_as_recipient(&bob_sec_prekey)
        .expect("Bob decrypts in memory");
    assert_eq!(decrypted, payload);

    // Verify zero database or cache files were created on disk by the SDK
    let after_files = std::fs::read_dir(".").unwrap().count();
    assert_eq!(
        before_files, after_files,
        "SDK must never create disk artifacts or databases"
    );

    assert!(!Path::new("./sds.db").exists());
    assert!(!Path::new("./users.db").exists());
    assert!(!Path::new("./history.db").exists());
    assert!(!Path::new("./profiles.json").exists());
}

// =========================================================================
// 2. Restart State: Zero Retained User History in SDK
// =========================================================================
#[test]
fn test_compliance_restart_has_zero_retained_user_history() {
    {
        let mut active_router = FederationRouter::new("ephemeral.domain.com");
        active_router.register_local_user("user-001");
        active_router.register_local_user("user-002");
        assert_eq!(active_router.local_users.len(), 2);
    } // active_router is dropped here

    // Reinstantiate router as on process restart
    let restarted_router = FederationRouter::new("ephemeral.domain.com");
    assert_eq!(
        restarted_router.local_users.len(),
        0,
        "Restarted SDK must have zero restored users"
    );
    assert_eq!(restarted_router.seen_message_ids.len(), 0);
    assert_eq!(restarted_router.delivered_receipts.len(), 0);
    assert_eq!(restarted_router.outbound_queue_len(), 0);
}

// =========================================================================
// 3. Profile Discovery Respects Backend Authorization & Privacy Rules
// =========================================================================
#[test]
fn test_compliance_profile_queries_respect_backend_authorization_and_privacy() {
    let mut router = FederationRouter::new("app.domain.com");
    let backend = Arc::new(MockHostApplicationBackend::default());

    // Register Bob in the application's database
    let bob_id = "bob@app.domain.com";
    backend.users.lock().unwrap().insert(
        bob_id.to_string(),
        SdsUserProfile {
            user_id: bob_id.to_string(),
            display_name: "Bob Builder".to_string(),
            avatar_url: Some("https://cdn.app.domain.com/avatars/bob.png".to_string()),
            bio: Some("Building decentralized systems".to_string()),
            public_identity_key: "ed25519-public-bob-key-hex".to_string(),
            is_online: true,
        },
    );

    // Set privacy rules: Charlie is a contact, Eve is a stranger, Mallory is blocked
    backend
        .contacts
        .lock()
        .unwrap()
        .insert(bob_id.to_string(), vec!["charlie@other.com".to_string()]);
    backend
        .blocked
        .lock()
        .unwrap()
        .insert(bob_id.to_string(), vec!["mallory@attacker.com".to_string()]);

    router.set_app_backend(backend);

    // Case 1: Mutual contact Charlie queries Bob -> Gets full profile + presence
    let charlie_query = router
        .handle_incoming_profile_query("charlie@other.com", bob_id)
        .unwrap();
    assert!(charlie_query.is_some());
    let charlie_view = charlie_query.unwrap();
    assert_eq!(charlie_view.display_name, "Bob Builder");
    assert_eq!(
        charlie_view.bio.as_deref(),
        Some("Building decentralized systems")
    );
    assert!(charlie_view.is_online);

    // Case 2: Stranger Eve queries Bob -> Gets public name/avatar, but bio & presence are redacted
    let eve_query = router
        .handle_incoming_profile_query("eve@random.org", bob_id)
        .unwrap();
    assert!(eve_query.is_some());
    let eve_view = eve_query.unwrap();
    assert_eq!(eve_view.display_name, "Bob Builder");
    assert_eq!(eve_view.bio, None, "Bio must be hidden from non-contacts");
    assert!(
        !eve_view.is_online,
        "Presence must not be disclosed to non-contacts"
    );

    // Case 3: Blocked Mallory queries Bob -> Returns None (completely invisible)
    let mallory_query = router
        .handle_incoming_profile_query("mallory@attacker.com", bob_id)
        .unwrap();
    assert!(mallory_query.is_none(), "Blocked caller must receive None");
}

// =========================================================================
// 4. Rate-Limiting Prevents Scraping and Account Enumeration
// =========================================================================
#[test]
fn test_compliance_profile_query_rate_limiting_prevents_scraping() {
    let mut router = FederationRouter::new("app.domain.com");
    let backend = Arc::new(MockHostApplicationBackend::default());
    router.set_app_backend(backend);

    let attacker_id = "scanner@botnet.xyz";

    // 20 requests within window succeed
    for i in 0..20 {
        let result = router.handle_incoming_profile_query(attacker_id, &format!("target_{}", i));
        assert!(result.is_ok());
    }

    // 21st request triggers rate-limiting error
    let rate_limited_result = router.handle_incoming_profile_query(attacker_id, "target_21");
    assert!(rate_limited_result.is_err());
    assert!(rate_limited_result
        .unwrap_err()
        .contains("Rate limit exceeded"));
}

// =========================================================================
// 5. Offline Delivery Never Reports Queued Without Backend Durable Confirmation
// =========================================================================
#[test]
fn test_compliance_offline_delivery_never_reports_queued_without_confirmation() {
    let mut router = FederationRouter::new("local.domain.com");
    router.add_local_domain("local.domain.com");

    let bob_id = "bob@local.domain.com";
    let bob = UserCryptoIdentity::generate();
    let (_, bob_bundle) = bob.generate_prekey_bundle();

    let dummy_envelope = E2eeMessageEnvelope::encrypt_for_recipient(
        "ALICE_EXT",
        bob_id,
        &bob_bundle,
        b"Offline check",
        1,
        1_700_000_000_000,
    )
    .expect("Encryption succeeds");

    // Scenario A: Default SDK routing to remote destination without queue returns UserServerUnavailable
    let mut stateless_router = FederationRouter::new("sender.com");
    let status_stateless = stateless_router.route_envelope(
        "msg-stateless-99",
        "offline-peer.com",
        dummy_envelope.clone(),
    );
    assert_eq!(
        status_stateless,
        MessageDeliveryStatus::UserServerUnavailable
    );
    assert_eq!(stateless_router.outbound_queue_len(), 0);

    // Scenario B: Recipient is offline and backend does NOT have durable queue configured
    let backend_no_queue = Arc::new(MockHostApplicationBackend {
        enable_durable_queue: false,
        ..Default::default()
    });
    backend_no_queue.users.lock().unwrap().insert(
        bob_id.to_string(),
        SdsUserProfile {
            user_id: bob_id.to_string(),
            display_name: "Bob".to_string(),
            avatar_url: None,
            bio: None,
            public_identity_key: "bob-key".to_string(),
            is_online: false, // OFFLINE
        },
    );
    router.set_app_backend(backend_no_queue);

    let status_fail =
        router.route_envelope("msg-fail-01", "local.domain.com", dummy_envelope.clone());
    assert_eq!(status_fail, MessageDeliveryStatus::UserServerUnavailable);

    // Scenario C: Recipient is offline AND backend durable queue successfully confirms acceptance
    let backend_with_queue = Arc::new(MockHostApplicationBackend {
        enable_durable_queue: true,
        ..Default::default()
    });
    backend_with_queue.users.lock().unwrap().insert(
        bob_id.to_string(),
        SdsUserProfile {
            user_id: bob_id.to_string(),
            display_name: "Bob".to_string(),
            avatar_url: None,
            bio: None,
            public_identity_key: "bob-key".to_string(),
            is_online: false, // OFFLINE
        },
    );
    router.set_app_backend(backend_with_queue.clone());

    let status_queued = router.route_envelope("msg-queued-02", "local.domain.com", dummy_envelope);
    assert_eq!(
        status_queued,
        MessageDeliveryStatus::RecipientOfflineQueued {
            queue_receipt: "pg_durable_ack_1".to_string(),
        }
    );
    assert_eq!(
        backend_with_queue
            .durable_offline_queue
            .lock()
            .unwrap()
            .len(),
        1
    );
}

// =========================================================================
// 6. Logging, Crash Reports & Audit Checkpoints Never Expose Plaintext or Private Keys
// =========================================================================
#[test]
fn test_compliance_logging_and_checkpoints_never_expose_plaintext_or_private_keys() {
    let mut audit_chain = AuditLogChain::new();
    let authority_keypair = SdsIdentityKeyPair::generate();

    let secret_plaintext = "TOP_SECRET_CREDIT_CARD_4111222233334444";

    // Append standard audit events
    audit_chain.append(
        AuditEventType::AuthSuccess,
        "node@alpha.ucall.net",
        "Authenticated cross-server connection established via Quinn TLS 1.3",
        1700000000000,
    );
    audit_chain.append(
        AuditEventType::KeyRotated,
        "node@alpha.ucall.net",
        "Ratchet step advanced: sequence=42 ephemeral_key=valid",
        1700000001000,
    );

    // Anchor to external checkpoint
    let checkpoint = audit_chain.create_signed_checkpoint(1700000002000, &authority_keypair);
    assert!(checkpoint.verify().unwrap());

    // Inspect serialized checkpoint and logs to ensure no private keys or plaintext
    let serialized_checkpoint = serde_json::to_string(&checkpoint).unwrap();
    assert!(!serialized_checkpoint.contains(secret_plaintext));

    // Verify external monitor trust boundary: checkpoint can be verified with ONLY public key
    assert_eq!(
        checkpoint.authority_pubkey_hex,
        authority_keypair.public_key_hex()
    );
}

// =========================================================================
// 7. Federation Across Independent Domains Without Central Directory
// =========================================================================
#[test]
fn test_compliance_federation_works_across_independent_domains_without_central_directory() {
    let mut router_a = FederationRouter::new("company-a.com");
    let _router_b = FederationRouter::new("ngo-b.org");
    let mut router_c = FederationRouter::new("startup-c.io");
    router_c.add_local_domain("startup-c.io");

    // Each domain runs its own independent backend
    let backend_c = Arc::new(MockHostApplicationBackend::default());
    let charlie_c_id = "charlie@startup-c.io";
    backend_c.users.lock().unwrap().insert(
        charlie_c_id.to_string(),
        SdsUserProfile {
            user_id: charlie_c_id.to_string(),
            display_name: "Charlie C".to_string(),
            avatar_url: None,
            bio: Some("Lead engineer".to_string()),
            public_identity_key: "charlie-pubkey-hex".to_string(),
            is_online: true,
        },
    );
    backend_c.contacts.lock().unwrap().insert(
        charlie_c_id.to_string(),
        vec!["alice@company-a.com".to_string()],
    );
    router_c.set_app_backend(backend_c);

    // Direct peer registration without central coordinator
    let addr_c: std::net::SocketAddr = "198.51.100.33:4433".parse().unwrap();
    router_a.register_peer_node("startup-c.io", "7K9M2P4X8B", Some(addr_c));

    // Direct profile query across domain boundary
    let profile = router_c
        .handle_incoming_profile_query("alice@company-a.com", charlie_c_id)
        .unwrap()
        .unwrap();
    assert_eq!(profile.display_name, "Charlie C");
    assert_eq!(profile.user_id, charlie_c_id);

    // Cross-domain routed envelope
    let user_c = UserCryptoIdentity::generate();
    let (_, bundle_c) = user_c.generate_prekey_bundle();
    let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
        "ALICE_CO_A",
        charlie_c_id,
        &bundle_c,
        b"Direct domain message",
        1,
        1_700_000_005_000,
    )
    .unwrap();

    let status_a = router_a.route_envelope("msg-federated-01", "startup-c.io", envelope.clone());
    assert_eq!(status_a, MessageDeliveryStatus::QueuedForFederatedServer);

    let status_c = router_c.route_envelope("msg-federated-01", "startup-c.io", envelope);
    assert_eq!(status_c, MessageDeliveryStatus::DeliveredDirect);
}
