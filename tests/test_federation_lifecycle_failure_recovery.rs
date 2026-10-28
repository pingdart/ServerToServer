use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sds_core::audit::{AuditEventType, AuditLogChain};
use sds_core::e2ee::{E2eeMessageEnvelope, UserCryptoIdentity};
use sds_core::federation::{
    FederationRouter, MessageDeliveryStatus, QueueAcceptance, SdsAppBackendAdapter, SdsUserProfile,
};
use sds_core::identity::{SdsIdentityKeyPair, SdsKeyRotationCertificate};

/// Realistic host application backend for each independent domain.
/// Demonstrates that each application backend manages its own persistent user database,
/// while the UCall SDS SDK core remains strictly stateless.
#[derive(Default)]
struct TestDomainAppBackend {
    pub domain_name: String,
    pub users: Arc<Mutex<HashMap<String, SdsUserProfile>>>,
    pub durable_queue: Arc<Mutex<Vec<(String, E2eeMessageEnvelope)>>>,
    pub enable_durable_queue: AtomicBool,
}

impl SdsAppBackendAdapter for TestDomainAppBackend {
    fn resolve_user_profile(
        &self,
        _requester_id: &str,
        target_user_id: &str,
    ) -> Option<SdsUserProfile> {
        let map = self.users.lock().unwrap();
        map.get(target_user_id).cloned()
    }

    fn deliver_incoming_message(
        &self,
        recipient_id: &str,
        envelope: &E2eeMessageEnvelope,
    ) -> Result<QueueAcceptance, String> {
        let users_map = self.users.lock().unwrap();
        let recipient = users_map.get(recipient_id).ok_or_else(|| {
            format!(
                "User {} not found on domain {}",
                recipient_id, self.domain_name
            )
        })?;

        if recipient.is_online {
            Ok(QueueAcceptance::DeliveredLive)
        } else if self.enable_durable_queue.load(Ordering::SeqCst) {
            let mut queue = self.durable_queue.lock().unwrap();
            queue.push((recipient_id.to_string(), envelope.clone()));
            let receipt = format!("{}_durable_tx_{}", self.domain_name, queue.len());
            Ok(QueueAcceptance::DurablyAccepted {
                queue_receipt: receipt,
            })
        } else {
            Ok(QueueAcceptance::NotAccepted)
        }
    }
}

#[test]
fn test_end_to_end_three_server_lifecycle_failure_and_recovery() {
    // =========================================================================
    // 1. Establish identities and secure sessions across three independent domains
    // =========================================================================
    let alpha_key = SdsIdentityKeyPair::generate();
    let _beta_key = SdsIdentityKeyPair::generate();
    let _gamma_key = SdsIdentityKeyPair::generate();

    let mut router_alpha = FederationRouter::new("alpha.org");
    let mut router_beta = FederationRouter::new("beta.net");
    let mut router_gamma = FederationRouter::new("gamma.io");

    // Configure independent application backends
    let backend_alpha = Arc::new(TestDomainAppBackend {
        domain_name: "alpha.org".to_string(),
        ..Default::default()
    });
    let backend_beta = Arc::new(TestDomainAppBackend {
        domain_name: "beta.net".to_string(),
        ..Default::default()
    });
    let backend_gamma = Arc::new(TestDomainAppBackend {
        domain_name: "gamma.io".to_string(),
        ..Default::default()
    });

    let alice_id = "alice@alpha.org";
    let bob_id = "bob@beta.net";
    let carol_id = "carol@gamma.io";

    let alice_crypto = UserCryptoIdentity::generate();
    let bob_crypto = UserCryptoIdentity::generate();
    let carol_crypto = UserCryptoIdentity::generate();

    let (_, bob_bundle) = bob_crypto.generate_prekey_bundle();
    let (carol_prekey_secret, carol_bundle) = carol_crypto.generate_prekey_bundle();

    // Populate user profiles on respective host application databases
    backend_alpha.users.lock().unwrap().insert(
        alice_id.to_string(),
        SdsUserProfile {
            user_id: alice_id.to_string(),
            display_name: "Alice Alpha".to_string(),
            avatar_url: None,
            bio: None,
            public_identity_key: alice_crypto.public_identity_hex(),
            is_online: true,
        },
    );

    backend_beta.users.lock().unwrap().insert(
        bob_id.to_string(),
        SdsUserProfile {
            user_id: bob_id.to_string(),
            display_name: "Bob Beta".to_string(),
            avatar_url: None,
            bio: None,
            public_identity_key: bob_crypto.public_identity_hex(),
            is_online: true,
        },
    );

    backend_gamma.users.lock().unwrap().insert(
        carol_id.to_string(),
        SdsUserProfile {
            user_id: carol_id.to_string(),
            display_name: "Carol Gamma".to_string(),
            avatar_url: None,
            bio: None,
            public_identity_key: carol_crypto.public_identity_hex(),
            is_online: true,
        },
    );

    router_alpha.set_app_backend(backend_alpha.clone());
    router_beta.set_app_backend(backend_beta.clone());
    router_gamma.set_app_backend(backend_gamma.clone());

    // Register active peer connections between servers with initial key epoch 1
    let addr_alpha: SocketAddr = "198.51.100.10:4433".parse().unwrap();
    let addr_beta: SocketAddr = "198.51.100.20:4433".parse().unwrap();
    let addr_gamma: SocketAddr = "198.51.100.30:4433".parse().unwrap();

    router_alpha.register_peer_node("beta.net", "BETA_ID_01", Some(addr_beta));
    router_alpha.register_peer_node("gamma.io", "GAMMA_ID_01", Some(addr_gamma));

    router_beta.register_peer_node_with_key(
        "alpha.org",
        "ALPHA_ID_01",
        Some(addr_alpha),
        &alpha_key.public_key_hex(),
        1,
    );
    router_beta.register_peer_node("gamma.io", "GAMMA_ID_01", Some(addr_gamma));

    // =========================================================================
    // 2. Deliver messages while all peers are online
    // =========================================================================
    let msg1_payload = b"Cross-server federated message from Alice to Bob";
    let envelope1 = E2eeMessageEnvelope::encrypt_for_recipient(
        alice_id,
        bob_id,
        &bob_bundle,
        msg1_payload,
        1,
        1700000000000,
    )
    .unwrap();

    // Alpha routes toward Beta -> QueuedForFederatedServer
    let status_alpha = router_alpha.route_envelope("msg-001", "beta.net", envelope1.clone());
    assert_eq!(
        status_alpha,
        MessageDeliveryStatus::QueuedForFederatedServer
    );

    // Beta receives envelope and delivers to local Bob (online) -> DeliveredDirect
    let status_beta = router_beta.route_envelope("msg-001", "beta.net", envelope1.clone());
    assert_eq!(status_beta, MessageDeliveryStatus::DeliveredDirect);

    // =========================================================================
    // 3. Disconnect one destination and verify exact queue-status contract
    // =========================================================================
    // Set Carol offline on Gamma
    backend_gamma
        .users
        .lock()
        .unwrap()
        .get_mut(carol_id)
        .unwrap()
        .is_online = false;

    let envelope_carol = E2eeMessageEnvelope::encrypt_for_recipient(
        alice_id,
        carol_id,
        &carol_bundle,
        b"Offline delivery check for Carol",
        2,
        1700000001000,
    )
    .unwrap();

    // Case 3a: Gamma has NO durable queue configured -> Returns UserServerUnavailable (Zero SDK persistence)
    backend_gamma
        .enable_durable_queue
        .store(false, Ordering::SeqCst);
    let status_gamma_fail =
        router_gamma.route_envelope("msg-offline-fail", "gamma.io", envelope_carol.clone());
    assert_eq!(
        status_gamma_fail,
        MessageDeliveryStatus::UserServerUnavailable
    );

    // Case 3b: Gamma host application confirms durable queue acceptance -> Returns RecipientOfflineQueued { queue_receipt }
    backend_gamma
        .enable_durable_queue
        .store(true, Ordering::SeqCst);
    let status_gamma_queued =
        router_gamma.route_envelope("msg-offline-queued", "gamma.io", envelope_carol.clone());
    match status_gamma_queued {
        MessageDeliveryStatus::RecipientOfflineQueued { queue_receipt } => {
            assert_eq!(queue_receipt, "gamma.io_durable_tx_1");
        }
        other => panic!("Expected RecipientOfflineQueued, got {:?}", other),
    }
    assert_eq!(backend_gamma.durable_queue.lock().unwrap().len(), 1);

    // =========================================================================
    // 4. Prove Queue Recovery Independently of Router Memory Across Process Restarts
    // =========================================================================
    // Completely destroy Server Gamma router process/memory
    drop(router_gamma);

    // Instantiate a completely fresh Gamma router (zero restored internal queue memory)
    let mut router_gamma_recovered = FederationRouter::new("gamma.io");
    router_gamma_recovered.add_local_domain("gamma.io");
    assert_eq!(router_gamma_recovered.outbound_queue_len(), 0);

    // Attach host application backend to fresh router
    router_gamma_recovered.set_app_backend(backend_gamma.clone());

    // Carol comes back online; host application drains its durable queue
    backend_gamma
        .users
        .lock()
        .unwrap()
        .get_mut(carol_id)
        .unwrap()
        .is_online = true;
    let (recipient_id, queued_envelope) =
        backend_gamma.durable_queue.lock().unwrap().pop().unwrap();
    assert_eq!(recipient_id, carol_id);

    // Recovered router delivers retrieved envelope directly to live Carol session
    let status_recovered = router_gamma_recovered.route_envelope(
        "msg-offline-queued",
        "gamma.io",
        queued_envelope.clone(),
    );
    assert_eq!(status_recovered, MessageDeliveryStatus::DeliveredDirect);

    // Resending duplicate message ID "msg-offline-queued" triggers duplicate suppression
    let status_dup_recovered =
        router_gamma_recovered.route_envelope("msg-offline-queued", "gamma.io", queued_envelope);
    assert_eq!(
        status_dup_recovered,
        MessageDeliveryStatus::DuplicateIgnored
    );

    // Carol decrypts payload in memory
    let decrypted_carol = envelope_carol
        .decrypt_as_recipient(&carol_prekey_secret)
        .unwrap();
    assert_eq!(decrypted_carol, b"Offline delivery check for Carol");

    // =========================================================================
    // 5. Strengthened Chain-of-Custody Key Rotation & Anti-Rollback Verification
    // =========================================================================
    let alpha_new_key = SdsIdentityKeyPair::generate();
    let rotation_cert = SdsKeyRotationCertificate::sign_rotation(
        "alpha.org",
        &alpha_key,
        &alpha_new_key.public_key_hex(),
        2,
        1700000002000,
    );

    // 5a. Legitimate key rotation to epoch 2 verifies and updates peer state
    assert!(router_beta.apply_peer_key_rotation(&rotation_cert).is_ok());
    assert_eq!(
        router_beta
            .federated_peers
            .get("alpha.org")
            .unwrap()
            .current_key_epoch,
        2
    );
    assert_eq!(
        router_beta
            .federated_peers
            .get("alpha.org")
            .unwrap()
            .authority_pubkey_hex,
        alpha_new_key.public_key_hex()
    );

    // 5b. Stale / Replayed certificate rejection (epoch 2 replayed or epoch 1 rollback)
    let stale_cert = SdsKeyRotationCertificate::sign_rotation(
        "alpha.org",
        &alpha_key,
        &alpha_new_key.public_key_hex(),
        2,
        1700000002000,
    );
    let replay_err = router_beta
        .apply_peer_key_rotation(&stale_cert)
        .unwrap_err();
    assert!(replay_err.contains("Stale or rollback key epoch"));

    // 5c. Domain mismatch rejection
    let wrong_domain_cert = SdsKeyRotationCertificate::sign_rotation(
        "evil-corp.com",
        &alpha_key,
        &alpha_new_key.public_key_hex(),
        3,
        1700000003000,
    );
    assert!(router_beta
        .apply_peer_key_rotation(&wrong_domain_cert)
        .is_err());

    // 5d. Revoked / Mismatched old key rejection
    let rogue_key = SdsIdentityKeyPair::generate();
    let cert_revoked_old_key = SdsKeyRotationCertificate::sign_rotation(
        "alpha.org",
        &alpha_key, // Revoked epoch-1 key! Current trusted key is alpha_new_key (epoch 2)
        &rogue_key.public_key_hex(),
        3,
        1700000003000,
    );
    let revoked_err = router_beta
        .apply_peer_key_rotation(&cert_revoked_old_key)
        .unwrap_err();
    assert!(revoked_err
        .contains("Old public key in rotation certificate does not match current trusted key"));

    // 5e. Forged key signature rejection (correct old key, but signature does not match altered payload)
    let mut forged_cert = rotation_cert.clone();
    forged_cert.old_public_key_hex = alpha_new_key.public_key_hex();
    forged_cert.epoch = 3;
    forged_cert.new_public_key_hex = rogue_key.public_key_hex();
    let forged_err = router_beta
        .apply_peer_key_rotation(&forged_cert)
        .unwrap_err();
    assert!(forged_err.contains("Invalid cryptographic signature"));

    // =========================================================================
    // 6. Explicit Persistence Boundary Verification
    // =========================================================================
    // Drop and re-instantiate Server Beta router
    drop(router_beta);
    let mut router_beta_restarted = FederationRouter::new("beta.net");

    // SDK-owned storage invariant: zero restored users or receipts
    assert_eq!(router_beta_restarted.local_users.len(), 0);
    assert_eq!(router_beta_restarted.outbound_queue_len(), 0);
    assert_eq!(router_beta_restarted.delivered_receipts.len(), 0);
    assert!(!Path::new("./beta_users.db").exists());
    assert!(!Path::new("./beta_messages.db").exists());

    // Application-owned storage invariant: host application database remains fully intact
    assert!(backend_beta.users.lock().unwrap().contains_key(bob_id));
    router_beta_restarted.set_app_backend(backend_beta.clone());
    let bob_profile = router_beta_restarted
        .handle_incoming_profile_query("alice@alpha.org", bob_id)
        .unwrap()
        .unwrap();
    assert_eq!(bob_profile.display_name, "Bob Beta");

    // =========================================================================
    // 7. External Audit Checkpoint Anchoring: Historical Rewriting & Truncation Detection
    // =========================================================================
    let mut audit_chain = AuditLogChain::new();
    audit_chain.append(
        AuditEventType::AuthSuccess,
        "node@alpha.org",
        "QUIC TLS 1.3 handshake verified with beta.net",
        1700000000000,
    );
    let genuine_checkpoint_epoch1 = audit_chain.create_signed_checkpoint(1700000001000, &alpha_key);

    audit_chain.append(
        AuditEventType::KeyRotated,
        "node@alpha.org",
        "Server authority rotated to epoch 2",
        1700000002000,
    );
    let genuine_checkpoint_epoch2 = audit_chain.create_signed_checkpoint(1700000003000, &alpha_key);

    // External witness verifies current anchored state
    assert!(genuine_checkpoint_epoch2
        .verify_against_anchored_state(&alpha_key.public_key_hex(), 1700000001000, 1)
        .is_ok());

    // Threat 7a: Historical log rewriting (altered past details)
    let mut rewritten_chain = AuditLogChain::new();
    rewritten_chain.append(
        AuditEventType::AuthSuccess,
        "node@alpha.org",
        "ALTERED: Unauthorized session injected",
        1700000000000,
    );
    rewritten_chain.append(
        AuditEventType::KeyRotated,
        "node@alpha.org",
        "Server authority rotated to epoch 2",
        1700000002000,
    );
    assert_ne!(
        rewritten_chain.head_hash(),
        audit_chain.head_hash(),
        "External checkpoint detects historical log rewrite"
    );

    // Threat 7b: Truncation & Rollback attack (presenting genuine but stale epoch-1 checkpoint)
    let rollback_result = genuine_checkpoint_epoch1.verify_against_anchored_state(
        &alpha_key.public_key_hex(),
        1700000003000,
        2,
    );
    assert!(
        rollback_result.is_err(),
        "External verifier detects stale checkpoint rollback/truncation"
    );
}
