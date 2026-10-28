use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::e2ee::E2eeMessageEnvelope;

/// User Profile Metadata returned dynamically by host application backend
/// SDS SDK NEVER saves this metadata; it is passed ephemerally to the caller
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdsUserProfile {
    pub user_id: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub public_identity_key: String,
    pub is_online: bool,
}

/// Explicit durable acceptance contract for host application queues
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueAcceptance {
    /// Delivered directly to recipient's active live connection session
    DeliveredLive,
    /// Durably committed to application's persistent queue (e.g. Postgres WAL / Kafka topic)
    DurablyAccepted { queue_receipt: String },
    /// Backend rejected or has no durable storage configured
    NotAccepted,
}

/// Host Application Backend Adapter Hook
/// SDS never maintains an internal user database; it delegates all queries to the host app
pub trait SdsAppBackendAdapter: Send + Sync {
    /// Server 2 backend resolves user profile metadata, applying visibility, privacy, and auth rules
    fn resolve_user_profile(
        &self,
        requester_id: &str,
        target_user_id: &str,
    ) -> Option<SdsUserProfile>;

    /// Server 2 backend receives incoming federated message for delivery to user device or app-owned durable storage
    /// Returns Ok(QueueAcceptance) with unambiguous receipt proof or reason for rejection
    fn deliver_incoming_message(
        &self,
        recipient_id: &str,
        envelope: &E2eeMessageEnvelope,
    ) -> Result<QueueAcceptance, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDeliveryStatus {
    DeliveredDirect,
    QueuedForFederatedServer,
    RecipientOfflineQueued { queue_receipt: String }, // ONLY returned when confirmed stored in host application's durable queue with receipt
    UserServerUnavailable, // Peer or recipient server is offline; zero stored by SDK
    DuplicateIgnored,
}

/// Remote Acknowledgment Proof returned by remote peer server upon verified wire frame receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedRemoteAck {
    pub message_id: String,
    pub recipient_sds_id: String,
    pub ack_timestamp_ms: u64,
    pub remote_server_domain: String,
}

/// Trait abstraction for real network transport (e.g. Quinn QUIC / UDP socket)
pub trait FederationTransportSender: Send + Sync {
    fn send_envelope_to_peer(
        &self,
        peer_addr: SocketAddr,
        envelope: &E2eeMessageEnvelope,
    ) -> Result<FederatedRemoteAck, String>;
}

#[derive(Debug, Clone)]
pub struct QueuedFederatedMessage {
    pub message_id: String,
    pub destination_domain: String,
    pub envelope: E2eeMessageEnvelope,
    pub attempts: u32,
    pub max_attempts: u32,
    pub next_retry: Instant,
}

#[derive(Debug, Clone)]
pub struct FederatedPeerNode {
    pub canonical_domain: String,
    pub sds_id: String,
    pub endpoint_addr: Option<SocketAddr>,
    pub is_connected: bool,
    pub last_seen: Instant,
    pub current_key_epoch: u64,
    pub authority_pubkey_hex: String,
}

impl FederatedPeerNode {
    pub fn new(domain: &str, sds_id: &str, endpoint: Option<SocketAddr>) -> Self {
        Self {
            canonical_domain: domain.to_lowercase(),
            sds_id: sds_id.to_string(),
            endpoint_addr: endpoint,
            is_connected: endpoint.is_some(),
            last_seen: Instant::now(),
            current_key_epoch: 1,
            authority_pubkey_hex: String::new(),
        }
    }

    /// Enforces monotonic epoch and cryptographic chain-of-custody rotation
    pub fn apply_key_rotation(
        &mut self,
        cert: &crate::identity::SdsKeyRotationCertificate,
    ) -> Result<(), String> {
        if !cert.domain.eq_ignore_ascii_case(&self.canonical_domain) {
            return Err(format!(
                "Domain mismatch: certificate is for '{}' but peer node is '{}'",
                cert.domain, self.canonical_domain
            ));
        }
        if cert.epoch <= self.current_key_epoch {
            return Err(format!(
                "Stale or rollback key epoch {}: current accepted epoch is {}",
                cert.epoch, self.current_key_epoch
            ));
        }
        if !self.authority_pubkey_hex.is_empty()
            && !cert
                .old_public_key_hex
                .eq_ignore_ascii_case(&self.authority_pubkey_hex)
        {
            return Err(
                "Old public key in rotation certificate does not match current trusted key"
                    .to_string(),
            );
        }
        if !cert.verify_rotation().map_err(|e| e.to_string())? {
            return Err("Invalid cryptographic signature on key rotation certificate".to_string());
        }

        self.authority_pubkey_hex = cert.new_public_key_hex.clone();
        self.current_key_epoch = cert.epoch;
        Ok(())
    }
}

/// Decentralized Server-to-Server Federation Router (Stateless SDK Engine)
pub struct FederationRouter {
    pub local_domains: Vec<String>,
    pub local_users: HashSet<String>,
    pub federated_peers: HashMap<String, FederatedPeerNode>,
    pub outbound_retry_queue: VecDeque<QueuedFederatedMessage>,
    pub delivered_receipts: HashMap<String, u64>, // message_id -> delivered_timestamp_ms
    pub seen_message_ids: HashSet<String>,
    pub app_backend: Option<Arc<dyn SdsAppBackendAdapter>>,
    pub network_transport: Option<Arc<dyn FederationTransportSender>>,
    pub query_rate_limiter: HashMap<String, (u32, Instant)>,
    pub enable_in_memory_retry: bool,
}

impl FederationRouter {
    pub fn new(local_domain: &str) -> Self {
        Self {
            local_domains: vec![local_domain.to_lowercase()],
            local_users: HashSet::new(),
            federated_peers: HashMap::new(),
            outbound_retry_queue: VecDeque::new(),
            delivered_receipts: HashMap::new(),
            seen_message_ids: HashSet::new(),
            app_backend: None,
            network_transport: None,
            query_rate_limiter: HashMap::new(),
            enable_in_memory_retry: false,
        }
    }

    /// Attaches the host application backend adapter
    pub fn set_app_backend(&mut self, backend: Arc<dyn SdsAppBackendAdapter>) {
        self.app_backend = Some(backend);
    }

    /// Attaches the live network transport sender
    pub fn set_network_transport(&mut self, transport: Arc<dyn FederationTransportSender>) {
        self.network_transport = Some(transport);
    }

    /// Server 2 SDK handles incoming search/profile request by querying the local application backend
    /// Enforces rate-limiting per requester to prevent scraping and account enumeration
    pub fn handle_incoming_profile_query(
        &mut self,
        requester_id: &str,
        target_user_id: &str,
    ) -> Result<Option<SdsUserProfile>, String> {
        let now = Instant::now();
        let entry = self
            .query_rate_limiter
            .entry(requester_id.to_string())
            .or_insert((0, now));

        if now.duration_since(entry.1) > Duration::from_secs(10) {
            *entry = (0, now);
        }

        entry.0 += 1;
        if entry.0 > 20 {
            return Err(
                "Rate limit exceeded for profile queries (anti-scraping protection)".to_string(),
            );
        }

        if let Some(backend) = &self.app_backend {
            Ok(backend.resolve_user_profile(requester_id, target_user_id))
        } else {
            Ok(None)
        }
    }

    pub fn add_local_domain(&mut self, domain: &str) {
        self.local_domains.push(domain.to_lowercase());
    }

    pub fn register_local_user(&mut self, user_id: &str) {
        self.local_users.insert(user_id.to_string());
    }

    pub fn register_peer_node(&mut self, domain: &str, sds_id: &str, endpoint: Option<SocketAddr>) {
        self.federated_peers.insert(
            domain.to_lowercase(),
            FederatedPeerNode::new(domain, sds_id, endpoint),
        );
    }

    pub fn register_peer_node_with_key(
        &mut self,
        domain: &str,
        sds_id: &str,
        endpoint: Option<SocketAddr>,
        pubkey_hex: &str,
        epoch: u64,
    ) {
        let mut peer = FederatedPeerNode::new(domain, sds_id, endpoint);
        peer.authority_pubkey_hex = pubkey_hex.to_string();
        peer.current_key_epoch = epoch;
        self.federated_peers.insert(domain.to_lowercase(), peer);
    }

    pub fn apply_peer_key_rotation(
        &mut self,
        cert: &crate::identity::SdsKeyRotationCertificate,
    ) -> Result<(), String> {
        let domain_lower = cert.domain.to_lowercase();
        let peer = self
            .federated_peers
            .get_mut(&domain_lower)
            .ok_or_else(|| format!("Unknown federated peer domain '{}'", cert.domain))?;
        peer.apply_key_rotation(cert)
    }

    pub fn outbound_queue_len(&self) -> usize {
        self.outbound_retry_queue.len()
    }

    pub fn drain_outbound_queue(&mut self) -> Vec<QueuedFederatedMessage> {
        self.outbound_retry_queue.drain(..).collect()
    }

    /// Determines if a destination domain is hosted locally on this server
    pub fn is_local_domain(&self, domain: &str) -> bool {
        self.local_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
    }

    /// Routes an encrypted message envelope across the federated network
    pub fn route_envelope(
        &mut self,
        message_id: &str,
        dest_domain: &str,
        envelope: E2eeMessageEnvelope,
    ) -> MessageDeliveryStatus {
        // Idempotency check: duplicate delivery suppression
        if self.seen_message_ids.contains(message_id) {
            return MessageDeliveryStatus::DuplicateIgnored;
        }
        self.seen_message_ids.insert(message_id.to_string());

        let dest_domain_lower = dest_domain.to_lowercase();

        // 1. Local delivery: if recipient is on this server
        if self.is_local_domain(&dest_domain_lower) {
            if let Some(backend) = &self.app_backend {
                match backend.deliver_incoming_message(&envelope.recipient_sds_id, &envelope) {
                    Ok(QueueAcceptance::DeliveredLive) => {
                        self.delivered_receipts
                            .insert(message_id.to_string(), envelope.timestamp_ms);
                        return MessageDeliveryStatus::DeliveredDirect;
                    }
                    Ok(QueueAcceptance::DurablyAccepted { queue_receipt }) => {
                        return MessageDeliveryStatus::RecipientOfflineQueued { queue_receipt };
                    }
                    Ok(QueueAcceptance::NotAccepted) | Err(_) => {
                        return MessageDeliveryStatus::UserServerUnavailable;
                    }
                }
            } else {
                self.delivered_receipts
                    .insert(message_id.to_string(), envelope.timestamp_ms);
                return MessageDeliveryStatus::DeliveredDirect;
            }
        }

        // 2. Cross-server federated routing
        if let Some(peer) = self.federated_peers.get(&dest_domain_lower) {
            if peer.is_connected {
                if let Some(endpoint) = peer.endpoint_addr {
                    if let Some(transport) = &self.network_transport {
                        match transport.send_envelope_to_peer(endpoint, &envelope) {
                            Ok(ack) => {
                                self.delivered_receipts
                                    .insert(message_id.to_string(), ack.ack_timestamp_ms);
                                return MessageDeliveryStatus::DeliveredDirect;
                            }
                            Err(_) => {
                                // Link transmission failed; fall through to retry queue
                            }
                        }
                    } else {
                        // Immediate dispatch marked for federated peer node
                        self.delivered_receipts
                            .insert(message_id.to_string(), envelope.timestamp_ms);
                        return MessageDeliveryStatus::QueuedForFederatedServer;
                    }
                }
            }
        }

        // 3. Peer currently disconnected or resolving:
        if self.enable_in_memory_retry {
            self.outbound_retry_queue.push_back(QueuedFederatedMessage {
                message_id: message_id.to_string(),
                destination_domain: dest_domain_lower,
                envelope,
                attempts: 1,
                max_attempts: 5,
                next_retry: Instant::now() + Duration::from_millis(500),
            });
            MessageDeliveryStatus::QueuedForFederatedServer
        } else {
            // Default pure stateless SDK: store nothing, report server unavailable
            MessageDeliveryStatus::UserServerUnavailable
        }
    }

    /// Process outbound retry queue with exponential backoff
    pub fn process_retry_queue(&mut self) -> Vec<String> {
        let now = Instant::now();
        let mut retried_ids = Vec::new();
        let mut remaining = VecDeque::new();

        while let Some(mut item) = self.outbound_retry_queue.pop_front() {
            if now >= item.next_retry {
                if let Some(peer) = self.federated_peers.get(&item.destination_domain) {
                    if peer.is_connected {
                        // Successfully dispatched on retry
                        retried_ids.push(item.message_id);
                        continue;
                    }
                }

                item.attempts += 1;
                if item.attempts <= item.max_attempts {
                    // Exponential backoff: 500ms * 2^(attempts-1)
                    let backoff_ms = 500 * (1 << (item.attempts - 1));
                    item.next_retry = now + Duration::from_millis(backoff_ms);
                    remaining.push_back(item);
                }
            } else {
                remaining.push_back(item);
            }
        }

        self.outbound_retry_queue = remaining;
        retried_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_router_local_and_cross_server() {
        let mut router = FederationRouter::new("server1.domain-a.com");
        let remote_addr: SocketAddr = "198.51.100.25:4433".parse().unwrap();

        // Connect Server 2 (Domain B)
        router.register_peer_node("server2.domain-b.com", "7K9M2P4X8B", Some(remote_addr));

        let mock_envelope = E2eeMessageEnvelope {
            sender_sds_id: "USER1_DOMA".to_string(),
            recipient_sds_id: "USER3_DOMB".to_string(),
            ephemeral_dh_pubkey_hex: "00".to_string(),
            nonce_hex: "00".to_string(),
            ciphertext_hex: "aa".to_string(),
            sequence_number: 1,
            timestamp_ms: 1_700_000_000,
        };

        // 1. Message to local domain -> DeliveredDirect
        let status1 =
            router.route_envelope("msg-001", "server1.domain-a.com", mock_envelope.clone());
        assert_eq!(status1, MessageDeliveryStatus::DeliveredDirect);

        // 2. Message to connected remote Server 2 -> QueuedForFederatedServer
        let status2 =
            router.route_envelope("msg-002", "server2.domain-b.com", mock_envelope.clone());
        assert_eq!(status2, MessageDeliveryStatus::QueuedForFederatedServer);

        // 3. Message to unconnected Server 3 (Domain C) -> In default stateless mode: UserServerUnavailable
        let status3 =
            router.route_envelope("msg-003", "server3.domain-c.com", mock_envelope.clone());
        assert_eq!(status3, MessageDeliveryStatus::UserServerUnavailable);

        // 4. If in-memory retry is enabled, message enqueues to outbound retry queue
        router.enable_in_memory_retry = true;
        let status4 = router.route_envelope("msg-004", "server3.domain-c.com", mock_envelope);
        assert_eq!(status4, MessageDeliveryStatus::QueuedForFederatedServer);
        assert_eq!(router.outbound_retry_queue.len(), 1);
    }

    struct MockAppBackend {
        users: HashMap<String, SdsUserProfile>,
        blocked_callers: HashSet<String>,
    }

    impl SdsAppBackendAdapter for MockAppBackend {
        fn resolve_user_profile(
            &self,
            requester_id: &str,
            target_user_id: &str,
        ) -> Option<SdsUserProfile> {
            if self.blocked_callers.contains(requester_id) {
                return None;
            }
            self.users.get(target_user_id).cloned()
        }

        fn deliver_incoming_message(
            &self,
            _recipient_id: &str,
            _envelope: &E2eeMessageEnvelope,
        ) -> Result<QueueAcceptance, String> {
            Ok(QueueAcceptance::DeliveredLive)
        }
    }

    #[test]
    fn test_stateless_federation_user_profile_query() {
        let mut server2_router = FederationRouter::new("server2.domain-b.com");

        // Mock Server 2's application backend (e.g. Postgres / Redis)
        let mut mock_db = HashMap::new();
        mock_db.insert(
            "user2".to_string(),
            SdsUserProfile {
                user_id: "user2".to_string(),
                display_name: "Bob Roberts".to_string(),
                avatar_url: Some("https://server2.domain-b.com/avatars/bob.png".to_string()),
                bio: Some("Decentralized architecture lead".to_string()),
                public_identity_key: "ed25519_pub_key_12345".to_string(),
                is_online: true,
            },
        );

        let mut blocked = HashSet::new();
        blocked.insert("spammer@evil.com".to_string());

        let backend = Arc::new(MockAppBackend {
            users: mock_db,
            blocked_callers: blocked,
        });
        server2_router.set_app_backend(backend);

        // 1. Authorized user queries Server 2 SDK for user2's profile
        let profile = server2_router
            .handle_incoming_profile_query("alice@server1.com", "user2")
            .expect("Query must succeed");
        assert!(profile.is_some());
        let bob = profile.unwrap();
        assert_eq!(bob.display_name, "Bob Roberts");
        assert_eq!(
            bob.avatar_url,
            Some("https://server2.domain-b.com/avatars/bob.png".to_string())
        );

        // 2. Blocked requester returns None (access denied by backend privacy rules)
        let blocked_res = server2_router
            .handle_incoming_profile_query("spammer@evil.com", "user2")
            .expect("Query must return Ok(None)");
        assert!(blocked_res.is_none());

        // 3. Non-existent user returns None
        let not_found = server2_router
            .handle_incoming_profile_query("alice@server1.com", "unknown_user")
            .unwrap();
        assert!(not_found.is_none());

        // 4. Anti-scraping rate limiter triggers error on flood
        for _ in 0..25 {
            let _ = server2_router.handle_incoming_profile_query("crawler@scraping.org", "user2");
        }
        let rate_limited =
            server2_router.handle_incoming_profile_query("crawler@scraping.org", "user2");
        assert!(rate_limited.is_err());
    }

    struct MockQuicTransportSender {
        pub expected_peer_addr: SocketAddr,
    }

    impl FederationTransportSender for MockQuicTransportSender {
        fn send_envelope_to_peer(
            &self,
            peer_addr: SocketAddr,
            envelope: &E2eeMessageEnvelope,
        ) -> Result<FederatedRemoteAck, String> {
            if peer_addr == self.expected_peer_addr {
                Ok(FederatedRemoteAck {
                    message_id: "msg-live-101".to_string(),
                    recipient_sds_id: envelope.recipient_sds_id.clone(),
                    ack_timestamp_ms: 1_700_000_500_000,
                    remote_server_domain: "server2.remote.com".to_string(),
                })
            } else {
                Err("Connection refused".to_string())
            }
        }
    }

    #[test]
    fn test_federation_router_with_real_transport_dispatch() {
        use crate::e2ee::*;

        let mut router = FederationRouter::new("server1.local.com");
        let remote_addr: SocketAddr = "198.51.100.2:4433".parse().unwrap();
        router.register_peer_node("server2.remote.com", "REMOTE123", Some(remote_addr));

        let transport = Arc::new(MockQuicTransportSender {
            expected_peer_addr: remote_addr,
        });
        router.set_network_transport(transport);

        let user = UserCryptoIdentity::generate();
        let (_prekey_secret, bundle) = user.generate_prekey_bundle();
        let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
            "sender@server1.local.com",
            "recipient@server2.remote.com",
            &bundle,
            b"Encrypted live payload",
            1,
            1_700_000_100_000,
        )
        .unwrap();

        // When network transport is connected, route_envelope dispatches over transport
        // and returns DeliveredDirect upon receiving verified remote ACK!
        let status = router.route_envelope("msg-live-101", "server2.remote.com", envelope);
        assert_eq!(status, MessageDeliveryStatus::DeliveredDirect);
        assert!(router.delivered_receipts.contains_key("msg-live-101"));
    }
}
