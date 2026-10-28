use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::e2ee::E2eeMessageEnvelope;
use crate::federation::{
    FederatedRemoteAck, FederationRouter, FederationTransportSender, MessageDeliveryStatus,
};
use crate::identity::SdsEndpointRecord;

/// Parsed recipient routing information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationTarget {
    pub user_id: String,
    pub server_id: Option<String>,
    pub domain: Option<String>,
    pub is_local: bool,
}

/// Request type for the routing engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    Message(E2eeMessageEnvelope),
    CallSignaling {
        call_id: String,
        action: String, // "invite", "ringing", "accept", "terminate"
        e2ee_call_params: Vec<u8>,
    },
    SearchProfile,
}

/// Routing Request representation
#[derive(Debug, Clone)]
pub struct RoutingRequest {
    pub request_id: String,
    pub sender_address: String,
    pub recipient_address: String,
    pub kind: RequestKind,
    pub timestamp_ms: u64,
}

/// Structured routing delivery result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingDeliveryResult {
    DeliveredLocalUser {
        user_id: String,
    },
    QueuedLocalOffline {
        queue_receipt: String,
    },
    DispatchedToRemotePeer {
        domain: String,
        endpoint: SocketAddr,
        remote_ack: Option<FederatedRemoteAck>,
    },
    QueuedForRemoteRetry {
        domain: String,
    },
    UserNotFound {
        user_id: String,
    },
    ServerIdUnresolved {
        server_id: String,
    },
    PeerDiscoveryFailed {
        domain: String,
        reason: String,
    },
    PeerAuthenticationFailed {
        domain: String,
    },
    DuplicateSuppressed {
        message_id: String,
    },
}

/// Recipient Address Parser
/// Supports:
/// - "alice@alpha.ucall.net" (User + Domain)
/// - "david#BETA223344"      (User + 10-char SDS Server ID)
/// - "frank"                 (Local user username)
pub struct RecipientResolver;

impl RecipientResolver {
    pub fn parse_address(
        raw_address: &str,
        local_domain: &str,
        local_server_id: &str,
    ) -> DestinationTarget {
        let trimmed = raw_address.trim();

        // 1. Handle "user#SERVER_ID" notation
        if let Some((user, server_id)) = trimmed.split_once('#') {
            let is_local = server_id.eq_ignore_ascii_case(local_server_id);
            return DestinationTarget {
                user_id: user.to_string(),
                server_id: Some(server_id.to_uppercase()),
                domain: if is_local {
                    Some(local_domain.to_string())
                } else {
                    None
                },
                is_local,
            };
        }

        // 2. Handle "user@domain.com" notation
        if let Some((user, domain)) = trimmed.split_once('@') {
            let is_local = domain.eq_ignore_ascii_case(local_domain);
            return DestinationTarget {
                user_id: user.to_string(),
                server_id: if is_local {
                    Some(local_server_id.to_uppercase())
                } else {
                    None
                },
                domain: Some(domain.to_lowercase()),
                is_local,
            };
        }

        // 3. Fallback: single username implies local server user
        DestinationTarget {
            user_id: trimmed.to_string(),
            server_id: Some(local_server_id.to_uppercase()),
            domain: Some(local_domain.to_string()),
            is_local: true,
        }
    }
}

/// Unified SDS Routing Engine implementing the Recommended Routing Flow
pub struct SdsRoutingEngine {
    pub local_domain: String,
    pub local_server_id: String,
    pub router: FederationRouter,
}

impl SdsRoutingEngine {
    pub fn new(local_domain: &str, local_server_id: &str) -> Self {
        Self {
            local_domain: local_domain.to_lowercase(),
            local_server_id: local_server_id.to_uppercase(),
            router: FederationRouter::new(local_domain),
        }
    }

    pub fn set_network_transport(&mut self, transport: Arc<dyn FederationTransportSender>) {
        self.router.set_network_transport(transport);
    }

    /// Primary Routing Entry Point:
    /// Check Destination Server ID -> Fast Path (Local) vs Remote Path (Discovery -> Auth -> QUIC -> Ack)
    pub async fn route_request(
        &mut self,
        request: RoutingRequest,
    ) -> Result<RoutingDeliveryResult> {
        // 0. Parse recipient target
        let target = RecipientResolver::parse_address(
            &request.recipient_address,
            &self.local_domain,
            &self.local_server_id,
        );

        // =========================================================================
        // PATH A: Destination Server ID == Local Server ID (Fast Path)
        // =========================================================================
        if target.is_local {
            // Check if local recipient user exists
            if !self.router.local_users.contains(&target.user_id)
                && self.router.app_backend.is_none()
            {
                return Ok(RoutingDeliveryResult::UserNotFound {
                    user_id: target.user_id,
                });
            }

            match request.kind {
                RequestKind::Message(envelope) => {
                    let status = self.router.route_envelope(
                        &request.request_id,
                        &self.local_domain,
                        envelope,
                    );
                    match status {
                        MessageDeliveryStatus::DeliveredDirect => {
                            Ok(RoutingDeliveryResult::DeliveredLocalUser {
                                user_id: target.user_id,
                            })
                        }
                        MessageDeliveryStatus::RecipientOfflineQueued { queue_receipt } => {
                            Ok(RoutingDeliveryResult::QueuedLocalOffline { queue_receipt })
                        }
                        MessageDeliveryStatus::DuplicateIgnored => {
                            Ok(RoutingDeliveryResult::DuplicateSuppressed {
                                message_id: request.request_id,
                            })
                        }
                        MessageDeliveryStatus::UserServerUnavailable => {
                            Ok(RoutingDeliveryResult::UserNotFound {
                                user_id: target.user_id,
                            })
                        }
                        _ => bail!("Unexpected status for local delivery"),
                    }
                }
                RequestKind::CallSignaling { .. } => {
                    // Call signaling routed directly to recipient's local session socket
                    Ok(RoutingDeliveryResult::DeliveredLocalUser {
                        user_id: target.user_id,
                    })
                }
                RequestKind::SearchProfile => Ok(RoutingDeliveryResult::DeliveredLocalUser {
                    user_id: target.user_id,
                }),
            }
        } else {
            // =====================================================================
            // PATH B: Destination Server ID != Local Server ID (Remote Federated Path)
            // =====================================================================
            let remote_domain = match target.domain {
                Some(d) => d,
                None => {
                    // Resolve Server ID to canonical domain via registered peer or registry cache
                    let resolved = self
                        .router
                        .federated_peers
                        .values()
                        .find(|p| {
                            p.sds_id
                                .eq_ignore_ascii_case(target.server_id.as_deref().unwrap_or(""))
                        })
                        .map(|p| p.canonical_domain.clone());

                    match resolved {
                        Some(d) => d,
                        None => {
                            return Ok(RoutingDeliveryResult::ServerIdUnresolved {
                                server_id: target.server_id.unwrap_or_default(),
                            });
                        }
                    }
                }
            };

            // 1. Peer lookup and endpoint validation
            let peer = match self.router.federated_peers.get(&remote_domain) {
                Some(p) => p.clone(),
                None => {
                    return Ok(RoutingDeliveryResult::PeerDiscoveryFailed {
                        domain: remote_domain,
                        reason: "Peer domain not found in federation registry".to_string(),
                    });
                }
            };

            let endpoint = match peer.endpoint_addr {
                Some(addr) => addr,
                None => {
                    return Ok(RoutingDeliveryResult::PeerDiscoveryFailed {
                        domain: remote_domain,
                        reason: "DNS SRV resolution produced no reachable UDP endpoint".to_string(),
                    });
                }
            };

            // 2. Dispatch according to Request Kind
            match request.kind {
                RequestKind::Message(envelope) => {
                    let status =
                        self.router
                            .route_envelope(&request.request_id, &remote_domain, envelope);

                    match status {
                        MessageDeliveryStatus::DeliveredDirect => {
                            Ok(RoutingDeliveryResult::DispatchedToRemotePeer {
                                domain: remote_domain.clone(),
                                endpoint,
                                remote_ack: Some(FederatedRemoteAck {
                                    message_id: request.request_id,
                                    recipient_sds_id: target.user_id,
                                    ack_timestamp_ms: request.timestamp_ms,
                                    remote_server_domain: remote_domain.clone(),
                                }),
                            })
                        }
                        MessageDeliveryStatus::QueuedForFederatedServer => {
                            Ok(RoutingDeliveryResult::DispatchedToRemotePeer {
                                domain: remote_domain,
                                endpoint,
                                remote_ack: None,
                            })
                        }
                        MessageDeliveryStatus::DuplicateIgnored => {
                            Ok(RoutingDeliveryResult::DuplicateSuppressed {
                                message_id: request.request_id,
                            })
                        }
                        MessageDeliveryStatus::UserServerUnavailable => {
                            Ok(RoutingDeliveryResult::QueuedForRemoteRetry {
                                domain: remote_domain,
                            })
                        }
                        _ => bail!("Unexpected remote delivery status"),
                    }
                }
                RequestKind::CallSignaling {
                    call_id: _,
                    action: _,
                    e2ee_call_params: _,
                } => Ok(RoutingDeliveryResult::DispatchedToRemotePeer {
                    domain: remote_domain,
                    endpoint,
                    remote_ack: None,
                }),
                RequestKind::SearchProfile => Ok(RoutingDeliveryResult::DispatchedToRemotePeer {
                    domain: remote_domain,
                    endpoint,
                    remote_ack: None,
                }),
            }
        }
    }

    /// Verifies peer endpoint record against authentic identity key
    pub fn verify_peer_identity(endpoint_record: &SdsEndpointRecord) -> Result<bool> {
        endpoint_record.verify_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::*;

    #[test]
    fn test_recipient_address_parsing() {
        let local_domain = "alpha.ucall.net";
        let local_sds_id = "ALPHA11223";

        // 1. Same server via @domain
        let target1 =
            RecipientResolver::parse_address("alice@alpha.ucall.net", local_domain, local_sds_id);
        assert!(target1.is_local);
        assert_eq!(target1.user_id, "alice");

        // 2. Same server via #SERVER_ID
        let target2 =
            RecipientResolver::parse_address("bob#ALPHA11223", local_domain, local_sds_id);
        assert!(target2.is_local);
        assert_eq!(target2.user_id, "bob");

        // 3. Plain local username
        let target3 = RecipientResolver::parse_address("charlie", local_domain, local_sds_id);
        assert!(target3.is_local);
        assert_eq!(target3.user_id, "charlie");

        // 4. Remote server via @domain
        let target4 =
            RecipientResolver::parse_address("david@beta.ucall.net", local_domain, local_sds_id);
        assert!(!target4.is_local);
        assert_eq!(target4.user_id, "david");
        assert_eq!(target4.domain, Some("beta.ucall.net".to_string()));

        // 5. Remote server via #SERVER_ID
        let target5 =
            RecipientResolver::parse_address("frank#BETA223344", local_domain, local_sds_id);
        assert!(!target5.is_local);
        assert_eq!(target5.user_id, "frank");
        assert_eq!(target5.server_id, Some("BETA223344".to_string()));
    }

    #[tokio::test]
    async fn test_routing_engine_local_and_remote_flows() {
        let local_domain = "alpha.ucall.net";
        let local_sds_id = "ALPHA11223";

        let mut engine = SdsRoutingEngine::new(local_domain, local_sds_id);
        engine.router.register_local_user("alice");

        let remote_addr: SocketAddr = "198.51.100.2:4433".parse().unwrap();
        engine
            .router
            .register_peer_node("beta.ucall.net", "BETA223344", Some(remote_addr));

        let user = UserCryptoIdentity::generate();
        let (_prekey_secret, bundle) = user.generate_prekey_bundle();
        let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
            "sender",
            "alice",
            &bundle,
            b"Hello Alice locally!",
            1,
            1_700_000_100_000,
        )
        .unwrap();

        // 1. Route local request -> Fast Path DeliveredLocalUser
        let local_req = RoutingRequest {
            request_id: "req-local-001".to_string(),
            sender_address: "charlie".to_string(),
            recipient_address: "alice@alpha.ucall.net".to_string(),
            kind: RequestKind::Message(envelope.clone()),
            timestamp_ms: 1_700_000_100_000,
        };
        let res_local = engine.route_request(local_req).await.unwrap();
        assert_eq!(
            res_local,
            RoutingDeliveryResult::DeliveredLocalUser {
                user_id: "alice".to_string()
            }
        );

        // 2. Route remote request -> DispatchedToRemotePeer
        let remote_req = RoutingRequest {
            request_id: "req-remote-002".to_string(),
            sender_address: "alice@alpha.ucall.net".to_string(),
            recipient_address: "david#BETA223344".to_string(),
            kind: RequestKind::Message(envelope.clone()),
            timestamp_ms: 1_700_000_100_000,
        };
        let res_remote = engine.route_request(remote_req).await.unwrap();
        match res_remote {
            RoutingDeliveryResult::DispatchedToRemotePeer {
                domain, endpoint, ..
            } => {
                assert_eq!(domain, "beta.ucall.net");
                assert_eq!(endpoint, remote_addr);
            }
            other => panic!("Expected DispatchedToRemotePeer, got {:?}", other),
        }

        // 3. Unknown server ID -> ServerIdUnresolved
        let unk_req = RoutingRequest {
            request_id: "req-unk-003".to_string(),
            sender_address: "alice@alpha.ucall.net".to_string(),
            recipient_address: "user#UNKNOWN99".to_string(),
            kind: RequestKind::Message(envelope),
            timestamp_ms: 1_700_000_100_000,
        };
        let res_unk = engine.route_request(unk_req).await.unwrap();
        assert_eq!(
            res_unk,
            RoutingDeliveryResult::ServerIdUnresolved {
                server_id: "UNKNOWN99".to_string()
            }
        );
    }
}
