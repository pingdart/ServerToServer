pub mod audit;
pub mod canonical;
pub mod checksum;
pub mod dns;
pub mod dns_wizard;
pub mod e2ee;
pub mod federation;
pub mod frame;
pub mod id;
pub mod identity;
pub mod profile;
pub mod recipient_resolver;
pub mod replay;
pub mod storage;
pub mod transport;

pub use audit::{AuditEventType, AuditLogChain, AuditLogEntry, SignedAuditCheckpoint};
pub use canonical::normalize_domain;
pub use checksum::verify_checksum;
pub use dns::{resolve_dns, DnsSnapshot};
pub use dns_wizard::{DnsSetupGuide, DnsVerificationEngine, DnsVerificationReport};
pub use e2ee::{E2eeMessageEnvelope, PrekeyBundle, UserCryptoIdentity};
pub use federation::{
    FederationRouter, MessageDeliveryStatus, QueueAcceptance, SdsAppBackendAdapter, SdsUserProfile,
};
pub use frame::{SdsFrame, MAGIC_BYTES, PROTOCOL_VERSION};
pub use id::{generate_domain_id, validate_domain_id, DomainIdResult};
pub use identity::{
    SdsEndpointRecord, SdsIdentityKeyPair, SdsKeyRotationCertificate, SdsVerifiedProfile,
};
pub use profile::{AppProfileCache, SdsAppProfile};
pub use recipient_resolver::{
    DestinationTarget, RecipientResolver, RequestKind, RoutingDeliveryResult, RoutingRequest,
    SdsRoutingEngine,
};
pub use replay::{ReplayStrikeRegister, SharedReplayStore};
pub use storage::SdsRegistry;
pub use transport::{SdsTransportSession, TransportMetrics, TransportState};
