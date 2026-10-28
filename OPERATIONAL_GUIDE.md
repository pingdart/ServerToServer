# UCall SDS — Official Operational & Developer Guide
**Document Version:** 1.0 (Production Standard)  
**Target Audience:** Systems Architects, Backend Engineers, Protocol Developers  
**Crate:** `sds-sdk` (Library: `sds_core`, CLI: `sds`)  
**Repository Location:** `/Users/malleravindra/Projucts/PingDart Chat/UcallSDS`  

---

## 1. Architecture & Protocol Foundations

### 1.1 The Core Problem & The SDS Solution
Traditional communication stacks rely on central directories (phone numbers, email addresses, centralized Matrix/Synapse clusters) or legacy WebRTC signaling (multi-second SDP text negotiations and ICE gathering).

SDS introduces a two-tier sovereign communication infrastructure:
1. **Compact 10-Character Domain Identifiers:** Deterministic, collision-resistant Crockford Base32 identifiers mapped to Internet domains.
2. **Transport-Independent QUIC Wire Protocol:** Multiplexed streams and low-latency datagrams (RFC 9000 & RFC 9221) with persistent 64-bit session Connection IDs (CIDs) surviving client IP/port changes.
3. **Stateless Core Boundary:** The SDK engine maintains zero local databases and writes zero state to disk. Host backends retain 100% data ownership.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Application Layer (UCall)                       │
│              (PostgreSQL, Redis, Kafka, Mobile Client UI)              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ SdsAppBackendAdapter
┌───────────────────────────────────▼────────────────────────────────────┐
│                    SDS CORE SDK ENGINE (Stateless)                     │
│                                                                        │
│  ┌──────────────────────┐  ┌─────────────────────┐  ┌───────────────┐  │
│  │ Domain Normalization │  │ 0-RTT Replay Gate   │  │ Double Ratchet│  │
│  │ & Polynomial Checksum│  │ & Ticket Validation │  │ E2EE Engine   │  │
│  └──────────┬───────────┘  └──────────┬──────────┘  └───────┬───────┘  │
│             │                         │                     │          │
│  ┌──────────▼─────────────────────────▼─────────────────────▼───────┐  │
│  │                     sds-transport (QUIC Core)                    │  │
│  │  • 28-Byte Binary Wire Framing    • Session CID Migration        │  │
│  │  • Jitter Queue Lifetime Budgets  • RFC 9221 Media Datagrams     │  │
│  └────────────────────────────────────┬─────────────────────────────┘  │
└───────────────────────────────────────┼────────────────────────────────┘
                                        │ DNS Discovery & QUIC UDP
┌───────────────────────────────────────▼────────────────────────────────┐
│                   Remote Autonomous SDS Server Nodes                   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Domain Identity, Encoding & Resolution

### 2.1 One-Way Cryptographic Derivation (Not Reversible)
A common misconception is that a 10-character code can be "mathematically reversed" into the original domain string. **It cannot.**

- Truncated SHA-256 is an irreversible cryptographic one-way hash.
- **Payload (8 chars):** Encodes 40 bits extracted from $\text{SHA-256}(\text{CanonicalDomain} \parallel \text{OptionalSalt})$.
- **Checksum (2 chars):** A 10-bit modulo polynomial checksum ($32^2 = 1024$) computed strictly for human error and transposition detection.

$$\text{Domain ID} = \underbrace{\text{Char}_1 \dots \text{Char}_8}_{\text{40-bit Payload}} \;\parallel\; \underbrace{\text{Char}_9 \text{Char}_{10}}_{\text{10-bit Polynomial Checksum}}$$

### 2.2 What "Decoding" Actually Means
When an SDS client or server "decodes" a 10-character code:
1. **Permissive Input Normalization:** Removes human separators (`-`, `_`, `%`, `$`, `#`, `@`, whitespace) and normalizes common visual typos (`O`/`o` $\to$ `0`, `I`/`i`/`L`/`l` $\to$ `1`).
2. **Checksum Verification:** Evaluates $\sum_{i=1}^{8} (i \times \text{Val}(\text{Char}_i)) \pmod{1024}$. If the checksum does not match, the code is rejected immediately as a typo without hitting the network or disk.
3. **Registry Resolution:** Recovers the original domain by looking up the validated 10-character key in the local offline registry ([`sds_registry.json`](file:///Users/malleravindra/Projucts/PingDart%20Chat/UcallSDS/sds_registry.json) for the CLI, or the application database for backend services).

### 2.3 Collision Resolution & Tiered Namespace Allocation
If two distinct domains generate the same 40-bit payload prefix:
- **Salt Window ($0..63$):** The allocation engine re-hashes $\text{SHA-256}(\text{domain} \parallel \text{"\#"} \parallel \text{salt})$.
- **Tiered Elevation:** If the 64 salt slots in Tier 1 are saturated, the system automatically elevates newly registered domains to Tier 2 (10 payload + 2 checksum = 12 chars, $1.12$ quadrillion slots) or Tier 3 (12 payload + 2 checksum = 14 chars, $1.15$ quintillion slots). Once assigned, a domain's ID is permanently immutable.
- **Concurrent Registration Safety:** In `src/storage.rs`, `register_domain` performs a disk re-read (`reload()`), checks existing keys, tests candidates, and writes via an atomic temporary file rename (`fs::rename`), ensuring race-free concurrency across worker threads (verified in `tests/production_verification_tests.rs::test_concurrent_registration_safety`).
- **Cross-Server Collision Semantics:** A 40-bit payload alone does not guarantee global uniqueness across all trillions of possible strings. Global disambiguation is provided by DNS domain anchoring: each domain's authoritative ID is published in its DNS TXT record (`_sds.<domain>`) and signed by its Ed25519 authority key. In the event of an identical hash between independent servers, the deterministic salt window or tiered escalation resolves the collision, and the landed ID is permanently authenticated by DNS.

### 2.4 Verified Implementation Test Vectors
The following test vectors are frozen and validated across Rust, Python, and Dart:

| Registered Domain | Canonical Domain | Tier | Payload | Checksum | Full SDS Domain ID |
|---|---|:---:|:---:|:---:|:---:|
| `pingdart.com` | `pingdart.com` | 1 | `5QJCXPH2` | `HN` | **`5QJCXPH2HN`** |
| `https://meddylist.com:8080/` | `meddylist.com` | 1 | `Q2KE9Y5F` | `G8` | **`Q2KE9Y5FG8`** |
| `sds://xyz.com.` | `xyz.com` | 1 | `19EGDPHY` | `N9` | **`19EGDPHYN9`** |
| `bloomingeasyservices.in` | `bloomingeasyservices.in` | 1 | `D543HERN` | `H8` | **`D543HERNH8`** |
| `xyz.com` (Tier 2 test) | `xyz.com` | 2 | `19EGDPHYZJ` | `3M` | **`19EGDPHYZJ3M`** |

---

## 3. DNS Federation, Domain Ownership & Key Rotation

### 3.1 DNS Discovery Records
To participate in decentralized server-to-server federation, a domain deploys two DNS records:
1. **SRV Endpoint Record:**
   ```text
   _sds._udp.chat.example.com.  3600  IN  SRV  10 10 4433 sds.example.com.
   ```
2. **TXT Identity Proof Record:**
   ```text
   _sds.chat.example.com.       3600  IN  TXT  "v=sds1; id=7K9M2P4X8B; k=ed25519; p=7a4f9b8c00112233..."
   ```

### 3.2 Authenticating Domain Ownership
Federated peers verify domain authenticity through a two-step cryptographic check:
1. The remote server resolves `_sds.<domain>` TXT record and checks that `id` matches the domain's calculated ID and `p` contains the authority's Ed25519 public key.
2. During the QUIC handshake, the server presents an `SdsEndpointRecord` signed by that same Ed25519 private key.

### 3.3 Cryptographic Key Rotation Chain-of-Custody
Keys are never rotated silently. The SDK requires an `SdsKeyRotationCertificate`:
- The certificate contains the domain, old public key, new public key, and a strictly increasing `epoch` counter.
- The **old private key must sign the rotation payload**.
- Peers verify the certificate signature against their cached old key and reject any certificate where `epoch <= current_epoch` (anti-rollback protection).

---

## 4. QUIC Transport, 0-RTT Replay Defense & Connection Migration

### 4.1 Universal 28-Byte Binary Wire Framing (`SdsFrame`)
All signaling, control, and media datagrams use the exact 28-byte big-endian header:
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic: 0x53 0x44 0x53 ("SDS")   | Version: 0x01 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Flags (1B)  | Sub-Type (1B) |     Frame / Message Type (2B) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Stream ID (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Sequence Number (u64, MSB)                |
|                     Sequence Number (u64, LSB)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length (u32)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Lifetime Budget ms (u16)  |      Reserved: 0x0000 (u16)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Payload Data (Variable Length) ...              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Authentication Tag / MAC (16 Bytes, Optional)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 RFC 9001 0-RTT Anti-Replay Defense
QUIC 0-RTT allows a client to transmit early data on resumption without waiting for a TLS handshake. However, **0-RTT data is inherently vulnerable to network replays by on-path eavesdroppers.**

SDS enforces strict defense-in-depth:
1. **Protocol-Layer Idempotency Gate (`handle_incoming_frame`):** State-mutating operations (`TYPE_CALL_INVITE`, `TYPE_MSG_ENVELOPE`, `TYPE_MSG_OFFLINE_SYNC_REQ`) are **strictly prohibited** in 0-RTT early data and trigger `ERR_0RTT_OPERATION_FORBIDDEN` (`0x0007`) at the protocol ingestion layer in `SdsTransportSession::handle_incoming_frame`, not merely in client-side helpers. Only safe read-only operations (`TYPE_RESOLVE_PROFILE_REQ`, `TYPE_PING`, `TYPE_PRESENCE_STATE`) are permitted (verified in `transport::tests::test_0rtt_protocol_layer_enforcement`).
2. **Server-Bounded Tickets & Expiration:** Resumption tickets carry an absolute UTC expiration timestamp (`ticket_expiry_epoch_ms`). Expired tickets fail with `ERR_REPLAY_DETECTED` (`0x0006`).
3. **Distributed Atomic Strike Register (`SharedReplayStore`):** In multi-instance server clusters, redeemed tickets and request idempotency tokens are atomically spent across worker nodes using thread-safe synchronization. When multiple concurrent worker threads race to present identical tickets, strictly 1 wins and all concurrent replays receive `Err(ERR_REPLAY_DETECTED)` (verified in `replay::tests::test_concurrent_multithreaded_replay_race`).

### 4.3 Connection Migration Realities
- **Implementation CID Format:** SDS sessions use a persistent **64-bit integer Connection ID** (`connection_id`) for internal session identification. (Standard QUIC allows variable CIDs from 0 to 20 bytes; SDS chooses a 64-bit scalar for zero-allocation performance).
- **Operational Reality:** Connection migration is designed to preserve active sessions across network interface changes (e.g., Wi-Fi $\leftrightarrow$ 5G). However, migration is **best-effort** and subject to:
  - Path validation (QUIC `PATH_CHALLENGE` / `PATH_RESPONSE`).
  - Strict NAT and firewall policies (some carrier networks filter non-whitelisted UDP ports).
  - Relay fallback: If direct path validation fails, the session transitions to `TransportState::RelayFallback` to route over authenticated relays.

---

## 5. Media Pipeline: Transport vs. Application Responsibilities

SDS separates transport mechanics from application-level audio/video codecs:

```
┌────────────────────────────────────────────────────────┐
│                   Application Domain                   │
│   • Audio Capture & Opus Encoding (20ms frames)        │
│   • AV1 / H.265 Hardware Video Encoding                │
│   • Playout Audio Rendering & Echo Cancellation (AEC)  │
└───────────────────────────┬────────────────────────────┘
                            │ Raw Encoded Frames
┌───────────────────────────▼────────────────────────────┐
│                    SDS SDK Domain                      │
│   • 28-Byte Wire Framing (Stream vs QUIC Datagram)     │
│   • Receiver Jitter Dwell Budget Enforcement           │
│   • Automatic Drop of Deadline-Expired Frames          │
│   • Congestion-Controlled Reliable Streams (Keyframes) │
└────────────────────────────────────────────────────────┘
```

- **Playout Lifetime Budget (`lifetime_ms`):** Specifies the receiver jitter queue dwell budget in milliseconds.
- **Deadline Drop Enforcement:** When audio datagrams arrive, `dequeue_playable_media()` calculates queue residence time. If a stalled audio frame exceeds `lifetime_ms`, **it is dropped immediately** rather than causing audio buffer stutter or triggering head-of-line retransmissions.

---

## 6. End-to-End Encryption (E2EE) Specification

In production, SDS uses **asymmetric prekey bundles (X3DH-style) and the Double Ratchet Algorithm** (X25519 ECDH + ChaCha20-Poly1305 AEAD).

### 6.1 Production Prekey Bundle Generation & Verification
A user's cryptographic identity consists of an Ed25519 identity keypair and an X25519 Diffie-Hellman keypair:

```rust
use sds_core::e2ee::{UserCryptoIdentity, E2eeMessageEnvelope, PrekeyBundle};

// 1. Bob provisions his cryptographic identity and publishes a signed PrekeyBundle
let bob = UserCryptoIdentity::generate();
let (bob_signed_prekey_secret, bob_prekey_bundle) = bob.generate_prekey_bundle();

// The prekey bundle carries an Ed25519 signature binding Bob's X25519 prekey to his identity
assert!(bob_prekey_bundle.verify_signature().unwrap());

// 2. Alice fetches Bob's published PrekeyBundle and encrypts a confidential message.
// encrypt_for_recipient automatically verifies bob_prekey_bundle's signature before computing ECDH!
let plaintext = b"Confidential federated message payload over SDS transport";
let envelope = E2eeMessageEnvelope::encrypt_for_recipient(
    "ALICE_7K9M",         // Sender SDS ID
    "BOB_9P4X",           // Recipient SDS ID
    &bob_prekey_bundle,   // Bob's verified prekey bundle
    plaintext,
    1,                    // Sequence number
    1_700_000_000_000,    // Timestamp ms
).expect("Encryption failed");

// 3. Bob receives the envelope and decrypts it using his private prekey secret
let decrypted = envelope
    .decrypt_as_recipient(&bob_signed_prekey_secret)
    .expect("Decryption failed");

assert_eq!(decrypted, plaintext);
```

### 6.2 Signed Prekey Rotation & Forward Secrecy
Users periodically rotate their signed prekeys to prevent long-term key compromise:
- Calling `bob.generate_prekey_bundle()` creates a new signed prekey and signs it with the persistent identity key.
- Messages encrypted to the new prekey cannot be decrypted by retired prekey secrets (verified in `e2ee::tests::test_signed_prekey_rotation_and_verification`).

### 6.2 Ongoing Two-Way Sessions: Double Ratchet
For ongoing chat sessions, peers initialize a `DoubleRatchetSession`:
- Every sent message derives a fresh symmetric message key via KDF chain step (forward secrecy).
- Every reply triggers an asymmetric X25519 Diffie-Hellman ratchet step, providing post-compromise break-in recovery.
- *(Note: Simplified unit tests utilizing a constant shared secret such as `[0x42; 32]` are strictly for test isolation and must never be used in production).*

---

## 7. Stateless SDK vs. Local Developer Registry

| Component | Owner | Storage Media | What It Stores |
|---|---|---|---|
| **CLI Developer Registry** (`sds_registry.json`) | CLI Tool (`src/main.rs`, `storage.rs`) | Local JSON File | Domain $\leftrightarrow$ ID mappings and DNS snapshots for offline developer testing. |
| **SDS Core Engine** (`sds_core`) | Core Library | **None (Pure RAM)** | **Zero disk persistence.** Stores zero user accounts, zero profiles, zero private keys, zero call histories. |
| **Host Application** (Your Backend) | Enterprise Backend | PostgreSQL, Redis, Kafka | User records, durable message queues, auth credentials, audit archives. |

---

## 8. Host Application Backend Adapter Integration

The host application connects to the stateless SDS router by implementing the `SdsAppBackendAdapter` trait:

```rust
use sds_core::federation::{
    FederationRouter, SdsAppBackendAdapter, SdsUserProfile, QueueAcceptance
};
use sds_core::e2ee::E2eeMessageEnvelope;
use std::sync::Arc;

pub struct ProductionPostgresBackend {
    // Database connection pools, Redis clients, Kafka producers
}

impl SdsAppBackendAdapter for ProductionPostgresBackend {
    fn resolve_user_profile(&self, requester_id: &str, target_user_id: &str) -> Option<SdsUserProfile> {
        // 1. Query application user table (Postgres/Redis)
        // 2. Evaluate visibility, friend status, and caller blocklists
        // 3. Return user profile metadata ephemerally (SDK never caches this on disk)
        Some(SdsUserProfile {
            user_id: target_user_id.to_string(),
            display_name: "Alice Engineering".to_string(),
            avatar_url: Some("https://example.com/avatars/alice.png".to_string()),
            bio: Some("Lead Distributed Systems".to_string()),
            public_identity_key: "ed25519_pubkey_hex".to_string(),
            is_online: true,
        })
    }

    fn deliver_incoming_message(
        &self,
        recipient_id: &str,
        envelope: &E2eeMessageEnvelope,
    ) -> Result<QueueAcceptance, String> {
        // In production, the receipt MUST represent a durably committed log record
        // (e.g., PostgreSQL WAL LSN, Kafka partition-offset, or RocksDB sequence)
        let wal_lsn = "pg_wal_0/16B38D8"; 

        Ok(QueueAcceptance::DurablyAccepted {
            queue_receipt: format!("committed:lsn:{}", wal_lsn),
        })
    }
}

fn main() {
    let mut router = FederationRouter::new("alpha.ucall.net");
    router.set_app_backend(Arc::new(ProductionPostgresBackend {}));
}
```

---

## 9. CLI Reference & Real Command Output

The compiled CLI binary is located at `UcallSDS/sds`.

### 1. Encode a Domain
```bash
./sds encode pingdart.com
```
```text
[*] Normalizing domain and registering SDS ID for 'pingdart.com'...
[*] Resolving DNS and querying live server...

════════════════════════════════════════════════════════════════
 SDS DOMAIN ENCODED SUCCESSFULLY
════════════════════════════════════════════════════════════════
 Canonical Domain   : pingdart.com
 SDS Domain ID      : 5QJCXPH2HN  (Exact 10 Characters)
 Checksum (2-Char)  : HN (Verified)
 Encoding Standard  : Crockford Base32 (8 Payload + 2 Checksum = 10 chars)
 Capacity           : 1.099 Trillion IDs (Collision-Proof & Unlimited)
 SDS URI            : sds://5QJCXPH2HN
 Offline Storage    : Cached in local registry (sds_registry.json)
════════════════════════════════════════════════════════════════
```

### 2. Decode an Identifier (Offline Validation)
```bash
./sds decode 5QJCXPH2HN
```
```text
[*] Validating 10-character SDS Code: '5QJCXPH2HN'...
 Checksum Status    : PASSED (Valid SDS Identifier)

════════════════════════════════════════════════════════════════
 SDS DOMAIN RESOLVED (OFFLINE CACHE HIT)
════════════════════════════════════════════════════════════════
 Decoded Domain     : pingdart.com
 SDS Domain ID      : 5QJCXPH2HN  (Exact 10 Characters)
 Registered At      : 2026-10-28 06:30:15 UTC
 Status             : ACTIVE
════════════════════════════════════════════════════════════════
```

### 3. Checksum Error Detection (Typo Rejection)
If a user misinterprets or mistypes a single character (e.g., typing `5QJCXPH2XX` instead of `5QJCXPH2HN`):
```bash
./sds decode 5QJCXPH2XX
```
```text
[*] Validating 10-character SDS Code: '5QJCXPH2XX'...

[!] Checksum Mismatch: Typo detected in code '5QJCXPH2XX'!
```

---

## 10. Continuous Integration & Release Verification

Each verification gate is an independent CI check with individual logs:

### Gate 1: Strict Compilation (`cargo check`)
```bash
cargo check --locked --all-targets
```
*Result:* Exited with code `0`. Zero compile errors across core library, CLI, and all integration tests.

### Gate 2: Strict Linter (`cargo clippy`)
```bash
cargo clippy --locked --all-targets -- -D warnings
```
*Result:* Exited with code `0`. Zero clippy warnings across all targets.

### Gate 3: Formatting Conformance (`cargo fmt`)
```bash
cargo fmt --check
```
*Result:* Exited with code `0`. 100% compliant with standard `rustfmt`.

### Gate 4: Test Suite Execution (`cargo test`)
```bash
cargo test --locked --all-targets
```
*Result:* **61 passed; 0 failed; 0 ignored** across **9 test suites** (with test targets):
- `src/lib.rs` (Unit Tests): **31 passed**
- `tests/production_verification_tests.rs`: **6 passed**
- `tests/test_federation_e2ee_profile.rs`: **3 passed**
- `tests/test_federation_lifecycle_failure_recovery.rs`: **1 passed**
- `tests/test_live_network_transport.rs`: **4 passed**
- `tests/test_live_quic_transport.rs`: **3 passed**
- `tests/test_stateless_compliance.rs`: **7 passed**
- `tests/test_three_server_mesh_federation.rs`: **1 passed**
- `tests/test_transport_and_framing.rs`: **5 passed**

*(Note: Target `src/main.rs` contains zero unit test definitions and successfully exits with code 0).*


