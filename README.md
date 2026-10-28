# UCall SDS — Sovereign Domain Service & Transport Engine

<p align="center">
  <b>Developed by PingDart and Tech2Day</b><br>
  <i>Next-Generation Sovereign Decentralized Messaging & Real-Time Calling Mesh Infrastructure</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust%202021-orange.svg" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/Transport-QUIC%20RFC%209000%20%7C%20RFC%209221-blue.svg" alt="QUIC RFC 9000 / 9221" />
  <img src="https://img.shields.io/badge/Security-E2EE%20Double%20Ratchet-green.svg" alt="E2EE Double Ratchet" />
  <img src="https://img.shields.io/badge/Architecture-100%25%20Stateless%20SDK-purple.svg" alt="Stateless SDK" />
  <img src="https://img.shields.io/badge/Tests-57%2F57%20Passed%20(9%20Suites)-success.svg" alt="Tests 57/57 Passed" />
</p>

---

## 1. Architectural Overview

UCall SDS empowers organizations, enterprises, and independent providers to run their own sovereign communication servers. Users can seamlessly send end-to-end encrypted (E2EE) messages and make ultra-low-latency voice/video calls across a decentralized mesh of independent servers without relying on any central monopoly or phonebook directory.

<p align="center">
  <img src="doc/Federated%20Messaging%20and%20Calling%20Architecture.png" alt="Federated Messaging and Calling Architecture" width="100%" style="border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);" />
</p>

### Understanding the Architecture Diagram
The architecture illustrated above is divided into four distinct operational layers:
1. **User Client Application Layer (Left & Right):**
   * Mobile (Flutter / Android / iOS) and Web (React / Vite) clients connect to their respective home servers.
   * Clients generate local cryptographic keypairs (Ed25519 for identity, X25519 for prekeys and Double Ratchet sessions).
   * **Payloads are encrypted directly on the client phone before transmission.** The server only ever handles encrypted ciphertext envelopes.
2. **Home Server Layer (Server 1 / Server 2 / Server N):**
   * Manages local client connections via WebSockets or push notifications.
   * Host backends retain complete data ownership using standard databases (PostgreSQL, MySQL, Redis).
   * Embeds the **stateless SDS core engine** (`sds-sdk`), which executes zero disk writes and maintains no local user profiles or message history.
3. **Decentralized Discovery Layer (Public DNS):**
   * Eliminates central directories using DNS SRV (`_sds._udp.<domain>`) and TXT records.
   * Binds server domain names directly to their public Ed25519 authority keys, stopping spoofing and DNS-poisoning attacks.
4. **Federated QUIC Transport Layer (Center Mesh):**
   * Servers establish high-throughput, multiplexed **QUIC (RFC 9000)** sessions and **QUIC Datagrams (RFC 9221)** over UDP.
   * Utilizes 28-byte binary framing with jitter playout lifetime budgets and 64-bit session Connection IDs (CIDs) for uninterrupted Wi-Fi to 5G connection migration.

---

## 2. What is UCall SDS Used For?

| Problem in Existing Systems | How UCall SDS Solves It |
|---|---|
| **Centralized Monopolies (WhatsApp, Telegram, Slack):** A single corporate outage or policy change cuts off communications; user metadata is centralized. | **Sovereign Federation:** Any company, school, or team runs their own server. Communication between servers flows peer-to-peer without a middleman. |
| **Heavy Federated Protocols (Matrix / Synapse):** Synchronizing heavy JSON room state graphs across thousands of servers causes massive database bloat and slow syncs. | **Stateless Mesh Core:** SDS operates as a stateless transport engine. Servers route authenticated binary wire frames without replicating global database state. |
| **Slow Call Setup (WebRTC SDP / ICE):** Multi-second delays while exchanging text-based SDP offers, answers, and gathering ICE candidates. | **Sub-50ms QUIC Signaling:** Cryptographic prekey bundles and 0-RTT/1-RTT QUIC streams establish media sessions nearly instantaneously. |
| **Dropped Calls on Network Handover:** Moving from office Wi-Fi to cellular data severs TCP/WebSocket connections, dropping active voice and video calls. | **64-bit QUIC Connection Migration:** The session Connection ID (CID) remains persistent. Audio/video flows uninterrupted when client IP/port changes. |
| **Voice / Video Lag & Stutter:** Packets delayed by network congestion arrive late and cause jarring audio buffer underruns. | **150ms Playout Lifetime Budgets:** Expired datagrams are discarded at the protocol layer, prioritizing immediate, real-time voice clarity over stale audio. |

---

## 3. Comprehensive Security Architecture & Cryptographic Parameters

Security in UCall SDS is enforced mathematically at every boundary:

### 3.1 Cryptographic Algorithms & Parameter Matrix

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               CRYPTOGRAPHIC PARAMETERS MATRIX                         │
├──────────────────────┬──────────────────────────────┬──────────────┬───────────────────┤
│ Security Purpose     │ Primitive / Algorithm        │ Key Length   │ Standard / RFC    │
├──────────────────────┼──────────────────────────────┼──────────────┼───────────────────┤
│ Server & User Id     │ Ed25519 (EdDSA)              │ 256 bits     │ RFC 8032          │
│ Key Exchange (Prekey)│ X25519 (Curve25519 ECDH)     │ 256 bits     │ RFC 7748          │
│ End-to-End Ratchet   │ Double Ratchet (Signal Spec) │ 256-bit keys │ Double Ratchet V1 │
│ Payload Encryption   │ ChaCha20-Poly1305 (AEAD)     │ 256-bit key  │ RFC 8439          │
│ AEAD Nonce           │ Monotonic Per-Message Counter│ 96 bits      │ RFC 8439          │
│ Key Derivation (KDF) │ HKDF-SHA256 (Extract/Expand) │ 256 bits     │ RFC 5869          │
│ Domain Identifier    │ SHA-256 + Polynomial Checksum│ 40-bit + 10b │ Crockford Base32  │
│ Wire Auth Tag        │ Poly1305 / HMAC-SHA256       │ 128 bits     │ RFC 8439          │
│ Replay Token Ticket  │ HMAC-SHA256 + Server Secret  │ 256 bits     │ RFC 2104          │
│ Session Identifier   │ QUIC Connection ID (CID)     │ 64 bits      │ RFC 9000          │
└──────────────────────┴──────────────────────────────┴──────────────┴───────────────────┘
```

### 3.2 Deep-Dive Security Protections

#### 1. Zero-Knowledge End-to-End Encryption (E2EE)
* Plaintext messages and media are encrypted on the sender's device using `sds_core::e2ee`.
* **Double Ratchet Forward & Future Secrecy:** Every message generates a new symmetric key via HKDF-SHA256. Even if a future key is compromised, past and future messages remain cryptographically protected.
* **Prekey Authentication & Signed Rotation:** The recipient publishes an X25519 signed prekey certified by their Ed25519 identity key. The sender mandates `PrekeyBundle::verify_signature()` before Diffie-Hellman derivation.

#### 2. Protocol-Layer 0-RTT Anti-Replay Gating
* While QUIC 0-RTT reduces connection latency to zero round-trips, early data is vulnerable to network replay attacks.
* SDS enforces a strict protocol-layer ingestion filter (`handle_incoming_frame`):
  * **Permitted in 0-RTT:** Only idempotent, read-only diagnostic frames (`Ping` `0x00`, `Ack` `0x01`).
  * **Forbidden in 0-RTT:** All state-changing frames (`Handshake`, `StreamData`, `ForwardReq`, `ProfileQuery`) are immediately rejected with error `ERR_ZERO_RTT_REJECTED` (`0x0004`).
* Under multi-threaded concurrent redemption races, the `DistributedReplayStore` guarantees atomic single-use ticket consumption (1 success, N-1 rejections).

#### 3. Cross-Process File Lock for Offline Registries
* The local domain CLI cache (`sds_registry.json`) uses an atomic RAII `FileLock` (`O_CREAT | O_EXCL` on `sds_registry.json.lock`) with a 5-second stale lock reclamation window and atomic `.tmp` file renaming. Multiple local processes cannot corrupt the registry under concurrent updates.

#### 4. SSRF & URL Protection
* App profile logos and server avatar URLs are validated against strict SSRF rules: private RFC 1918 IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), link-local (`169.254.0.0/16`), and non-HTTPS protocols are automatically rejected.

---

## 4. Binary Wire Framing Protocol (28-Byte Exact Header)

All communication between federated servers is structured into binary frames formatted to minimize network serialization overhead:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: "SDS1" (0x53445331)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)|FrameType(0x02)|          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Stream ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Timestamp (Playout ms)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Lifetime Limit (ms)        |          Payload Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Auth Tag (16 Bytes / 128 Bits)             +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Encrypted Payload Bytes...                |
```

### Frame Types:
* `0x00`: **Ping** — Keepalive and path validation (0-RTT permitted).
* `0x01`: **Ack** — Delivery acknowledgement and receipt confirmation (0-RTT permitted).
* `0x02`: **StreamData** — Reliable E2EE text message, attachment, or profile payload.
* `0x03`: **StreamClose** — Stream termination and teardown.
* `0x04`: **DatagramMedia** — Unreliable low-latency Opus audio / video packet (RFC 9221).
* `0x05`: **ForwardReq** — Cross-server call invitation and routing request.
* `0x06`: **ProfileQuery** — User identity and prekey bundle lookup.

---

## 5. Network Configuration & Ports

The standard port configuration for PingDart and UCall SDS:

| Port | Protocol | Service / Component | Purpose |
|:---:|:---:|---|---|
| **`4433`** (or `8443`) | **QUIC / UDP** | **SDS Federation Gateway** | Primary inter-server communication port advertised in DNS SRV (`_sds._udp.<domain>`). |
| **`4025`** | TCP / HTTP | **PingDart Backend API** | Express/Node.js host API server managing authentication and database transactions. |
| **`4026`** | TCP / HTTP | **Web Chat Client** | Frontend web application UI (`chat.pingdart.com`). |
| **`3306`** | TCP | **MySQL Database** | Persistent relational storage for server configuration and user accounts. |
| **`80` / `443`** | TCP / HTTPS | **Web & DNS Health** | Verified during DNS setup wizard to validate web accessibility and Let's Encrypt TLS. |

---

## 6. Multi-Server Mesh Operation (1 Server to 10 Servers)

When Server 1 communicates across 10 autonomous servers:
1. **Connection Pooling:** Server 1 establishes **one pooled QUIC session** to each peer server (`Server 2` through `Server 11`). Thousands of local user streams are multiplexed through these 10 pipes.
2. **Server-Side Fan-Out:** Group messages sent by a local user are encrypted once with a group Sender Key (SFrame / MLS). Server 1 replicates and distributes 1 copy over each peer QUIC connection, saving up to 90% of client cellular bandwidth.
3. **Stateless Resilience:** If a remote server is temporarily unreachable, the SDS core returns `MessageDeliveryStatus::UserServerUnavailable`. The host application (Postgres/Redis queue) manages retry scheduling, guaranteeing zero uncommitted state in SDK memory.

*(For full implementation flows, see [`MULTI_SERVER_MULTI_USER_FEDERATION_GUIDE.md`](MULTI_SERVER_MULTI_USER_FEDERATION_GUIDE.md)).*

---

## 7. Command-Line Interface (CLI) Quickstart

The project compiles into a single, high-performance binary: `sds` (located in root).

### 7.1 Interactive Shell
Launch the interactive management terminal:
```bash
./sds interactive
```

### 7.2 Encode a Domain to Compact SDS Identifier
```bash
./sds encode pingdart.com
```
*Output:*
```text
[*] Canonicalizing domain 'pingdart.com'...
    Normalized Domain : pingdart.com
    Computed SDS ID   : 5QJCXPH2HN (Tier 1: 10 Chars)
    Checksum Status   : VALID (Polynomial Checksum: HN)
[✓] Domain successfully mapped and saved to local offline registry.
```

### 7.3 Offline Decode & Typo Validation
```bash
./sds decode 5QJCXPH2HN
```
*Output:*
```text
[*] Validating 10-character SDS Code: '5QJCXPH2HN'...
    Checksum Status : PASSED (Valid SDS Identifier)
    Decoded Domain  : pingdart.com
    Status          : ACTIVE
```
*If a user mistypes a single character (e.g. `5QJCXPH2XX`), the polynomial checksum immediately catches the typo:*
```text
[!] Checksum Mismatch: Typo detected in code '5QJCXPH2XX'!
```

### 7.4 Automated DNS Setup Wizard
Generate copy-pasteable DNS records for domain federation:
```bash
./sds dns-setup pingdart.com
```

---

## 8. Continuous Integration & Release Verification

UCall SDS passes all 4 strict release verification gates with **zero warnings**:

```bash
# Gate 1: Strict Compilation
cargo check --locked --all-targets

# Gate 2: Strict Linter (Zero Warnings)
cargo clippy --locked --all-targets -- -D warnings

# Gate 3: Formatting Conformance
cargo fmt --check

# Gate 4: Test Suite Execution (57 Passed across 9 Test Targets)
cargo test --locked --all-targets
```

### Summary of Passing Automated Test Suites:
- `src/lib.rs` (Unit Tests): **27 passed**
- `tests/production_verification_tests.rs`: **6 passed**
- `tests/test_federation_e2ee_profile.rs`: **3 passed**
- `tests/test_federation_lifecycle_failure_recovery.rs`: **1 passed**
- `tests/test_live_network_transport.rs`: **4 passed**
- `tests/test_live_quic_transport.rs`: **3 passed**
- `tests/test_stateless_compliance.rs`: **7 passed**
- `tests/test_three_server_mesh_federation.rs`: **1 passed**
- `tests/test_transport_and_framing.rs`: **5 passed**

**Total: 57 passed, 0 failed, 0 ignored (100% pass rate).**

---

## 9. Codebase Structure

```text
UcallSDS/
├── doc/
│   └── Federated Messaging and Calling Architecture.png   # Architectural schematic
├── src/
│   ├── canonical.rs         # Domain normalization and Crockford Base32 hashing
│   ├── dns_wizard.rs        # DNS record generation and snapshot validation
│   ├── e2ee.rs              # Double Ratchet, X25519 prekey bundles, and AEAD encryption
│   ├── federation.rs        # Multi-node router, connection pooling, and mesh delivery
│   ├── frame.rs             # 28-byte binary wire framing and auth tags
│   ├── identity.rs          # Ed25519 server & user identity key management
│   ├── profile.rs           # Signed application profiles and SSRF protection
│   ├── replay.rs            # Anti-replay ticket store and 0-RTT idempotency
│   ├── storage.rs           # Registry management with cross-process file locks
│   ├── transport.rs         # QUIC state machine, 0-RTT frame gating, playout budgets
│   ├── lib.rs               # Library export definition (sds_core)
│   └── main.rs              # CLI entrypoint (sds)
├── tests/                   # 9 comprehensive integration and live socket test suites
├── OPERATIONAL_GUIDE.md     # In-depth operational engineering guide
├── MULTI_SERVER_MULTI_USER_FEDERATION_GUIDE.md  # 10-server mesh scaling & call guide
├── SDS_TRANSPORT_SPEC_AND_STATUS.md             # Wire transport specification
├── Cargo.toml               # Locked Rust dependency manifest
└── sds                      # Optimized production release binary
```

---

## 10. Authors & Acknowledgements

* **PingDart** (`https://pingdart.com`) — Decentralized architecture, real-time communications, and secure messaging infrastructure.
* **Tech2Day** — Protocol design, security engineering, and cryptographic verification.

*UCall SDS is engineered for total sovereignty, high throughput, and privacy by design.*

