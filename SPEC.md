# SDS Protocol Specification — Domain Identity & Resolution
**Version:** 1.0-RC1 (Frozen Wire-Format Specification)  
**Standard:** RFC-Style Technical Standard for SDS Core, Rust SDK & Flutter Client

---

## 1. Domain Identifier Specification

### 1.1 Character Set & Value Mapping
SDS Domain Identifiers use **Crockford's Base32** alphabet consisting of 32 uppercase characters:
```text
0 1 2 3 4 5 6 7 8 9 A B C D E F G H J K M N P Q R S T V W X Y Z
```
*Note: Characters `I`, `L`, `O`, and `U` are intentionally excluded to eliminate visual ambiguity and offensive strings.*

#### Permissive Decoding Normalization
When parsing user input, decoders MUST normalize the following characters before processing:
- `'O'` or `'o'` $\rightarrow$ `'0'` (Value 0)
- `'I'`, `'i'`, `'L'`, or `'l'` $\rightarrow$ `'1'` (Value 1)
- Separators `'-'`, `'_'`, `'%'`, `'$'`, `'#'`, `'@'`, `' '` $\rightarrow$ MUST be stripped.

### 1.2 Binary Value Table (5 Bits per Character)
| Dec | Char | Dec | Char | Dec | Char | Dec | Char |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 0 | `0` | 8 | `8` | 16 | `G` | 24 | `R` |
| 1 | `1` | 9 | `9` | 17 | `H` | 25 | `S` |
| 2 | `2` | 10 | `A` | 18 | `J` | 26 | `T` |
| 3 | `3` | 11 | `B` | 19 | `K` | 27 | `V` |
| 4 | `4` | 12 | `C` | 20 | `M` | 28 | `W` |
| 5 | `5` | 13 | `D` | 21 | `N` | 29 | `X` |
| 6 | `6` | 14 | `E` | 22 | `P` | 30 | `Y` |
| 7 | `7` | 15 | `F` | 23 | `Q` | 31 | `Z` |

---

## 2. Canonical Domain Normalization

Before computing an ID or checking the registry, every domain input MUST be canonicalized through the following pipeline:
1. **Trim:** Strip leading and trailing whitespace.
2. **Protocol Strip:** Strip `http://`, `https://`, `sds://` prefixes.
3. **Path & Port Strip:** Strip any `/path` or `:port` components.
4. **Trailing Root Dot:** Remove trailing dot `.` if present (`xyz.com.` $\rightarrow$ `xyz.com`).
5. **IDNA / Punycode:** Convert non-ASCII unicode labels to standard IDNA ACE format.
6. **Lowercase:** Convert all ASCII characters to lowercase.
7. **FQDN Validation:** Validate that the string consists of dot-separated alphanumeric labels of max 63 chars each, with no starting/ending hyphens.

---

## 3. Tiered Expansion & Allocation Policy

### 3.1 Tier Structure
The SDS ID structure is composed of:
$$\mathbf{ID} = \text{Payload} \parallel \text{Checksum}$$
where Checksum is ALWAYS the trailing 2 characters.

| Tier | Payload Chars | Checksum Chars | Total Length | Unique Namespace Slots |
|:---:|:---:|:---:|:---:|:---:|
| **Tier 1 (Default)** | 8 chars (40 bits) | 2 chars (10 bits) | **10 characters** | $32^8 = \mathbf{1,099,511,627,776}$ (~1.1 Trillion) |
| **Tier 2 (Expanded)** | 10 chars (50 bits) | 2 chars (10 bits) | **12 characters** | $32^{10} = \mathbf{1,125,899,906,842,624}$ (~1.12 Quadrillion) |
| **Tier 3 (Enterprise)**| 12 chars (60 bits) | 2 chars (10 bits) | **14 characters** | $32^{12} = \mathbf{1,152,921,504,606,846,976}$ (~1.15 Quintillion) |

### 3.2 Expansion Rules
1. **Immutable Once Issued:** Once a domain receives an ID, that ID is permanently immutable and NEVER expands or changes.
2. **Salt Window:** Allocation starts at `Tier 1` with `salt = 0`. If a hash collision occurs against an existing registered domain, the allocation engine increments `salt = 1..63` (`domain#salt`).
3. **Automatic Tier Elevation:** If `salt` reaches 64 without finding an unassigned slot in Tier 1, or if a global registry policy declares Tier 1 saturated, newly registered domains are issued IDs under `Tier 2` (12 characters).

---

## 4. Cryptographic Hashing & Checksum Algorithm

### 4.1 Payload Bit Extraction
1. Compute the cryptographic hash:
   $$\text{Hash} = \text{SHA-256}(\text{CanonicalDomain} \parallel \text{OptionalSalt})$$
2. Extract the MSB bitstream from the 256-bit hash.
3. Group bits into 5-bit chunks for each payload character:
   $$\text{Char}_i = \text{Alphabet}\left[\sum_{j=0}^{4} \text{Bit}_{5i + j} \times 2^{4 - j}\right]$$

### 4.2 Polynomial Checksum Formula
The trailing 2 characters form a 10-bit modulo checksum over the entire payload string:
$$\text{Sum} = \left(\sum_{i=1}^{L_{\text{payload}}} i \times \text{Val}(\text{Payload}_i)\right) \pmod{1024}$$

The 10-bit sum is split into two 5-bit base32 characters:
$$C_1 = \text{Alphabet}\left[\lfloor \text{Sum} / 32 \rfloor\right]$$
$$C_2 = \text{Alphabet}\left[\text{Sum} \pmod{32}\right]$$

**Error Detection Capability:** Detects 100% of single-character substitution errors and 100% of adjacent transpositions.

---

## 5. Atomic Registration & Concurrency Guarantees

File renaming alone is insufficient for multi-process environments. SDS requires **atomic registry storage**:

### Database Schema (SQLite / PostgreSQL / MySQL)
```sql
CREATE TABLE IF NOT EXISTS sds_domain_registry (
    raw_id VARCHAR(16) PRIMARY KEY,
    canonical_domain VARCHAR(253) UNIQUE NOT NULL,
    tier TINYINT NOT NULL DEFAULT 1,
    checksum CHAR(2) NOT NULL,
    public_key VARCHAR(64),
    signature VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sds_raw_id ON sds_domain_registry(raw_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sds_canonical ON sds_domain_registry(canonical_domain);
```

### Atomic Registration Algorithm
```text
BEGIN IMMEDIATE TRANSACTION;
1. SELECT raw_id FROM sds_domain_registry WHERE canonical_domain = ?;
2. IF EXISTS -> COMMIT and RETURN existing raw_id (Idempotent).
3. FOR tier IN [Tier1, Tier2, Tier3]:
       FOR salt IN [0..63]:
           candidate = generate_domain_id_tiered(canonical_domain, salt, tier);
           INSERT OR IGNORE INTO sds_domain_registry (raw_id, canonical_domain, ...)
           VALUES (candidate.raw_id, canonical_domain, ...);
           IF ROWS_AFFECTED == 1 -> COMMIT and RETURN candidate.raw_id;
4. ROLLBACK and RETURN Error;
```

---

## 6. Authenticated Offline Resolution (Signed SDS Records)

Offline decoding guarantees structural validity via the checksum, but trusted domain authentication requires **cryptographic proof of registry authority**.

### Signed Record Format (JSON-LD / Canonical JSON)
```json
{
  "protocol": "sds-v1",
  "domain_id": "19EGDPHYN9",
  "canonical_domain": "xyz.com",
  "tier": 1,
  "registered_at": "2026-10-27T06:21:44Z",
  "authority_pubkey": "ed25519:7a4f9b8c...",
  "signature": "ed25519_sig_in_hex_or_base64..."
}
```
SDS clients (desktop, mobile Flutter app) verify the `signature` against pre-installed or DNS-pinned registry authority public keys before trusting sensitive communications.

---

## 7. Cross-Language SDK Contract (Rust & Flutter FFI)

### 7.1 Rust Core C-ABI Export
```rust
#[no_mangle]
pub extern "C" fn sds_normalize_domain(
    input_ptr: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_generate_id(
    domain_ptr: *const c_char,
    salt: u32,
    tier: u8,
    out_buf: *mut c_char,
    out_len: usize,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_verify_id(id_ptr: *const c_char) -> i32;
```

### 7.2 Flutter Dart Interface
```dart
class SdsCore {
  static String normalize(String domain);
  static String generateId(String domain, {int salt = 0, int tier = 1});
  static bool verifyId(String id);
  static Future<SdsRecord?> resolveOffline(String id);
}
```

---

## 8. Frozen Cross-Language Test Vectors

All implementations (Rust, Dart/Flutter, Python, Go) MUST pass the test vectors defined in [test_vectors.json](file:///Users/malleravindra/Projucts/PingDart%20Chat/UCall/UcallSDS/test_vectors.json):

| Domain | Tier | Length | Payload | Checksum | Full SDS ID |
|---|:---:|:---:|:---:|:---:|:---:|
| `xyz.com` | 1 | 10 | `19EGDPHY` | `N9` | **`19EGDPHYN9`** |
| `meddylist.com` | 1 | 10 | `Q2KE9Y5F` | `G8` | **`Q2KE9Y5FG8`** |
| `bloomingeasyservices.in` | 1 | 10 | `D543HERN` | `H8` | **`D543HERNH8`** |
| `pingdart.com` | 1 | 10 | `5QJCXPH2` | `HN` | **`5QJCXPH2HN`** |
| `xyz.com` | 2 | 12 | `19EGDPHYZJ` | `3M` | **`19EGDPHYZJ3M`** |
| `pingdart.com` | 2 | 12 | `5QJCXPH2V1` | `SJ` | **`5QJCXPH2V1SJ`** |

---

## 9. Modular Architecture & Subsystem Responsibilities

SDS is engineered as a decoupled, transport-independent protocol suite implemented in pure Rust with FFI bindings.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Application Layer (UCall)                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Dart FFI / C-ABI
┌───────────────────────────────────▼────────────────────────────────────┐
│                    sds-flutter (FFI Native Bridge)                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                              SDS RUST SDK                              │
│                                                                        │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────┐  │
│  │        sds-core         │  │            sds-identity             │  │
│  │ Crockford Base32 IDs,   │  │ Ed25519 signatures, verified        │  │
│  │ Checksums, Wire Frames  │  │ profiles, server proofs             │  │
│  └───────────┬─────────────┘  └──────────────────┬──────────────────┘  │
│              │                                   │                     │
│  ┌───────────▼─────────────┐  ┌──────────────────▼──────────────────┐  │
│  │      sds-discovery      │  │            sds-security             │  │
│  │ SDS ID -> Domain ->     │  │ Noise Protocol Handshake &          │  │
│  │ DNS SRV & Signed Record │  │ Double Ratchet E2EE                 │  │
│  └───────────┬─────────────┘  └──────────────────┬──────────────────┘  │
│              │                                   │                     │
│  ┌───────────▼───────────────────────────────────▼──────────────────┐  │
│  │                          sds-transport                           │  │
│  │  • QUIC Streams (Reliable) & Unreliable Datagrams (Low Latency)  │  │
│  │  • Connection Migration across IP/WiFi/Cellular handover         │  │
│  │  • Replay-Safe 0-RTT Cache & Congestion Control (BBR)            │  │
│  └───────────┬───────────────────────────────────┬──────────────────┘  │
│              │                                   │                     │
│  ┌───────────▼─────────────┐  ┌──────────────────▼──────────────────┐  │
│  │        sds-media        │  │            sds-messaging            │  │
│  │ Opus Audio, AV1 Video,  │  │ Cross-server chat, delivery acks,   │  │
│  │ Jitter Buffer, Deadlines│  │ offline queues & sync               │  │
│  └───────────┬─────────────┘  └──────────────────┬──────────────────┘  │
│              │                                   │                     │
│  ┌───────────▼───────────────────────────────────▼──────────────────┐  │
│  │                       sds-relay (DERP/MASQUE)                    │  │
│  │ Authenticated encrypted relay fallback for symmetric NATs        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Module Matrix
1. **`sds-core`**: Standard domain ID generation, Crockford Base32 codecs, polynomial checksum verification, universal binary wire frame serialization, and protocol negotiation versioning.
2. **`sds-identity`**: Cryptographic Ed25519 keypairs, domain ownership certificates, verifiable application profiles (app name, icon hash, authorized scopes), and public-key registry verification.
3. **`sds-discovery`**: Resolves `SDS ID` $\rightarrow$ `Domain` $\rightarrow$ `DNS SRV / TXT records` $\rightarrow$ `Authenticated IP/Port endpoint` with local cryptographic record caching.
4. **`sds-transport`**: Native QUIC-based transport engine managing connection state machines, bidirectional multiplexed streams, unreliable datagrams, connection migration, and replay-safe 0-RTT state.
5. **`sds-media`**: Real-time packetization of audio (Opus) and video (AV1 / H.265), sequence tracking, playout deadline tagging, jitter buffering, and Forward Error Correction (FEC).
6. **`sds-messaging`**: Server-to-server and client-to-client asynchronous messaging, cryptographic delivery receipts, idempotency keys, and offline queue synchronization.
7. **`sds-relay`**: End-to-end encrypted packet forwarding engine for endpoints obstructed by strict symmetric NATs/firewalls (similar to Tailscale DERP or IETF MASQUE).
8. **`sds-ffi`**: C-compatible shared library (`.so`, `.dylib`, `.dll`, `.a`) and Dart FFI bindings exposing clean, thread-safe asynchronous APIs for Flutter.

---

## 10. SDS Binary Wire Protocol Specification

All communication across the network—whether transmitted over QUIC streams, raw UDP datagrams, or through relay servers—uses the **SDS Universal Binary Frame**.

### 10.1 Frame Layout (RFC 28-Byte Header, Network Byte Order / Big-Endian)

The SDS header consists of exactly **28 bytes** (7 contiguous 32-bit words), aligning on 32-bit word boundaries:

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
|                                                               |
+                    Payload Data (Variable Length)            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Authentication Tag / MAC (16 Bytes, Optional)       |
|            (Present when Flags.AUTH_TAG_PRESENT == 1)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 10.2 Header Field Offsets & Definitions

| Byte Offset | Field Name | Width | Type | Description |
|---|---|---|---|---|
| `0..2` | **Magic** | 3 Bytes | `[u8; 3]` | Constant `0x53 0x44 0x53` (ASCII `"SDS"`). Packets missing this magic MUST be dropped immediately. |
| `3` | **Version** | 1 Byte | `u8` | Protocol version: `0x01` (v1.0). |
| `4` | **Flags** | 1 Byte | `u8` | Bit 0: `IS_DATAGRAM` (0 = stream, 1 = datagram)<br>Bit 1: `ENCRYPTED_E2EE`<br>Bit 2: `AUTH_TAG_PRESENT` (16-byte MAC appended)<br>Bit 3: `COMPRESSED_ZSTD`<br>Bit 4: `URGENT_PRIORITY`<br>Bits 5..7: Reserved (MUST be 0). |
| `5` | **Sub-Type** | 1 Byte | `u8` | Command or codec sub-identifier. |
| `6..7` | **Frame Type** | 2 Bytes | `u16` BE | Primary packet category (see §10.3). |
| `8..11` | **Stream ID** | 4 Bytes | `u32` BE | Logical multiplexed channel (0 = Control, 1 = Signaling, 2 = Chat, 3 = Keyframes). |
| `12..19`| **Sequence Number** | 8 Bytes | `u64` BE | Monotonically increasing counter per stream for ordering and deduplication. |
| `20..23`| **Payload Length** | 4 Bytes | `u32` BE | Length of `Payload Data` in bytes ($0 \le N \le 16,777,216$). |
| `24..25`| **Lifetime Budget** | 2 Bytes | `u16` BE | Relative playout expiration budget in milliseconds (`lifetime_ms`). Value `0` denotes infinite lifetime. |
| `26..27`| **Reserved** | 2 Bytes | `u16` BE | Extension padding. MUST be set to `0x0000`. |
| `28..28+N`| **Payload Data** | $N$ Bytes | `[u8]` | Wire payload data. |
| `+16` | **Auth Tag** | 16 Bytes | `[u8; 16]`| Poly1305 / HMAC-SHA256 authentication tag if flag bit 2 is set. |

### 10.3 Mapping SDS Framing to QUIC Channels (RFC 9000 & RFC 9221)

SDS does NOT duplicate QUIC transport framing, packet numbers, or connection IDs. The QUIC implementation handles connection IDs (DCID/SCID), TLS 1.3 encryption, and path migration. SDS frames travel within the following designated QUIC channels:

| QUIC Channel | Channel Type | SDS Message Types | Delivery Semantics |
|---|---|---|---|
| **Stream 0** | Bidirectional Reliable Stream | `HANDSHAKE_INIT`, `HANDSHAKE_RESP`, `CLOSE_NOTIFY` | Guaranteed, ordered, TLS-authenticated |
| **Stream 1** | Bidirectional Reliable Stream | `CALL_INVITE`, `CALL_RINGING`, `CALL_ACCEPT`, `CALL_TERMINATE` | Guaranteed signaling, zero packet loss |
| **Stream 2** | Bidirectional Reliable Stream | `MSG_ENVELOPE`, `MSG_ACK`, `MSG_OFFLINE_SYNC_REQ` | Ordered E2EE messaging & delivery receipts |
| **Stream 3** | Unidirectional Reliable Stream | `MEDIA_VIDEO_KEYFRAME` | Reliable intra-frame video burst (AV1/H.265) |
| **QUIC DATAGRAM** | Unreliable Datagram (RFC 9221) | `MEDIA_AUDIO_OPUS`, `MEDIA_VIDEO_DELTA`, `MEDIA_FEEDBACK_RTCP` | Lowest latency, deadline-bounded, no retransmission stall |

---

### 11.1 QUIC Transport Security and E2EE Boundaries
- **Hop-by-Hop Transport Security:** QUIC uses TLS-derived packet-protection keys and the negotiated AEAD algorithm to provide confidentiality and integrity for protected QUIC packets, including packets carrying reliable STREAM frames and unreliable DATAGRAM frames. Nonce construction and packet-number handling MUST follow the applicable QUIC specifications (RFC 9001 §5.3: reconstructing the 64-bit packet number, left-padding with zeros to the AEAD nonce length, and XORing with the TLS 1.3 `iv`).
- **End-to-End Application Security:** The SDS routing header may expose only the fields required for forwarding. Sensitive application content must be protected using the applicable end-to-end encryption protocol (Double Ratchet for 1:1 communications, SFrame/MLS for group sessions). QUIC transport protection does not replace end-to-end encryption because intermediate federation servers terminate their own transport connections.
- **Group Media:** SFrame provides end-to-end media-frame encryption and authentication, while MLS provides group key establishment and membership updates. Group E2EE remains a preview feature until implementation and interoperability tests pass.
- **Cryptographic Primitives:**
  - **Identity & Signatures:** Ed25519 (`edwards25519` curve, SHA-512) for server endpoint proofs and signed user profiles.
  - **Key Exchange:** X25519 (`curve25519`) ECDH.
  - **Symmetric Encryption:** ChaCha20-Poly1305 (IETF RFC 8439) or AES-256-GCM.
  - **Session Security:** TLS 1.3 with ALPN `sds/1.0`.
  - **End-to-End Encryption (E2EE):** Double Ratchet Algorithm with Diffie-Hellman ratchets and symmetric KDF chains. Federated relay servers see only encrypted envelopes.

### 11.2 RFC 9001 Hardened 0-RTT Replay Protection & Distributed Server Policy
Application data transmitted in QUIC 0-RTT is vulnerable to replay attacks (RFC 9001 §9.2). SDS enforces strict server-controlled anti-replay mechanisms:

1. **Idempotency Gate:** State-mutating operations (`CALL_INVITE`, `MSG_ENVELOPE`, `MSG_OFFLINE_SYNC_REQ`) are **STRICTLY PROHIBITED** in 0-RTT early data. Any 0-RTT frame of these types MUST be rejected with error `ERR_0RTT_OPERATION_FORBIDDEN` (`0x0007`).
2. **Permitted 0-RTT Frames:** Strictly read-only or idempotent operations (`RESOLVE_PROFILE_REQ`, `PING`, `PRESENCE_STATE`).
3. **Unique Idempotency Key:** Every 0-RTT request MUST include a 128-bit unique request identifier (`idempotency_key`).
4. **Server-Bounded Session Tickets:** Session tickets issued by the server contain an absolute server epoch expiration timestamp (`ticket_expiry_epoch_ms`, maximum lifetime: 300 seconds).
5. **Distributed Multi-Instance Replay Store (`SharedReplayStore`):** In clustered deployments where multiple server instances accept early data, replay detection is not isolated to single-instance memory. Server clusters MUST either:
   - **(a) Route Sticky 0-RTT:** Bind session tickets to an explicit `server_instance_id` (enforcing full 1-RTT handshake if routed to an alternate instance), OR
   - **(b) Synchronize Strike Stores:** Use a shared atomic strike register (e.g., Redis cluster / atomic KV) so that tickets redeemed on Instance A are immediately marked as spent on Instance B. Duplicate ticket submissions across any instance return `ERR_REPLAY_DETECTED` (`0x0006`).

### 11.3 Standardized Playout Lifetime Budget (`lifetime_ms`) & Jitter Dwell Rules
- **Field Definition:** The `lifetime_ms` field (2 bytes BE, offset 24..25) defines the **Receiver Jitter Queue Dwell Budget** in milliseconds.
- **Rule for `lifetime_ms == 0`:** A value of `0` denotes **Infinite Lifetime / No Dwell Expiration**. This applies to all control, signaling, reliable stream frames, and persistent message envelopes.
- **Rule for Datagram Media (`FLAG_IS_DATAGRAM == 1`):** For real-time audio (Opus) and video delta frames, `lifetime_ms` specifies the maximum tolerable time in milliseconds the frame is permitted to dwell inside the receiver's jitter buffer before presentation to the decoder.
- **Transit Time Compensation (Clock-Independent):** To prevent network lag from causing stale playback without requiring wall-clock synchronization between peers, the receiver adjusts the remaining queue budget upon arrival:
  $$\Delta t_{\text{remaining}} = \text{lifetime\_ms} - \min\left(\frac{\text{SRTT}}{2}, \frac{\text{lifetime\_ms}}{2}\right)$$
  where $\text{SRTT}$ is the smoothed round-trip time continuously measured by QUIC transport ping probes. If the packet's residence time in the jitter queue exceeds $\Delta t_{\text{remaining}}$, the receiver **MUST DROP** the packet immediately without stalling playback or triggering retransmissions.


---

## 12. Connection Lifecycle & Federation State Machine

```
                               ┌─────────────────┐
                               │  UNINITIALIZED  │
                               └────────┬────────┘
                                        │ User enters 10-char SDS ID
                               ┌────────▼────────┐
                               │   ID_RESOLVED   │ (Check checksum & resolve domain)
                               └────────┬────────┘
                                        │ Query DNS SRV / TXT records
                               ┌────────▼────────┐
                               │ ENDPOINT_FOUND  │ (Target endpoint & signed server pubkey)
                               └────────┬────────┘
                                        │ Authenticate server proof
                    ┌───────────────────┴───────────────────┐
                    │                                       │ Direct UDP reachable
                    │ Direct failed / symmetric NAT         ▼
                    ▼                          ┌────────────────────────┐
         ┌─────────────────────┐               │     DIRECT_QUIC_0RTT   │
         │   RELAY_FALLBACK    │               └────────────┬───────────┘
         └──────────┬──────────┘                            │ Handshake completed
                    │ Encrypted relay path                  │
                    └───────────────────┬───────────────────┘
                                        │
                               ┌────────▼────────┐
                               │  SESSION_ACTIVE │
                               └────────┬────────┘
               Network change detected  │  (WiFi <-> 5G / IP change)
                               ┌────────▼────────┐
                               │  CID_MIGRATING  │
                               └────────┬────────┘
                                        │ Connection ID validated on new 4-tuple
                               ┌────────▼────────┐
                               │  SESSION_ACTIVE │
                               └────────┬────────┘
                                        │ Close frame / timeout
                               ┌────────▼────────┐
                               │   TERMINATED    │
                               └─────────────────┘
```

### Discovery Pipeline (ID $\rightarrow$ Endpoint)
1. **User Input:** User enters SDS ID `7K9M2P4X8B`.
2. **Local Registry Check:** `sds_core::validate_domain_id` verifies polynomial checksum. If cached locally in `sds_registry.json`, return canonical domain immediately.
3. **DNS SRV & TXT Discovery:** If not cached, the SDK performs DNS resolution on the domain:
   - `_sds._udp.<canonical_domain>` $\rightarrow$ returns target hostname and QUIC transport port (e.g. `4433`).
   - `TXT` record at `_sds.<canonical_domain>` $\rightarrow$ returns public identity key: `v=sds1; k=ed25519; p=<base64_pubkey>`.
4. **Endpoint Signature Verification:** Client connects and verifies that the remote server signs the TLS/Noise handshake with the matching Ed25519 key.

---

## 13. Canonical Protocol Error Codes

| Error Code (Hex) | Name | Description |
|---|---|---|
| `0x0000` | `OK` | Operation completed successfully. |
| `0x0001` | `ERR_MALFORMED_FRAME` | Frame length, magic bytes, or header structure is invalid. |
| `0x0002` | `ERR_UNSUPPORTED_VERSION` | Requested protocol version is not supported by peer. |
| `0x0003` | `ERR_ID_CHECKSUM_INVALID` | 10-char domain ID failed polynomial checksum verification. |
| `0x0004` | `ERR_DOMAIN_NOT_REGISTERED` | SDS domain not found in local registry or DNS directory. |
| `0x0005` | `ERR_IDENTITY_SIGNATURE_FAILED` | Ed25519 signature verification on server/profile record failed. |
| `0x0006` | `ERR_REPLAY_DETECTED` | 0-RTT token, nonce, or sequence number was reused. |
| `0x0007` | `ERR_0RTT_OPERATION_FORBIDDEN` | Attempted non-idempotent operation over 0-RTT transport. |
| `0x0008` | `ERR_DEADLINE_EXPIRED` | Media datagram arrived past playout deadline and was dropped. |
| `0x0009` | `ERR_DIRECT_PATH_UNAVAILABLE` | Direct UDP connection timed out; switching to relay fallback. |
| `0x000A` | `ERR_RELAY_AUTH_FAILED` | Token rejected by SDS relay server. |
| `0x000B` | `ERR_RATE_LIMITED` | Peer exceeded maximum permitted requests per second. |
| `0x000C` | `ERR_CALL_BUSY` | Callee is currently engaged in another active call. |
| `0x000D` | `ERR_CALL_DECLINED` | Callee explicitly rejected the call invitation. |

---

## 14. Rust C-ABI & Flutter FFI Contract

```rust
// C-ABI Export Definitions for libsds_core / libsds_transport

#[repr(C)]
pub struct SdsProfileRecord {
    pub sds_id: [c_char; 16],
    pub canonical_domain: [c_char; 256],
    pub display_name: [c_char; 64],
    pub app_name: [c_char; 64],
    pub public_key: [c_char; 64],
    pub endpoint_host: [c_char; 256],
    pub endpoint_port: u16,
    pub is_verified: bool,
}

#[no_mangle]
pub extern "C" fn sds_resolve_endpoint(
    sds_id: *const c_char,
    out_profile: *mut SdsProfileRecord,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_transport_connect(
    endpoint: *const c_char,
    port: u16,
    out_session_handle: *mut u64,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_transport_send_datagram(
    session_handle: u64,
    frame_type: u16,
    payload_ptr: *const u8,
    payload_len: u32,
    deadline_ms: u16,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_transport_send_stream(
    session_handle: u64,
    stream_id: u32,
    payload_ptr: *const u8,
    payload_len: u32,
) -> i32;

#[no_mangle]
pub extern "C" fn sds_transport_disconnect(session_handle: u64) -> i32;
```

---

---

## 16. Decentralized Server-to-Server Federation Architecture

### 16.1 Mesh Topology & Dynamic Server Joining
The SDS network operates as a decentralized, federated network of independent application servers:
```
           Server 1 (Domain A)                     Server 2 (Domain B)
      ┌──────────────────────────┐            ┌──────────────────────────┐
      │  User 1 · User 2 · User 3│            │  User 1 · User 2 · User 3│
      └────────────┬─────────────┘            └────────────┬─────────────┘
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                          UCall SDS Protocol Federation
                    Identity · Discovery · Secure QUIC Transport
                                       │
                   ┌───────────────────┴───────────────────┐
                   │                                       │
      ┌────────────┴─────────────┐            ┌────────────┴─────────────┐
      │  User 1 · User 2 · User 3│            │  User 1 · User 2 · User 3│
      └──────────────────────────┘            └──────────────────────────┘
           Server 3 (Domain C)                     Server N (Domain N)
```
- **Zero Centralized Coordinator:** No single server acts as a global master. Any server (Domain A) can discover and establish authenticated QUIC connections directly with any other server (Domain B).
- **Dynamic Join:** When Server 3 (Domain C) enters the network, it publishes standard DNS discovery records (`_sds._udp.domain-c.com` SRV and `_sds.domain-c.com` TXT). Existing servers resolve Server 3 on-demand without network re-indexing or re-architecting.
- **Federated Routing:** Each server runs an `SdsFederationRouter`. When a local user sends a message or initiates a call to `user@domain-b.com`, Server 1 routes the payload across the federated QUIC link to Server 2.

### 16.2 Delivery Receipts & Offline Retry Queues
Federated server-to-server messaging enforces store-and-forward reliability:
1. **Queued For Peer:** If Domain B's endpoint is temporarily unreachable, messages are stored in an outbound priority queue with exponential backoff retry.
2. **Delivery Statuses:**
   - `DeliveredDirectLocal`: Recipient is connected to the same local server.
   - `QueuedForFederatedServer`: Envelope buffered for outbound delivery.
   - `TransmittedToFederatedServer`: Verified receipt from peer server.
   - `DeliveredToRecipient`: End-user device acknowledged receipt.

---

## 17. User-to-User End-to-End Encryption (E2EE) Specification

### 17.1 Zero Server Visibility Threat Model
Servers act strictly as blind transport routers. Even if intermediate servers or relay nodes are compromised, message content and media payloads cannot be inspected or tampered with.

### 17.2 Cryptographic Primitives & Envelope Format
- **User Cryptographic Identity:** Every user generates an Ed25519 identity keypair (`SdsIdentityKeyPair`) and an X25519 Diffie-Hellman identity key.
- **Prekey Bundles (`PrekeyBundle`):**
  - `identity_pubkey_hex`: Ed25519 public key (signing).
  - `dh_identity_pubkey_hex`: X25519 public key (Diffie-Hellman).
  - `signed_prekey_hex`: Rotated X25519 public key.
  - `signed_prekey_signature_hex`: Ed25519 signature of `signed_prekey_hex`.
- **Key Exchange:** X25519 Diffie-Hellman (RFC 7748) between sender's ephemeral private key and recipient's prekey public key:
  $$K_{\text{shared}} = \text{X25519}(sk_{\text{ephemeral}}, pk_{\text{prekey}})$$
  $$K_{\text{sym}} = \text{HKDF-SHA256}(K_{\text{shared}}, \text{"sds-v1-e2ee-message"})$$
- **Authenticated Encryption:** ChaCha20-Poly1305 AEAD (RFC 8439) with a 96-bit unique random nonce.
- **Envelope Wire Format (`E2eeMessageEnvelope`):**
  - `sender_sds_id`, `recipient_sds_id`: Routing metadata.
  - `ephemeral_dh_pubkey_hex`: Sender's 32-byte ephemeral public key.
  - `nonce_hex`: 12-byte random nonce.
  - `ciphertext_hex`: ChaCha20 ciphertext + Poly1305 16-byte authentication tag.
### 17.3 Double Ratchet Session Protocol (Forward Secrecy & Post-Compromise Security)
To ensure past communications cannot be decrypted if a device key is compromised later (Forward Secrecy), and to allow conversations to heal after temporary memory inspection (Post-Compromise Break-in Recovery), ongoing sessions use the Double Ratchet:
1. **Symmetric KDF Chain Ratchet:**
   Every sent and received message advances a symmetric key-derivation chain:
   $$(CK_{i+1}, MK_i) = \text{KDF}_{CK}(CK_i)$$
   The message key $MK_i$ is immediately deleted after encrypting or decrypting a message.
2. **Diffie-Hellman Asymmetric Ratchet:**
   When a peer replies, they publish a new ephemeral X25519 public key. Receiving a new DH key triggers a root ratchet step:
   $$DH_{\text{recv}} = \text{X25519}(sk_{\text{local}}, pk_{\text{peer\_new}})$$
   $$(RK_{\text{new}}, CK_{\text{recv\_new}}) = \text{KDF}_{RK}(RK_{\text{current}}, DH_{\text{recv}})$$
   The receiver then generates a new local ephemeral keypair and derives a new sending chain key, rendering any previous key compromise useless for subsequent messages.
3. **Out-of-Order Delivery & Dropped Packets:**
   Skipped message keys are safely stored in `skipped_message_keys` (capped at 1,000 keys) until the corresponding sequence numbers arrive.

---

## 18. Domain Registration & DNS Setup Wizard Specification

### 18.1 Automated DNS Records
Developers deploying an SDS server run the automated DNS Wizard which generates compliant records:
| Record Type | Host / Label | Target / Value | Purpose |
|---|---|---|---|
| **SRV** | `_sds._udp.<domain>` | `Priority: 10, Weight: 10, Port: 4433, Target: sds.<domain>` | Advertises QUIC transport hostname and port |
| **TXT** | `_sds.<domain>` | `"v=sds1; id=<10-char-id>; k=ed25519; p=<pubkey>"` | Domain ownership & cryptographic endpoint proof |
| **A / AAAA** | `sds.<domain>` | `<server_ipv4> / <server_ipv6>` | Resolves host to IP address |
| **CNAME** | (optional alias) | Target FQDN | Where DNS infrastructure permits |

### 18.2 DNS Verification Engine
The SDK includes a built-in verification engine (`DnsVerificationEngine`) that queries DNS and validates:
1. `sds_txt_verified`: Valid `v=sds1` signature record present.
2. `srv_record_verified`: Valid port and hostname configuration.
3. `authority_key_matched`: Published public key matches server private key.
4. `is_ready_for_federation`: All required checks pass.

### 18.3 DNSSEC Cryptographic Trust & Key Rotation Chain
To eliminate DNS spoofing, cache poisoning, and rogue registrar attacks, identity trust is anchored cryptographically:
1. **DNSSEC Trust Anchor (`AD` Bit):** When resolving `_sds.<domain>`, resolvers MUST verify the DNSSEC `RRSIG` and `DS` validation chain to the IANA root trust anchor. Unauthenticated DNS responses without the Authentic Data (`AD`) bit trigger warning or validation failure.
2. **Chain of Custody Key Rotation:** When a domain rotates its Ed25519 server identity key:
   - The new key is published in TXT with a backward signature: `v=sds1; p=<new_key>; prev=<old_key>; sig=<sig_of_new_by_old>`.
   - Federated peers verify that the previous authority key signed the new key before accepting routing updates.
3. **Signed Transparency Ledger:** Servers can optionally register domain $\leftrightarrow$ public key bindings in an append-only transparency log (Merkle tree) verified by independent witnesses.

---

## 19. Automatic App Name & Logo Discovery Specification

### 19.1 Signed Application Profile (`SdsAppProfile`)
Servers publish a signed application profile at `/.well-known/sds-app-profile.json`:
```json
{
  "protocol": "SDS",
  "protocol_version": "1.0",
  "domain": "chat.example.com",
  "sds_id": "7K9M2P4X8B",
  "app_id": "example-chat",
  "app_name": "Example Chat",
  "app_logo_url": "https://example.com/logo.png",
  "app_logo_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "website": "https://example.com",
  "server_identity_hex": "7a4f9b8c00112233...",
  "capabilities": ["messaging", "voice", "video", "e2ee"],
  "signature_hex": "d8e3..."
}
```

### 19.2 Security & Integrity Protections
1. **Ed25519 Profile Signature:** The canonical profile bytes are cryptographically signed by the server's identity key. Modifying the app name or capabilities invalidates the signature.
2. **Logo Hash Verification:** `app_logo_sha256` prevents CDN tampering or dynamic image replacement attacks.
3. **SSRF & Malicious URL Protections:** Logo URLs MUST:
   - Use HTTPS protocol only (`https://`).
   - Forbid localhost (`127.0.0.1`, `localhost`, `::1`).
   - Forbid private IP blocks (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`).
   - Forbid AWS/GCP cloud metadata endpoints (`169.254.169.254`).
4. **App Profile Caching (`AppProfileCache`):** Profiles are cached with an expiration TTL (default: 3600 seconds) to avoid redundant network queries while keeping metadata fresh.

---

## 20. Defense-in-Depth Security Architecture, Threat Model & Release Gates

### 20.1 The 12 Defense-in-Depth Security Layers
To guarantee that the compromise of a single user account, server node, network link, or client device cannot compromise the wider federation or eavesdrop on private communications, UCall SDS implements 12 security layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Layer 1: Zero-Trust Identity                         │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 2: Secure Federation                           │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 3: Cryptographic E2EE (Double Ratchet + MLS)   │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 4: Device & Session Security                   │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 5: Network Isolation & Tiering                 │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 6: DDoS, Quotas & Resource Caps                │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 7: API & Application Hardening                 │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 8: Rust Process & Memory Hardening             │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 9: Secrets & Cryptographic Key Lifecycle       │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 10: Detection, Audit & Privacy Telemetry       │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 11: Supply Chain & Artifact Integrity          │
├────────────────────────────────────────────────────────────────────────┤
│                   Layer 12: Recovery, Containment & Quarantine         │
└────────────────────────────────────────────────────────────────────────┘
```

| Layer | Security Control | Implementation Mechanism | Status |
|---|---|---|---|
| **Layer 1: Zero-Trust Identity** | Continuous authentication | Cryptographic proof on every packet; zero assumed perimeter trust. Re-authenticate on sensitive state transitions. | **[Implemented & Verified]** |
| **Layer 2: Secure Federation** | Server-to-server isolation | Independent Ed25519 node identities, mutual QUIC/TLS verification, request nonces, per-server private keys (no shared master keys). | **[Implemented & Verified]** |
| **Layer 3: Cryptographic E2EE** | Unconditional confidentiality | X25519 + ChaCha20-Poly1305 prekey envelopes and Double Ratchet (1:1 messaging). SFrame media encryption + MLS group ratchets (group calls). | **[Implemented & Verified (1:1)]** / **[Planned (MLS/SFrame)]** |
| **Layer 4: Device & Session Security** | Platform-level key isolation | Hardware keystore integration (iOS Keychain / Android Keystore), refresh token rotation, remote session revocation. | **[Planned]** |
| **Layer 5: Network Isolation** | Defense boundary tiering | Edge gateways, federation routers, and SFU relays run on segregated network segments; internal DBs inaccessible from public WAN. | **[Planned]** |
| **Layer 6: DDoS & Resource Caps** | Admission & rate control | Strict token-bucket rate limits per IP/account/domain, bounded receive buffers, early packet-drop on jitter expiration. | **[Implemented & Verified]** |
| **Layer 7: API Hardening** | Strict input validation | 28-byte wire header validation, payload size enforcement, SSRF defenses on logo URLs (blocking private IP ranges & cloud metadata). | **[Implemented & Verified]** |
| **Layer 8: Rust Process Hardening** | Memory & parser safety | Panic-free deserialization, explicit allocation bounds before buffer reads, `no_std`-ready core logic, non-root execution. | **[Implemented & Verified]** |
| **Layer 9: Secrets & Key Lifecycle** | Key management & rotation | Chain-of-custody key rotation (dual-signed TXT records), automated expiration, emergency revocation broadcast. | **[Implemented & Verified]** |
| **Layer 10: Detection & Audit** | Tamper-evident logging | Immutable event logging for auth failures, key rotations, and federation state changes; strictly zero logging of plaintext or keys. | **[Implemented & Verified]** |
| **Layer 11: Supply Chain Security** | Artifact integrity verification | Pinned dependency tree in `Cargo.lock`, automated `cargo-audit` vulnerability scanning, signed binary releases, SBOM generation. | **[Planned]** |
| **Layer 12: Recovery & Quarantine** | Blast-radius containment | Instant server quarantine mechanism, rogue peer node isolation, offline queue drain upon verified re-admission. | **[Implemented & Verified]** |

---

### 20.2 Extra Protections for Group Calls & Webinars
- **Zero-Plaintext SFU Routing:** Selective Forwarding Units (SFUs) inspect only the 28-byte SDS routing header and SFrame packet metadata. The audio/video payload remains fully encrypted end-to-end between participants.
- **Room Security & Ephemeral Access:**
  - Meeting room IDs use cryptographically random 128-bit identifiers (not guessable sequential IDs).
  - Join invitations carry an expiring cryptographic signature from the room creator.
- **Role-Based Privilege Separation:**
  - *Presenters:* Authorized to publish media streams to the SFU origin.
  - *Moderators:* Cryptographically sign signaling actions (mute participant, spotlight, kick).
  - *Attendees:* Receive encrypted downstream broadcasts only; cannot inject media without moderator approval.
- **Group Key Rotation on Membership Changes:** When an attendee leaves or is evicted from a group call or webinar, group media keys are ratcheted immediately to ensure former participants cannot decrypt future media.

---

### 20.3 Mandatory CI Security Test Suite & Release Gates
Every release candidate MUST pass the following automated security verification suite before promotion:
1. **Malformed Frame & Fuzzing:** Corrupt headers, truncated payloads, and random noise injected into QUIC sockets MUST return `ERR_MALFORMED_FRAME` without panics or memory growth.
2. **Replay & Ticket Strike Register:** 0-RTT replay tokens, duplicated idempotency keys, and expired session tickets MUST return `ERR_REPLAY_DETECTED` on repeated presentation.
3. **E2EE Tamper Detection:** Modifying a single bit in an encrypted envelope MUST trigger Poly1305 MAC verification failure (`aead::Error`).
4. **Out-of-Order Decryption:** Skipped messages delivered out of order MUST decrypt correctly via the Double Ratchet skipped key store.
5. **SSRF URL Sanitization:** Profile logo URLs targeting `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, or `169.254.169.254` MUST be rejected with error.
6. **Duplicate Routing Suppression:** Duplicate federated envelopes MUST be suppressed idempotently with `MessageDeliveryStatus::DuplicateIgnored`.
7. **Node Quarantine:** When a peer server's identity key is revoked, subsequent messages MUST be routed to offline quarantine rather than transmitted.

---

## 21. Stateless SDK Engine & Host Application Delegation Model

### 21.1 Zero Persistent Storage Principle
UCall SDS is explicitly engineered as a **stateless, decentralized communication SDK**:
- **No Local User Database:** The SDK never stores user accounts, credentials, contact lists, or message history to disk.
- **Host Application Authority:** Each participating server's application backend (PostgreSQL, MySQL, Redis, DynamoDB, etc.) remains the sole source of truth for its users, authorization rules, and presence state.
- **Ephemeral Metadata:** User search results, avatar URLs, display names, and presence states are yielded directly to the caller in memory and are never persisted to disk by the SDK.
- **Host Key Storage:** User private identity keys are managed by the host application or device secure enclaves (iOS Keychain / Android Keystore), not written to plaintext files by the SDK.

### 21.2 Federated Search & User Profile Resolution Flow

```
   User 1 (Server 1)                                   User 2 (Server 2)
           │                                                   │
   ┌───────▼────────┐                                 ┌────────┴───────┐
   │  Server 1 App  │                                 │  Server 2 App  │
   │    Backend     │                                 │    Backend     │
   └───────┬────────┘                                 └────────▲───────┘
           │ 1. Search `user2@server2.com`                     │ 4. resolve_user_profile(user2)
   ┌───────▼────────┐                                 ┌────────┴───────┐
   │  Server 1 SDK  │ 2. Domain Discovery & QUIC Link │  Server 2 SDK  │
   │  (Stateless)   ├────────────────────────────────►│  (Stateless)   │
   └───────▲────────┘ 3. PROFILE_QUERY("user2")       └────────┬───────┘
           │                                                   │
           │ 6. Yields SdsUserProfile                          │ 5. Returns name, DP URL, etc.
           └──────────────────◄────────────────────────────────┘
                         (Ephemeral in memory)
```

1. **User 1 Input:** User 1 on Server 1 searches for User 2 using their public SDS address (`user2@server2.com`).
2. **Domain Discovery:** Server 1 SDK decodes the domain `server2.com`, queries DNS SRV/TXT records, and establishes an authenticated QUIC connection to Server 2's endpoint.
3. **Delegation to Application Backend:** Server 2 SDK receives `PROFILE_QUERY("user2")` and invokes the registered `SdsAppBackendAdapter::resolve_user_profile("user2")`.
4. **Backend Authorization:** Server 2 application backend evaluates privacy settings, contacts, or blocks, and returns an ephemeral `SdsUserProfile` (display name, avatar DP URL, public identity key).
5. **Zero Disk Footprint:** Server 2 SDK streams the metadata back to Server 1 SDK. Server 1 SDK returns the metadata to User 1's client UI without storing any record in a local database.

### 21.3 Offline Message Policy & Typed Delivery Status Semantics
When a recipient or their home server is offline:
- **Default Stateless Policy (Zero SDK Persistence):** If a recipient server is offline or unreachable, the SDK reports `MessageDeliveryStatus::UserServerUnavailable`. The SDK persists zero message content to disk.
- **Typed `QueueAcceptance` Contract:** To ensure durable persistence guarantees cannot be misunderstood, the application adapter uses an explicit result enum:
  ```rust
  pub enum QueueAcceptance {
      DeliveredLive,
      DurablyAccepted { queue_receipt: String },
      NotAccepted,
  }
  ```
- **Strict `RecipientOfflineQueued` Semantics:** The SDK **NEVER** reports `RecipientOfflineQueued` unless the application backend returns `Ok(QueueAcceptance::DurablyAccepted { queue_receipt })`. The `queue_receipt` is returned in `MessageDeliveryStatus::RecipientOfflineQueued { queue_receipt }` as cryptographic or database commit evidence without disclosing message plaintext.
- **In-Memory Transit Retry (Opt-In):** For ephemeral network hiccups, the host application can enable in-memory transit retry (`enable_in_memory_retry = true`). In this case, messages in transit are tracked ephemerally in RAM (`QueuedForFederatedServer`) and drained upon reconnection; restarting the SDK process immediately purges this transit buffer with zero disk remnants.

---

### 21.4 Secure Profile Discovery & Privacy Projection
1. **Authenticated & Authorized Profile Queries:** Inbound `PROFILE_QUERY` requests carry the verified SDS identity of the requester. The receiving SDK invokes `SdsAppBackendAdapter::resolve_user_profile(requester_id, target_user_id)`.
2. **Dynamic Privacy & Visibility Projection:**
   - **Public:** Basic metadata (display name, avatar URL) visible to all federated requesters.
   - **Contacts Only:** Detailed profile fields (e.g., bio) and real-time presence indicators (`is_online`) are disclosed **ONLY** if the host application backend verifies that the requester is in the recipient's authorized contact list.
   - **Blocked / Hidden:** If the target user has blocked the requester, the backend returns `None`, making the user appear non-existent (zero enumeration leakage).
3. **Anti-Scraping Rate Limiting:** Inbound profile queries are throttled per requester (default: 20 queries per 10-second sliding window). Queries exceeding this cap are rejected with an anti-scraping error to prevent bulk directory harvesting.
4. **Zero Key & Private Field Exposure:** `SdsUserProfile` exposes **ONLY** the user's public identity key. Private keys, salt values, and internal account IDs are never exposed over the protocol.

---

### 21.5 No-Persistence Boundary & In-Memory vs. Disk Storage
| State Category | Storage Location | Retention Lifetime | Contents |
|---|---|---|---|
| **Transport State** | RAM only (ephemeral) | Connection lifetime | Quinn QUIC streams, flow control windows, packet numbers, TLS 1.3 session tickets. |
| **Ratchet Crypto State** | RAM only (ephemeral) | Active session | Double Ratchet X25519 ephemeral keys, symmetric chain keys, skipped out-of-order keys (max 1,000). |
| **Replay Strike Register** | RAM only (ephemeral) | 300-second TTL | 0-RTT token hashes and idempotency keys; automatically pruned. |
| **User Data & Profiles** | **Application Backend Only** | App-controlled DB | User accounts, display names, avatar URLs, contact lists, and message history (Postgres/MySQL/Redis). |
| **Durable Queues** | **Application Backend Only** | App-controlled DB | Offline messages accepted for durable store-and-forward. |
| **SDK Disk Footprint** | **None (Zero Disk I/O)** | N/A | The SDK core does not create or write to any local files, SQLite databases, or disk directories. |

**Sanitization of Logs, Telemetry & Crash Reports:**
- Plaintext message contents and private cryptographic keys are strictly excluded from all SDK loggers, tracing spans, and crash reporting hooks.
- Audit logs record event types (e.g., `AuthSuccess`, `KeyRotated`), sequence numbers, actor public identifiers, and SHA-256 hashes, ensuring zero sensitive data exposure.

---

### 21.6 External Audit Checkpoint Anchoring Outside Trust Boundary
A privileged adversary who compromises an individual server could rewrite local logs and recompute SHA-256 hash chains. To neutralize this threat:
1. **Signed Checkpoints (`SignedAuditCheckpoint`):** The audit head is periodically signed using Ed25519 authority keypairs, binding the log epoch, entry count, and SHA-256 root hash.
2. **External Anchoring:** Signed checkpoints are published outside the server's administrative trust boundary (e.g., to external transparency witnesses, independent peer nodes, or remote audit ledgers).
3. **Tamper & Rollback Detection:** Any local tampering, truncation, or historical rewrite creates an irreconcilable hash discrepancy against previously anchored checkpoints, providing irrefutable mathematical evidence of tampering.

---

## 22. Final Architecture Contract & Stateless Compliance

### 22.1 Component Responsibility Matrix
| Component | Primary Responsibility |
|---|---|
| **UCall SDS SDK** | Discovery, authenticated transport, frame routing, E2EE Double Ratchet, and temporary in-memory state. |
| **Application Backend** | User lookup, account permissions, profile metadata, friendship graphs, and optional durable offline queues. |
| **DNS & Identity Layer** | Domain-to-endpoint discovery (SRV/TXT), DNSSEC trust anchors, and authenticated server identity. |
| **Remote SDK Adapter** | Authorize inbound requests, enforce anti-scraping rate limits, and delegate user resolution to the host backend. |
| **QUIC Transport** | Secure hop-by-hop packet protection (RFC 9001 §5.3 AEAD) and connection migration between server endpoints. |
| **E2EE Layer** | Protect message content end-to-end between user client applications with forward secrecy and post-compromise security. |
| **Group Media** | **Preview Status:** SFrame media packetization and MLS group ratchets remain in preview until full multi-party interoperability testing is certified. |

### 22.2 Stateless Compliance & Lifecycle Verification Test Suites
The automated Stateless Compliance and Multi-Domain Lifecycle Verification Suites verify the architectural contract:
1. `test_compliance_zero_sdk_disk_persistence`: Confirms zero disk files, directories, or SQLite databases created during routing, encryption, and decryption.
2. `test_compliance_restart_has_zero_retained_user_history`: Verifies that restarting the SDK restores zero cached users, receipts, or message history.
3. `test_compliance_profile_queries_respect_backend_authorization_and_privacy`: Validates mutual contact visibility, redaction of bio and presence for non-contacts, and complete invisibility for blocked requesters.
4. `test_compliance_profile_query_rate_limiting_prevents_scraping`: Verifies rejection of queries exceeding 20 requests per 10s window.
5. `test_compliance_offline_delivery_never_reports_queued_without_confirmation`: Confirms `UserServerUnavailable` when no durable queue exists, and `RecipientOfflineQueued { queue_receipt }` only upon affirmative backend queue confirmation.
6. `test_compliance_logging_and_checkpoints_never_expose_plaintext_or_private_keys`: Verifies absence of plaintext and private keys from audit logs and externally anchored checkpoints.
7. `test_compliance_federation_works_across_independent_domains_without_central_directory`: Verifies end-to-end decentralized discovery, profile query, and E2EE message delivery across three autonomous domains.
8. `test_end_to_end_three_server_lifecycle_failure_and_recovery`: Exercises full lifecycle across three independent domains under network disconnection, server crash/restart, duplicate suppression, chain-of-custody key rotation, and intentional log tampering detection.

**Total Automated Test Suite Status:** 53 passing tests across unit and integration suites (100% pass rate, zero compiler warnings).





