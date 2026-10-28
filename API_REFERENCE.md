# UCall SDS — Complete REST & RPC API Reference

**Document Version:** 1.0 (Production API Specification)  
**Host Backend Base URL:** `http://localhost:4025` (configurable via `API_URL`)  
**SDS Federation Gateway:** `udp://<server_domain>:4433` (QUIC RFC 9000 / RFC 9221)  
**Authentication:** Bearer JWT Token (`Authorization: Bearer <token>`) or Server-to-Server Ed25519 signature  
**File Location:** `/Users/malleravindra/Projucts/PingDart Chat/UcallSDS/API_REFERENCE.md`  

---

## Table of Contents
1. [Domain & DNS Verification APIs](#1-domain--dns-verification-apis)
2. [SDS Domain ID & Registry APIs](#2-sds-domain-id--registry-apis)
3. [Federation Mesh & Server Health APIs](#3-federation-mesh--server-health-apis)
4. [Identity & E2EE Prekey APIs](#4-identity--e2ee-prekey-apis)
5. [Message Routing & Delivery Status APIs](#5-message-routing--delivery-status-apis)
6. [Real-Time Call Signaling APIs](#6-real-time-call-signaling-apis)
7. [0-RTT Replay & Security APIs](#7-0-rtt-replay--security-apis)
8. [Cryptographic Audit & Checkpoint APIs](#8-cryptographic-audit--checkpoint-apis)

---

## 1. Domain & DNS Verification APIs

These endpoints verify whether a domain has published the required DNS SRV and TXT records, validate its Ed25519 root authority signature, and report its federation readiness.

### 1.1 Verify Domain DNS & Federation Readiness
Verifies a domain's live DNS records, checks authority public keys, and tests web port reachability.

* **Endpoint:** `GET /api/v1/sds/dns/verify`
* **Query Parameters:**
  * `domain` (required, string): The fully qualified domain name (e.g., `chat.pingdart.com`).

#### Request Example:
```bash
curl -X GET "http://localhost:4025/api/v1/sds/dns/verify?domain=pingdart.com" \
     -H "Authorization: Bearer <admin_token>"
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "canonical_domain": "pingdart.com",
  "is_ready_for_federation": true,
  "sds_txt_verified": true,
  "authority_key_matched": true,
  "detected_sds_id": "5QJCXPH2HN",
  "dns_records": {
    "srv": {
      "target": "quic.pingdart.com",
      "port": 4433,
      "priority": 10,
      "weight": 10,
      "status": "VALID"
    },
    "txt": {
      "record": "v=sds1; id=5QJCXPH2HN; k=ed25519:7a8f62c...3c; proto=quic",
      "status": "VALID"
    },
    "a_records": ["13.140.151.16"],
    "aaaa_records": ["2a02:c207:2335:7104::1"]
  },
  "connectivity": {
    "https_port_443": "REACHABLE",
    "http_port_80": "REACHABLE",
    "quic_udp_port_4433": "OPEN"
  },
  "issues": []
}
```

#### Verification Failure Response (`200 OK` with Issues):
```json
{
  "success": false,
  "canonical_domain": "unverified-domain.org",
  "is_ready_for_federation": false,
  "sds_txt_verified": false,
  "authority_key_matched": false,
  "detected_sds_id": null,
  "issues": [
    "Missing DNS SRV record: _sds._udp.unverified-domain.org",
    "Missing TXT record containing 'v=sds1'",
    "HTTPS connectivity check failed on port 443"
  ]
}
```

---

### 1.2 Get Recommended DNS Setup Guide
Returns copy-pasteable DNS records to configure on domain registrars (Cloudflare, Route53, Namecheap, GoDaddy).

* **Endpoint:** `GET /api/v1/sds/dns/setup-guide`
* **Query Parameters:**
  * `domain` (required, string): Domain name (e.g., `alpha.ucall.net`).

#### Success Response (`200 OK`):
```json
{
  "canonical_domain": "alpha.ucall.net",
  "sds_id": "ALPHA11223",
  "quic_port": 4433,
  "recommended_records": [
    {
      "record_type": "SRV",
      "name": "_sds._udp.alpha.ucall.net",
      "value": "10 10 4433 quic.alpha.ucall.net.",
      "ttl": 3600,
      "description": "Advertises the SDS QUIC/UDP service endpoint and port to federated servers"
    },
    {
      "record_type": "TXT",
      "name": "alpha.ucall.net",
      "value": "v=sds1; id=ALPHA11223; k=ed25519:4a8b...7f; proto=quic",
      "ttl": 3600,
      "description": "Binds domain identity to Ed25519 authority public key and SDS ID"
    }
  ]
}
```

---

## 2. SDS Domain ID & Registry APIs

### 2.1 Encode Domain to Compact 10-Character ID
Normalizes a domain, computes its deterministic 10-char Crockford Base32 ID with polynomial checksum, and registers it locally.

* **Endpoint:** `POST /api/v1/sds/domain/encode`
* **Request Body:**
```json
{
  "domain": "pingdart.com",
  "authority_pubkey": "7a8f...3c"
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "normalized_domain": "pingdart.com",
  "sds_domain_id": "5QJCXPH2HN",
  "checksum": "HN",
  "checksum_status": "VALID",
  "tier": 1,
  "length": 10
}
```

---

### 2.2 Decode & Validate 10-Character Code
Validates polynomial checksum (detecting single-character typos) and resolves the domain via local offline registry / DNS.

* **Endpoint:** `GET /api/v1/sds/domain/decode/:id`

#### Request Example:
```bash
curl -X GET "http://localhost:4025/api/v1/sds/domain/decode/5QJCXPH2HN"
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "sds_domain_id": "5QJCXPH2HN",
  "checksum_status": "PASSED",
  "resolved_domain": "pingdart.com",
  "registration_status": "ACTIVE",
  "registered_at": "2026-10-28T06:30:15Z"
}
```

#### Typo Detection Response (`400 Bad Request`):
```json
{
  "success": false,
  "sds_domain_id": "5QJCXPH2XX",
  "checksum_status": "FAILED",
  "error": "Checksum Mismatch: Typo detected in code '5QJCXPH2XX'"
}
```

---

### 2.3 List Registered Sovereign Domains
Returns all registered domains with their authority keys, endpoints, and statuses.

* **Endpoint:** `GET /api/v1/sds/domains`

#### Success Response (`200 OK`):
```json
{
  "total": 2,
  "domains": [
    {
      "domain": "pingdart.com",
      "sds_id": "5QJCXPH2HN",
      "status": "ACTIVE",
      "endpoint": "13.140.151.16:4433",
      "authority_pubkey": "7a8f...3c",
      "key_epoch": 1,
      "created_at": "2026-10-28T06:30:15Z"
    },
    {
      "domain": "alpha.ucall.net",
      "sds_id": "ALPHA11223",
      "status": "ACTIVE",
      "endpoint": "192.0.2.1:4433",
      "authority_pubkey": "3f9c...1a",
      "key_epoch": 1,
      "created_at": "2026-10-28T07:15:00Z"
    }
  ]
}
```

---

## 3. Federation Mesh & Server Health APIs

### 3.1 Local Server Federation Status
Reports this server's identity, active QUIC connection pools, and real-time transport metrics.

* **Endpoint:** `GET /api/v1/sds/federation/status`

#### Success Response (`200 OK`):
```json
{
  "server_domain": "alpha.ucall.net",
  "server_sds_id": "ALPHA11223",
  "authority_pubkey": "7a8f...3c",
  "quic_port": 4433,
  "uptime_seconds": 86400,
  "transport_metrics": {
    "active_quic_sessions": 10,
    "total_packets_sent": 142050,
    "total_packets_received": 139820,
    "bytes_sent": 18450120,
    "bytes_received": 17290450,
    "dropped_deadline_packets": 12,
    "migration_events": 4,
    "average_rtt_ms": 28
  }
}
```

---

### 3.2 List Federated Peer Nodes
Returns all connected and known remote peer servers in the mesh.

* **Endpoint:** `GET /api/v1/sds/federation/peers`

#### Success Response (`200 OK`):
```json
{
  "total_peers": 10,
  "peers": [
    {
      "domain": "beta.ucall.net",
      "sds_id": "BETA223344",
      "endpoint_addr": "198.51.100.2:4433",
      "is_connected": true,
      "key_epoch": 1,
      "authority_pubkey": "a1b2...c3",
      "last_seen_ms": 1700000500000,
      "rtt_ms": 32
    },
    {
      "domain": "gamma.ucall.net",
      "sds_id": "GAMMA33445",
      "endpoint_addr": "198.51.100.3:4433",
      "is_connected": true,
      "key_epoch": 1,
      "authority_pubkey": "d4e5...f6",
      "last_seen_ms": 1700000495000,
      "rtt_ms": 45
    }
  ]
}
```

---

## 4. Identity & E2EE Prekey APIs

### 4.1 Fetch User Prekey Bundle (For Starting E2EE Chat)
Returns a recipient's signed X25519 prekey bundle, certified by their Ed25519 identity key.

* **Endpoint:** `GET /api/v1/sds/users/:userId/prekey`
* **Query Parameters:**
  * `domain` (optional, string): If querying a federated remote server user.

#### Success Response (`200 OK`):
```json
{
  "user_id": "david",
  "domain": "beta.ucall.net",
  "prekey_bundle": {
    "identity_pubkey_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "dh_identity_pubkey_hex": "1122334455667788990011223344556677889900112233445566778899001122",
    "signed_prekey_hex": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    "signed_prekey_signature_hex": "445566...8899",
    "signature_verified": true
  }
}
```

---

### 4.2 Publish / Rotate User Signed Prekey
Clients periodically publish fresh signed prekeys to guarantee forward secrecy.

* **Endpoint:** `POST /api/v1/sds/users/prekey`
* **Request Body:**
```json
{
  "user_id": "alice",
  "identity_pubkey_hex": "0102...1f20",
  "dh_identity_pubkey_hex": "1122...1122",
  "signed_prekey_hex": "aabb...8899",
  "signed_prekey_signature_hex": "4455...8899"
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "message": "Signed prekey bundle accepted and verified",
  "published_at": "2026-10-28T08:00:00Z"
}
```

---

## 5. Message Routing & Delivery Status APIs

### 5.1 Route Encrypted Message Envelope
Routes an encrypted message envelope using the destination-first algorithm (Fast Local Delivery vs. Remote Federated Transport).

* **Endpoint:** `POST /api/v1/sds/messages/route`
* **Request Body:**
```json
{
  "message_id": "msg-uuid-987654",
  "sender_address": "alice@alpha.ucall.net",
  "recipient_address": "david@beta.ucall.net",
  "envelope": {
    "sender_sds_id": "alice",
    "recipient_sds_id": "david",
    "ephemeral_dh_pubkey_hex": "7788...9900",
    "nonce_hex": "123456789012345678901234",
    "ciphertext_hex": "4a7b9c...f0e1",
    "sequence_number": 1,
    "timestamp_ms": 1700000100000
  }
}
```

#### Success Response — Direct Local Delivery (`200 OK`):
```json
{
  "success": true,
  "message_id": "msg-uuid-987654",
  "delivery_status": "DeliveredLocalUser",
  "user_id": "david",
  "delivered_at_ms": 1700000100050
}
```

#### Success Response — Dispatched to Remote Peer Server (`200 OK`):
```json
{
  "success": true,
  "message_id": "msg-uuid-987654",
  "delivery_status": "DispatchedToRemotePeer",
  "remote_domain": "beta.ucall.net",
  "remote_endpoint": "198.51.100.2:4433",
  "remote_ack": {
    "message_id": "msg-uuid-987654",
    "recipient_sds_id": "david",
    "ack_timestamp_ms": 1700000100120,
    "remote_server_domain": "beta.ucall.net"
  }
}
```

#### Recipient Offline / Queued Response (`200 OK`):
```json
{
  "success": true,
  "message_id": "msg-uuid-987654",
  "delivery_status": "QueuedLocalOffline",
  "queue_receipt": "pg_wal_00000001000000000000002A"
}
```

---

### 5.2 Query Message Delivery Status
* **Endpoint:** `GET /api/v1/sds/messages/:messageId/status`

#### Success Response (`200 OK`):
```json
{
  "message_id": "msg-uuid-987654",
  "status": "DELIVERED",
  "receipt_timestamp_ms": 1700000100120,
  "delivered_to_domain": "beta.ucall.net"
}
```

---

## 6. Real-Time Call Signaling APIs

### 6.1 Initiate Call Invitation
Sends a reliable call invitation frame (`TYPE_CALL_INVITE = 0x0050`) to a local or remote user.

* **Endpoint:** `POST /api/v1/sds/calls/invite`
* **Request Body:**
```json
{
  "call_id": "call-session-8888",
  "caller": "alice@alpha.ucall.net",
  "callee": "frank@gamma.ucall.net",
  "call_type": "video",
  "e2ee_call_params": "base64_encoded_sframe_keys_and_media_capabilities",
  "quic_connection_id": "0x9988776655443322"
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "call_id": "call-session-8888",
  "call_state": "RINGING",
  "session_cid": "0x9988776655443322",
  "quic_datagram_port": 4433
}
```

---

### 6.2 Call Acceptance & Media Coordination
* **Endpoint:** `POST /api/v1/sds/calls/:callId/answer`
* **Request Body:**
```json
{
  "callee_answer": "ACCEPTED",
  "e2ee_response_params": "base64_callee_public_media_key"
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "call_id": "call-session-8888",
  "call_state": "ACTIVE",
  "playout_lifetime_limit_ms": 150
}
```

---

## 7. 0-RTT Replay & Security APIs

### 7.1 Issue 0-RTT Session Ticket
Generates a server-bounded, HMAC-signed session ticket for zero round-trip connection resumption.

* **Endpoint:** `POST /api/v1/sds/security/ticket`
* **Request Body:**
```json
{
  "client_identity": "alice@alpha.ucall.net",
  "validity_seconds": 300
}
```

#### Success Response (`200 OK`):
```json
{
  "ticket_id": "srv-ticket-777",
  "expires_at_epoch_ms": 1700000400000,
  "max_lifetime_ms": 300000,
  "hmac_signature": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### 7.2 Check & Consume Ticket (Cross-Process Atomic Redemption)
Validates single-use tickets, rejecting replays across multiple server processes.

* **Endpoint:** `POST /api/v1/sds/security/verify-ticket`
* **Request Body:**
```json
{
  "ticket_id": "srv-ticket-777",
  "idempotency_key": "idemp-uuid-112233",
  "ticket_expiry_epoch_ms": 1700000400000
}
```

#### Success Response (`200 OK`):
```json
{
  "valid": true,
  "status": "TICKET_CONSUMED"
}
```

#### Replay Rejection (`409 Conflict`):
```json
{
  "valid": false,
  "error_code": "0x0006",
  "error": "ERR_REPLAY_DETECTED: Ticket or idempotency token already redeemed"
}
```

---

## 8. Cryptographic Audit & Checkpoint APIs

### 8.1 Fetch Cryptographic Audit Log Chain
Returns tamper-evident audit records linked by SHA-256 parent hash pointers.

* **Endpoint:** `GET /api/v1/sds/audit/chain`
* **Query Parameters:**
  * `limit` (optional, integer, default: 50): Number of entries to retrieve.

#### Success Response (`200 OK`):
```json
{
  "total_records": 1024,
  "chain_valid": true,
  "entries": [
    {
      "sequence_number": 1024,
      "event_type": "DomainRegistered",
      "timestamp_ms": 1700000200000,
      "payload": "Registered domain pingdart.com (5QJCXPH2HN)",
      "previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "entry_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    }
  ]
}
```

---

### 8.2 Get Latest Signed Audit Checkpoint
Returns the root Merkle hash of the audit log signed by the server's Ed25519 authority key for external anchoring.

* **Endpoint:** `GET /api/v1/sds/audit/checkpoint/latest`

#### Success Response (`200 OK`):
```json
{
  "checkpoint_sequence": 10,
  "up_to_sequence_number": 1024,
  "root_chain_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "timestamp_ms": 1700000200000,
  "authority_pubkey_hex": "7a8f...3c",
  "signature_hex": "1b2c...3d",
  "signature_valid": true
}
```

---

## 9. Error Code Reference Table

| Hex Code | Protocol Error Name | Description |
|:---:|---|---|
| `0x0000` | `ERR_OK` | Request succeeded without error. |
| `0x0001` | `ERR_MALFORMED_FRAME` | Frame header or payload fails binary wire format specification. |
| `0x0002` | `ERR_UNSUPPORTED_VERSION` | Protocol version mismatch (expected `0x01`). |
| `0x0003` | `ERR_ID_CHECKSUM_INVALID` | 10-char Crockford Base32 polynomial checksum error (typo detected). |
| `0x0004` | `ERR_DOMAIN_NOT_REGISTERED` | Target domain is not registered in the SDS mesh. |
| `0x0005` | `ERR_IDENTITY_SIGNATURE_FAILED` | Ed25519 identity verification failure (tampering / spoofing). |
| `0x0006` | `ERR_REPLAY_DETECTED` | Replayed 0-RTT session ticket, duplicate token, or expired timestamp. |
| `0x0007` | `ERR_0RTT_OPERATION_FORBIDDEN` | State-mutating operation attempted in 0-RTT early data. |
| `0x0008` | `ERR_DEADLINE_EXPIRED` | Packet exceeded playout lifetime budget (150ms); dropped by receiver. |
| `0x0009` | `ERR_DIRECT_PATH_UNAVAILABLE` | Direct QUIC path unreachable; fallback to relay requested. |
| `0x000A` | `ERR_RELAY_AUTH_FAILED` | Turn / Relay server authentication failed. |
| `0x000B` | `ERR_RATE_LIMITED` | Anti-scraping rate limit triggered (exceeded 20 reqs / 10s). |
| `0x000C` | `ERR_CALL_BUSY` | Callee is already in an active call session. |
| `0x000D` | `ERR_CALL_DECLINED` | Callee declined incoming call invitation. |
