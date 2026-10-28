# SDS Domain Encoding & Decoding System
## Product Requirements Document (PRD) — Phase 1

**Product:** SDS (Server-to-Server Communication Protocol)  
**Module:** Domain ID Generator and Offline Decoder  
**Version:** 1.0  
**Phase:** 1 — Domain Encoding and Decoding  
**Status:** Proposed  
**Primary objective:** Create a unique 10-character identifier for each registered domain and allow SDS clients to decode that identifier locally without an internet connection.

---

## 1. Executive Summary

SDS will introduce a custom Domain ID Algorithm to assign a compact, unique identifier to a registered internet domain.

Examples of supported domains:

- `ewrewrewrewr.com`
- `meddylist.com`
- `meddylistravi.com`
- `meddylistravi.in`
- `sds.example.co.in`

The system must support domains with different lengths, subdomains, and suffixes such as `.com`, `.in`, `.co.in`, and other valid domain extensions.

Each registered domain receives a unique 10-character ID.

Example:

| Property | Example |
|---|---|
| Original domain | `ewrewrewrewr.com` |
| Domain ID | `7K9M2P4X8B` |
| ID length | 10 characters |
| Character set | `A–Z`, `0–9` |
| Decoding | Offline, using a local mapping |
| Collision handling | Mandatory |
| Domain recovery | Exact original registered domain |

The example ID above is illustrative and must not be treated as a registered identifier until generated and stored by the implementation.

## 2. Problem Statement

Traditional server discovery often requires a domain name, DNS resolution, or a central directory lookup.

SDS needs a compact identifier that can be entered, copied, shared, and resolved into a domain by an SDS client.

The system must solve these problems:

1. Domain names can have different lengths.
2. Domains may have different top-level and multi-level suffixes.
3. The identifier must always contain exactly 10 characters.
4. Two different registered domains must never receive the same active ID.
5. The client must be able to decode known IDs without internet access.
6. Domain IDs must remain stable when a domain's server IP changes.
7. The system must distinguish an unknown ID from an invalid ID.

## 3. Goals

### 3.1 Functional goals

- Accept a valid domain name.
- Normalize and validate the domain.
- Generate a unique 10-character Domain ID.
- Store the ID-to-domain relationship.
- Decode the ID to recover the exact registered domain.
- Support offline decoding using a locally available mapping database.
- Import and export the mapping database.
- Prevent duplicate registrations and accidental overwrites.
- Provide an API and a simple developer interface.

### 3.2 Non-goals for Phase 1

The following features are outside the initial scope:

- Full SDS messaging and calling.
- Automatic server discovery across the internet.
- DNS replacement.
- Automatic IP-address discovery and failover.
- Cryptographic identity verification.
- Guaranteed decoding of IDs never downloaded or otherwise provisioned to the client.
- A globally synchronized, decentralized registry.

These can be addressed in later phases.

## 4. Technical Constraint

A 10-character identifier using 36 possible characters per position has:

`36^10 = 3,656,158,440,062,976` possible combinations.

However, this does not mean an arbitrary domain can be converted into 10 characters and recovered perfectly from the ID alone.

Domain names can contain substantially more information than a 10-character ID can represent.

Therefore, Phase 1 will use a **unique identifier plus a reversible local mapping**:

`Domain → Unique 10-character ID → Local mapping → Original domain`

This approach is practical, collision-safe when properly enforced, and compatible with offline decoding.

If SDS later requires an ID to be decoded on a completely fresh device without downloading or receiving any mapping, a different format with sufficient encoded information or a restricted domain namespace will be required.

## 5. Identifier Specification

### 5.1 Character set

The default character set is Base36:

`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`

Rules:

- Exactly 10 characters.
- Uppercase letters and digits only.
- No spaces.
- No punctuation.
- No lowercase characters in the ID.
- Case-insensitive domain input may be normalized before registration.

Domain IDs are not passwords and must not be treated as authentication credentials.

### 5.2 Example

Input:

`ewrewrewrewr.com`

Illustrative registration result:

`7K9M2P4X8B`

Stored mapping:

`7K9M2P4X8B → ewrewrewrewr.com`

When the client enters `7K9M2P4X8B`, it searches its local database and returns `ewrewrewrewr.com`.

## 6. Domain Normalization and Validation

Before registration, the system must normalize the domain consistently.

Required steps:

1. Remove accidental leading and trailing whitespace.
2. Convert internationalized domain names to a consistent ASCII representation using IDNA.
3. Convert DNS hostnames to lowercase.
4. Remove a trailing DNS root dot if present.
5. Validate the domain according to the selected hostname policy.
6. Reject malformed names and unsupported input.
7. Preserve the normalized domain as the canonical value.

Examples:

| Input | Normalized domain |
|---|---|
| `MEDDYLIST.COM` | `meddylist.com` |
| `MeddyList.com ` | `meddylist.com` |
| `ewrewrewrewr.com` | `ewrewrewrewr.com` |
| `sds.example.co.in` | `sds.example.co.in` |

Domain normalization must not incorrectly remove meaningful subdomains.

A DNS lookup or proof of domain ownership is not inherently required to calculate an ID, but it should be required before activating a domain in a production SDS registry.

## 7. Domain ID Generation Algorithm

### 7.1 Recommended approach

Use a cryptographically secure random generator to produce a candidate 10-character Base36 ID, then check whether it already exists in the registry.

Algorithm:

1. Receive a normalized domain.
2. Check whether the domain is already registered.
3. If it is registered, return its existing ID.
4. Otherwise, generate a random 10-character Base36 candidate.
5. Check the unique ID constraint in the database.
6. If the ID exists, generate another candidate.
7. Insert the new mapping in a transaction.
8. Return the assigned ID.

The database must enforce unique constraints on both the canonical domain and the Domain ID.

This is a random allocation algorithm, not a reversible mathematical transformation. Reversibility is provided by the mapping database.

### 7.2 Pseudocode

```text
function registerDomain(inputDomain):
    domain = normalizeAndValidate(inputDomain)

    existing = findByCanonicalDomain(domain)

    if existing exists:
        return existing.domainId

    repeat:
        candidate = generateRandomBase36(length = 10)

        try:
            saveMappingAtomically(
                domainId = candidate,
                canonicalDomain = domain
            )
            return candidate

        if uniqueIdConflict:
            continue
```

The actual implementation must handle concurrent registrations and database transaction conflicts safely.

## 8. Offline Decoding Algorithm

### 8.1 Required behavior

The SDS client must decode previously synchronized or provisioned Domain IDs without making a network request.

Process:

1. Accept an ID from the user.
2. Convert it to uppercase.
3. Validate its length and character set.
4. Search the local mapping database.
5. Return the stored canonical domain if found.
6. Display an offline-not-found result if the mapping does not exist locally.

### 8.2 Pseudocode

```text
function decodeDomainId(inputId):
    domainId = uppercase(trim(inputId))

    if length(domainId) != 10:
        return INVALID_ID

    if domainId contains characters outside A-Z and 0-9:
        return INVALID_ID

    domain = localDatabase.findByDomainId(domainId)

    if domain exists:
        return domain.canonicalDomain

    return NOT_AVAILABLE_OFFLINE
```

### 8.3 Offline guarantee

A mapping previously installed, imported, or synchronized to the client must remain available offline.

The application must not silently fall back to an internet lookup during offline decoding.

Decoding a domain does not guarantee that the destination server is online or reachable.

## 9. Local Mapping Database

### 9.1 Suggested schema

**Table:** `sds_domain_registry`

| Field | Type | Description |
|---|---|---|
| `domain_id` | CHAR(10) | Unique 10-character identifier |
| `canonical_domain` | VARCHAR(253) | Normalized domain |
| `created_at` | TIMESTAMP | Registration timestamp |
| `updated_at` | TIMESTAMP | Last metadata update |
| `status` | ENUM | Active, suspended, revoked |
| `registry_version` | BIGINT | Mapping version |
| `verification_status` | ENUM | Pending, verified, rejected |

Constraints:

- Primary key or unique index on `domain_id`.
- Unique index on `canonical_domain`.
- Transaction-safe registration.
- No silent reassignment of a previously used ID.

A production implementation should also maintain an audit log for registrations, suspensions, revocations, and ownership changes.

## 10. Registration and Decoding APIs

The initial service may expose the following endpoints.

### 10.1 Register a domain

`POST /v1/domains/register`

Request:

```json
{
  "domain": "ewrewrewrewr.com"
}
```

Example response:

```json
{
  "success": true,
  "domain_id": "7K9M2P4X8B",
  "domain": "ewrewrewrewr.com",
  "status": "pending_verification"
}
```

The example ID is illustrative.

Registration must be protected by appropriate authentication and domain-ownership verification.

### 10.2 Decode an ID online

`GET /v1/domains/{domain_id}`

Example response:

```json
{
  "success": true,
  "domain_id": "7K9M2P4X8B",
  "domain": "ewrewrewrewr.com",
  "status": "active"
}
```

### 10.3 Decode an ID offline

The client must use a local database or imported mapping file. This operation must not require an API call.

### 10.4 Export local mappings

Provide an authenticated export function that generates a versioned mapping file.

Example:

```json
{
  "format": "sds-domain-map",
  "version": 1,
  "domains": [
    {
      "domain_id": "7K9M2P4X8B",
      "domain": "ewrewrewrewr.com"
    }
  ]
}
```

For production use, mapping files should be authenticated or digitally signed so that untrusted files cannot silently redirect users to attacker-controlled domains.

## 11. Domain Verification and Security

The system must not assume that a person owns a domain merely because they enter its name.

Before activation, use an ownership verification process such as a DNS TXT record or a controlled HTTPS challenge.

Security requirements:

- Authenticate registration requests.
- Verify domain ownership before activation.
- Prevent users from replacing another domain's mapping.
- Protect registry administration.
- Audit all changes.
- Sign exported registry snapshots.
- Support suspension and revocation.
- Never treat a Domain ID as proof of identity.
- Verify server identity separately before sending sensitive SDS messages.

A decoded domain should be displayed as data, not automatically trusted or opened without appropriate safeguards.

## 12. Domain and Server IP Changes

The Domain ID represents the registered domain, not the current IP address.

Example:

| Property | Before | After |
|---|---|---|
| Domain | `ewrewrewrewr.com` | `ewrewrewrewr.com` |
| Domain ID | Same ID | Same ID |
| Server IP | Old IP | New IP |
| Domain mapping | Unchanged | Unchanged |

If the server IP changes while the domain stays the same, the Domain ID does not need to change.

The SDS client can resolve the domain to its current endpoint when online. Offline decoding can display the domain, but it cannot discover a new IP address without updated information.

## 13. User Interface Requirements

Create a simple developer interface with two primary panels.

### Panel A — Encode Domain

Inputs:

- Domain name.

Actions:

- Validate domain.
- Register domain.
- Generate or retrieve the assigned ID.
- Copy Domain ID.
- Export mapping.

Output:

- Canonical domain.
- 10-character Domain ID.
- Verification status.

### Panel B — Decode Domain ID

Inputs:

- 10-character Domain ID.

Actions:

- Decode locally.
- Copy decoded domain.

Output states:

- **Found offline:** Display the exact stored domain.
- **Invalid ID:** Explain the required format.
- **Not found offline:** Explain that the mapping must be imported or synchronized.
- **Revoked mapping:** Display the status and do not treat it as trusted.

The offline decoder must clearly indicate whether the result came from a local mapping or a live registry.

## 14. Testing Requirements

The implementation must pass these tests:

1. Register a valid domain and return a 10-character ID.
2. Register the same domain again and return the same ID.
3. Reject invalid domains.
4. Reject malformed IDs.
5. Detect ID collisions and generate a replacement.
6. Preserve exact domain mappings after application restart.
7. Export and import mapping files correctly.
8. Decode an imported ID while disconnected from the internet.
9. Return an offline-not-found result for unknown IDs.
10. Preserve the ID when the server IP changes.
11. Handle concurrent registrations without duplicate IDs.
12. Reject tampered or invalid signed mapping files when signature verification is enabled.
13. Ensure different registered domains never share the same active ID.
14. Ensure suspended or revoked mappings are not presented as active.

## 15. Acceptance Criteria

Phase 1 is complete when:

- Every active registered domain has a unique 10-character ID.
- Duplicate registrations return the original ID.
- All valid local mappings decode correctly without internet.
- Unknown mappings produce a clear offline result.
- Domain registration and mapping updates are transaction-safe.
- Exported mappings can be imported into a clean SDS client.
- Changing the server IP does not change the Domain ID.
- Automated tests pass for validation, collisions, offline behavior, and persistence.

## 16. Recommended Technology Stack

The first implementation can use:

- **Backend:** Python with FastAPI or Node.js.
- **Registry database:** PostgreSQL or MySQL.
- **Offline client database:** SQLite.
- **ID generation:** Cryptographically secure random Base36 generation.
- **Mapping exchange:** Versioned JSON files, with digital signatures for production use.
- **Domain verification:** DNS TXT records or HTTPS challenges.

The encoding and decoding logic should be independent of the backend so that the same client-side decoder can run on desktop, mobile, or other SDS-compatible platforms.

## 17. Phase 1 Deliverables

1. SDS Domain ID specification.
2. Domain normalization and validation module.
3. 10-character unique ID generator.
4. Domain registry schema and migration.
5. Registration and lookup APIs.
6. Offline decoding library.
7. Local SQLite mapping store.
8. Mapping export and import.
9. Developer UI for encoding and decoding.
10. Automated unit, integration, collision, and offline tests.
11. API documentation.
12. Security and domain-verification documentation.

## 18. Future Phases

**Phase 2 — SDS Server Identity**
- Stable server identity independent of IP address.
- Server public-key identity.
- Server endpoint and port metadata.

**Phase 3 — Distributed Discovery**
- Discover servers without manually entering IP addresses.
- Replicated registry or distributed discovery.
- Signed endpoint updates and caching.

**Phase 4 — Messaging Identity**
- Combine the Domain ID with a user ID.
- Define the full SDS Messaging ID format.
- Resolve a recipient's server and user identity.

**Phase 5 — Secure Communication**
- Server authentication.
- Secure message transport.
- Replay protection, key rotation, and protocol versioning.

## 19. Final Design Decision

Phase 1 will use a **10-character unique Domain ID backed by a local mapping database**.

This is the recommended starting point because it supports arbitrary valid domain lengths, collision checks, offline decoding, and stable identifiers without attempting an impossible lossless compression of every possible domain into a fixed 10-character value.

The offline decoder can work without internet as long as the necessary mapping is already stored or imported locally. A brand-new client cannot decode an arbitrary ID that it has never received a mapping for.
