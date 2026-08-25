# ADR-003: Contract authority, ownership, and versioning

Status: accepted

## Decision

AgentPass treats every public, signed, cross-process, or durable structure as a versioned security contract. A machine-readable catalog under `contracts/` is the authoritative inventory. A structure is not part of the production protocol until the catalog names its owner, trust direction, tenant and actor bindings, compatibility policy, implementation references, and evidence.

Authority ownership is split into three non-interchangeable classes:

- **Human authority** authenticates organization members and authorizes management intent. It may create, narrow, revoke, or approve bounded Cloud state, but it never signs Git payloads and never receives device private material.
- **Cloud authority** commits organization policy, capabilities, revocations, grants, refresh metadata, audit projections, and release evidence. Every tenant-scoped lookup is bound to `organization_id`; every signed purpose has a dedicated domain and key role.
- **Device authority** proves possession of a non-exportable key, evaluates the current local intersection, signs device ACK/audit evidence, and performs the final Git signature. Device evidence cannot create Cloud authority, and a wake notification cannot widen local authority.

An implementation may consume multiple authority classes, but one contract cannot silently change owner or purpose. Cross-purpose key reuse and generic “sign arbitrary bytes” interfaces are prohibited.

## Versioning rules

1. Unknown fields, unknown kinds, unknown versions, and ambiguous aliases fail closed at every untrusted boundary.
2. Additive changes are allowed only when the current version already defines the field as optional and every strict decoder has a fixture for both forms. Otherwise a new schema version or format epoch is required.
3. Signed preimages are domain-separated and canonical. Changing field order, normalization, purpose, algorithm, audience, or key role requires a new signed-contract version.
4. PostgreSQL migrations are forward-only and immutable. Released migration bytes and checksums never change; a newer application must add a migration.
5. OpenAPI paths, XPC selectors, and durable native formats are integration locks. Their inventory or fingerprint must change intentionally with compatibility tests.
6. A tenant-scoped contract must carry or derive one exact organization binding. An actor-authorized mutation must additionally bind the human member/session or device identity and a single operation purpose.
7. Retryable mutations require an idempotency identity bound to the same tenant, actor, operation, and canonical request. Conflicting reuse fails closed.
8. Short-lived authority and authorization evidence carry explicit issuance and expiry bounds. Notification-only metadata is never treated as authority.

## Compatibility evidence

Each catalog entry identifies the evidence needed for its boundary. Depending on the contract this includes JSON Schema fixtures, OpenAPI route tests, Node/Swift canonical vectors, XPC selector/DTO inventories, PostgreSQL checksum history, browser BFF decoding tests, and release-verifier fixtures.

Passing a producer-only test is insufficient. A contract change is complete only when every listed producer, consumer, persistent representation, and negative compatibility case agrees.

## Consequences

- Contract drift becomes a build failure instead of a deployment discovery.
- Organization, actor, and signing-purpose ambiguity is rejected before repository or signer access.
- Cloud, browser, CLI, and native work can proceed in parallel after the catalog and integration-lock fingerprints are frozen.
- The catalog is metadata, not authority. It must never contain private keys, credentials, bearer tokens, WebAuthn assertions, raw device challenges, or repository content.
