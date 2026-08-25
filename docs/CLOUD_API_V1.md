# AgentPass Cloud API v1

All endpoints are under `/v1`, accept and return JSON, reject unknown request fields, and enforce a 1 MiB request limit unless a smaller endpoint limit applies. Every response includes `request_id`; errors use `{ "error": { "code", "message" }, "request_id" }` and never echo credentials.

## Authentication

- Human endpoints use a hashed bearer API token only in the initial self-hosted compatibility runtime. Roles are `owner`, `admin`, `auditor`, and `viewer`. High-risk operations require `AgentPass-Recent-Auth` to identify a server-side WebAuthn challenge that was verified for the exact member, organization, and operation and atomically consumed; freshness alone is insufficient and replay fails. The endpoint fails closed with `503` when that verifier is not configured. Hosted production must use durable human sessions and the browser WebAuthn ceremony, never the bootstrap bearer token.
- Hosted SIWC session bootstrap is `POST /auth/session` in the Human contract and maps to the runtime path `/api/auth/session`. The Console BFF sends an exact empty JSON object plus one `agentpass-console-identity` header containing a compact Ed25519 assertion. Cloud pins the assertion `kid`, verifies the exact canonical header/payload, issuer, audience, provider, origin, UUID `org`, and `iat`/`nbf`/`exp` window (maximum 60 seconds), then atomically consumes `SHA-256(iss || U+0000 || aud || U+0000 || jti)` in the dedicated PostgreSQL replay ledger before resolving the active membership. The SIWC contract has no redirect URI and never accepts `Authorization`, caller identity headers, member/role claims, or browser-supplied identity fields.
- Device enrollment uses a one-time 256-bit credential plus a P-256/Ed25519 possession signature over `AgentPass-Enrollment-Proof-v1`, `POST`, the exact path, request-body SHA-256, and credential SHA-256. Only the credential digest is stored. Exact retries are idempotent; expiry, cross-tenant binding changes, key substitution, and consumed-request substitution fail closed.
- Device endpoints use headers `AgentPass-Device`, `AgentPass-Timestamp`, `AgentPass-Nonce`, `AgentPass-Content-SHA256`, and `AgentPass-Signature`. Ed25519 or P-256/SHA-256 (64-byte IEEE P1363) binds the uppercase method, normalized path and query, body digest, timestamp, and nonce. P-256 is the macOS Secure Enclave profile; the enrolled device record pins the exact public key and therefore the algorithm. ControlBundle and Capability signing remains a separate Ed25519 trust root.
- Mutating human requests require `Idempotency-Key`. Device audit events are intrinsically idempotent by `(device_id, event_id)`.
- The Web Console bridge requires an authenticated SIWC user on every read and mutation. Same-origin checks are an additional CSRF control, not authentication.
- The bridge connects to the Cloud API only over HTTPS. Plain HTTP is accepted solely for loopback development when explicitly enabled.
- Hosted transport admission is shared across replicas. Authenticated UUID scopes consume tenant/principal PostgreSQL buckets; unauthenticated or malformed scopes consume fixed purpose-separated HMAC UUID buckets and can never create attacker-selected rows. PostgreSQL unavailability denies the request instead of falling back to a process-local allowance.

## Resources and minimum roles

| Endpoint | Method | Minimum role / principal | Purpose |
| --- | --- | --- | --- |
| `/organizations` | POST | bootstrap | create an organization and owner |
| `/organizations/:org` | GET | viewer | organization summary |
| `/organizations/:org/members` | GET/POST | admin | list or add members |
| `/organizations/:org/devices` | GET/POST | viewer/admin | list or administratively register devices |
| `/organizations/:org/device-enrollments` | POST | admin + recent WebAuthn | issue a one-time enrollment |
| `/enrollments/:id` | POST | enrollment credential + key possession | activate the reserved device |
| `/organizations/:org/devices/:id` | PATCH | admin | label, disable, or rotate public key |
| `/organizations/:org/agents` | GET/POST | viewer/admin | list or register agents |
| `/organizations/:org/agents/:id/revoke` | POST | admin | immediate agent revocation |
| `/organizations/:org/policies` | GET/POST | viewer/admin | list or publish versioned policies |
| `/organizations/:org/capabilities` | POST | admin | issue a short-lived signed capability |
| `/organizations/:org/bundles/:device` | GET | device | fetch signed effective policy/revocations |
| `/organizations/:org/audit/events` | POST | device | append device audit events |
| `/organizations/:org/audit/events` | GET | auditor | query redacted activity |
| `/organizations/:org/emergency-stop` | POST | owner + recent WebAuthn | publish organization-wide revocation |

## Tenant and concurrency rules

Resource IDs are globally opaque but every lookup also requires the organization ID; cross-tenant existence is never disclosed. Updates carry an integer `version`, and stale `If-Match` values return `version_conflict`. Mutations are serialized per organization. Deletion is represented as a tombstone where auditability is required.

Token-bucket functions lock the selected row before sampling wall-clock time and never move `updated_at` backward. Expired shared-control and signed-identity replay records are deleted with bounded `FOR UPDATE SKIP LOCKED` batches. A dedicated maintenance worker uses one total deletion budget, never overlaps its own cycles, contains database/metric-sink failures, and is drained before PostgreSQL shutdown.

## Bundle behavior

Each device receives one canonical ControlBundle v2 (`format_epoch: 2`) signed with Ed25519 and an increasing organization/device sequence. Unchanged effective state returns the same signed bundle across requests and server restarts; policy or revocation changes advance the durable sequence. The bundle contains the active policy scope, revoked agents/devices/capabilities, global stop state, issuance and expiry, offline TTL, and signing-key ID. A device pins the public key and rejects wrong audience, rollback, same-sequence different content, future, expired, or overlong bundles. The effective permission is always:

```text
local policy ∩ local agent scope ∩ cloud policy ∩ short-lived capability
```

No cloud response can widen local permission.

## Audit ingestion

Devices upload redacted protocol-v1 events in order. `event_hash` is SHA-256 over canonical JSON of the normalized event with only `event_hash` removed; `previous_hash` remains in the preimage. The server recomputes this hash before any write or head advance, then validates IDs, tenant/device binding, and previous-hash continuity. Exact retries are accepted as duplicates; conflicting reuse of an event ID is rejected. A missing predecessor records a visible gap and never rewrites earlier events.
