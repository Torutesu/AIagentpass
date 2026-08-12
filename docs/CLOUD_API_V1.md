# AgentPass Cloud API v1

All endpoints are under `/v1`, accept and return JSON, reject unknown request fields, and enforce a 1 MiB request limit unless a smaller endpoint limit applies. Every response includes `request_id`; errors use `{ "error": { "code", "message" }, "request_id" }` and never echo credentials.

## Authentication

- Human endpoints use a hashed bearer API token in the initial self-hosted release. Roles are `owner`, `admin`, `auditor`, and `viewer`. Issuing a device enrollment additionally requires a bounded `AgentPass-Recent-Auth` assertion accepted by the configured recent-WebAuthn verifier; the endpoint fails closed with `503` when that verifier is not configured. Durable WebAuthn ceremonies and production identity-provider sessions remain separate work.
- Device enrollment uses a one-time 256-bit credential plus a P-256/Ed25519 possession signature over `AgentPass-Enrollment-Proof-v1`, `POST`, the exact path, request-body SHA-256, and credential SHA-256. Only the credential digest is stored. Exact retries are idempotent; expiry, cross-tenant binding changes, key substitution, and consumed-request substitution fail closed.
- Device endpoints use headers `AgentPass-Device`, `AgentPass-Timestamp`, `AgentPass-Nonce`, `AgentPass-Content-SHA256`, and `AgentPass-Signature`. Ed25519 or P-256/SHA-256 (64-byte IEEE P1363) binds the uppercase method, normalized path and query, body digest, timestamp, and nonce. P-256 is the macOS Secure Enclave profile; the enrolled device record pins the exact public key and therefore the algorithm. ControlBundle and Capability signing remains a separate Ed25519 trust root.
- Mutating human requests require `Idempotency-Key`. Device audit events are intrinsically idempotent by `(device_id, event_id)`.
- The Web Console bridge requires an authenticated SIWC user on every read and mutation. Same-origin checks are an additional CSRF control, not authentication.
- The bridge connects to the Cloud API only over HTTPS. Plain HTTP is accepted solely for loopback development when explicitly enabled.

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
| `/organizations/:org/emergency-stop` | POST | owner | publish organization-wide revocation |

## Tenant and concurrency rules

Resource IDs are globally opaque but every lookup also requires the organization ID; cross-tenant existence is never disclosed. Updates carry an integer `version`, and stale `If-Match` values return `version_conflict`. Mutations are serialized per organization. Deletion is represented as a tombstone where auditability is required.

## Bundle behavior

Each device receives one canonical ControlBundle v2 (`format_epoch: 2`) signed with Ed25519 and an increasing organization/device sequence. Unchanged effective state returns the same signed bundle across requests and server restarts; policy or revocation changes advance the durable sequence. The bundle contains the active policy scope, revoked agents/devices/capabilities, global stop state, issuance and expiry, offline TTL, and signing-key ID. A device pins the public key and rejects wrong audience, rollback, same-sequence different content, future, expired, or overlong bundles. The effective permission is always:

```text
local policy ∩ local agent scope ∩ cloud policy ∩ short-lived capability
```

No cloud response can widen local permission.

## Audit ingestion

Devices upload redacted protocol-v1 events in order. `event_hash` is SHA-256 over canonical JSON of the normalized event with only `event_hash` removed; `previous_hash` remains in the preimage. The server recomputes this hash before any write or head advance, then validates IDs, tenant/device binding, and previous-hash continuity. Exact retries are accepted as duplicates; conflicting reuse of an event ID is rejected. A missing predecessor records a visible gap and never rewrites earlier events.
