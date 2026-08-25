# AgentPass contracts

This directory is the machine-readable boundary between Web Console, Human API, Device API, PostgreSQL, Node clients, and the native Swift endpoint.

- `openapi/` fixes HTTP paths, principals, request/response shapes, and error framing.
- `schemas/` fixes signed or cross-process JSON formats. Unknown fields are rejected.
- `postgres/` fixes tenant-qualified persistence constraints and migration order.
- `fixtures/` contains deterministic positive and negative values consumed by Node and Swift tests.

The G4 refresh lane has two exact, signed envelopes:

- `refresh-hint-v1` is an expiring notification containing only the organization/device scope, monotonic authority generation, canonical timestamps, nonce, signer key ID, and Ed25519 signature. It carries no authority, policy, capability, or secret material.
- `bundle-ack-v1` binds the device key epoch, ControlBundle format epoch, sequence, lowercase statement hash, result, and canonical observation/signature fields. `reason_code` is required for `blocked` and prohibited for `applied`; its values are the stable bundle/device failure vocabulary in the schema.

Both envelopes reject unknown fields, use canonical UTC millisecond timestamps, and use unpadded base64url for their fixed-size nonce and signature values. The refresh hint validator also enforces `expires_at > published_at` and a maximum five-minute hint lifetime.

Implementation status (2026-08-13): the Cloud runtime implements the target bundle-fetch envelope, refresh long-poll, and ACK ingestion with local PostgreSQL qualification. The Swift native endpoint implements the durable refresh machine, authenticated poll/fetch/ACK transport, atomic bundle activation, and the single live ControlBundle v2 daemon runner with redacted status and manual-refresh joining. G4.2 remains in progress until real XPC, subprocess kill/restart, installed launchd, unified-log redaction, and physical Secure Enclave qualification pass. This distinction is also machine-readable in `openapi/device-v1.json`.

## Device audit upload and ingest (current status: 2026-08-20)

The native Device-audit delivery slice is implemented at
the native audit slice commits on `codex/agent-platform`. Its source-level contract
references are:

| Boundary | Authority | Status |
| --- | --- | --- |
| Native event, batch, and ingestion response | `native/macos/Sources/AgentPassNativeCore/NativeDeviceAuditUploadContracts.swift` | Implemented; closed canonical JSON and event-hash validation. |
| Durable local queue and bounded resend | `native/macos/Sources/AgentPassNativeCore/NativeDeviceAuditOutbox.swift` and `native/macos/Sources/AgentPassNativeServiceSupport/NativeDeviceAuditUploadCoordinator.swift` | Implemented; exact bytes remain pending across transport/response failure, with at most eight attempts per flush call. |
| Device API | `openapi/device-v1.json`, `POST /organizations/{organization_id}/audit/events`, `appendDeviceAuditEvents` | Route and device-signature boundary exist. The POST currently advertises a generic JSON response; standalone upload/ingestion schemas are still a contract-freeze task. |
| Audit listing | `schemas/device-audit-list-v1.schema.json` and `GET /organizations/{organization_id}/audit/events` | Implemented read/list schema with tenant/device-bound keyset cursor. It is not the upload request schema. |
| PostgreSQL event/head/gap state | `postgres/0001_control_plane.sql`, `postgres/0011_control_plane_hosted_cutover.sql`, `postgres/0010_device_audit_activity_keyset.sql` | Implemented tenant-qualified event persistence, per-device head, gap record, trigger/index support, and list ordering. |
| Contract catalog | `catalog-v1.json` entries `api.device.appendDeviceAuditEvents` and `api.device.listDeviceAuditEvents` | Cataloged; native upload DTOs are not yet represented by standalone JSON Schema entries. |

The Cloud path is synchronous request-transaction ingestion into
`device_audit_events`; it is not yet a separate durable `device_audit_inbox`
plus asynchronous worker. PostgreSQL serializes a device head, exact retries
become `duplicates`, and predecessor mismatches become durable `gap` evidence.
See [`docs/NEXT_IMPLEMENTATION_PLAN.md`](../docs/NEXT_IMPLEMENTATION_PLAN.md)
for the resend, head, and failure-recovery procedure and for the explicit
local-versus-external verification boundary.

The focused native and Node test files are the local verification basis in the
checkout. They are not a claim of deployed Cloud, real PostgreSQL role/RLS,
multi-instance, crash/response-loss, launchd, signed-artifact, or physical
hardware qualification. Contract completion requires adding the upload and
ingestion request/response schemas, deterministic fixtures, and catalog links;
code consumers must then validate those shared artifacts.

Contract changes are additive within v1 unless a new path or format epoch is introduced. A change is incomplete until OpenAPI, JSON Schema, PostgreSQL constraints, Node validation, Swift fixtures, and negative tests agree.

Run:

```sh
npm run contracts:validate
```

The validator intentionally uses no network and resolves only repository-local references.
