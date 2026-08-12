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

Contract changes are additive within v1 unless a new path or format epoch is introduced. A change is incomplete until OpenAPI, JSON Schema, PostgreSQL constraints, Node validation, Swift fixtures, and negative tests agree.

Run:

```sh
npm run contracts:validate
```

The validator intentionally uses no network and resolves only repository-local references.
