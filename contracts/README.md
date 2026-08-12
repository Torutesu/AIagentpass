# AgentPass contracts

This directory is the machine-readable boundary between Web Console, Human API, Device API, PostgreSQL, Node clients, and the native Swift endpoint.

- `openapi/` fixes HTTP paths, principals, request/response shapes, and error framing.
- `schemas/` fixes signed or cross-process JSON formats. Unknown fields are rejected.
- `postgres/` fixes tenant-qualified persistence constraints and migration order.
- `fixtures/` contains deterministic positive and negative values consumed by Node and Swift tests.

Contract changes are additive within v1 unless a new path or format epoch is introduced. A change is incomplete until OpenAPI, JSON Schema, PostgreSQL constraints, Node validation, Swift fixtures, and negative tests agree.

Run:

```sh
npm run contracts:validate
```

The validator intentionally uses no network and resolves only repository-local references.
