# Managed-signer provider-operation uncertainty adjudication

Status: deployment-internal contract v1, implemented in
`apps/cloud-api/src/managed-signer-provider-operation-adjudication.mjs`.

This document defines the operator boundary for an uncertain managed-signer
provider operation. It does not define a Human HTTP endpoint, a Console route,
or a new database mutation. It is a frozen DTO contract for trusted server
components and a reviewable handoff between maintenance, provider adapters,
and the producer of the signing ledger.

## Why this is deployment-internal

`managed_signer_provider_operations` is intentionally deployment-wide. Its
identity is `(purpose, operation_id)` plus the immutable signing binding, and
the table has no `organization_id`, tenant foreign key, agent identity, or
producer correlation. An operation ID is therefore not proof of organization
ownership.

The contract always emits:

```json
{
  "organization_correlation": "unavailable",
  "human_exposure": "forbidden"
}
```

The normalizers reject organization and tenant selectors. No Human API or
Console route may list, detail, verify, or mutate these records until an
authoritative producer ledger supplies an exact, transactionally verified
organization correlation. A future BFF must not infer a tenant from purpose,
key ID, operation ID, receipt ID, process, IP address, or the current human
session.

## Frozen DTO boundary

An uncertainty summary contains only bounded public metadata:

```json
{
  "version": 1,
  "purpose": "agentpass.capability",
  "operation_id": "op-adjudication-001",
  "algorithm": "ed25519",
  "bytes_length": 128,
  "request_digest": "sha256-hex-64-bytes",
  "key_id": "managed-key-2026",
  "key_version": "7",
  "state": "uncertain",
  "uncertain_reason": "provider_response_lost",
  "provider_result": "present",
  "organization_correlation": "unavailable",
  "human_exposure": "forbidden"
}
```

`provider_result` is only `present` or `absent`; it never carries the
signature, public-key bytes, receipt, or provider response. A list is capped at
100 summaries and carries only an opaque bounded cursor. The detail DTO is
derived by the server from a summary and its configured capabilities; callers
cannot add actions to it.

The normalizer rejects, among other fields:

- signing bytes or arbitrary byte buffers;
- signatures, public keys, receipts, claim tokens, or provider diagnostics;
- organization/tenant IDs and selectors;
- generic retry, confirm, reject, or caller-selected terminal state;
- unknown fields, unbounded strings, unsupported uncertainty reasons, and
  output/state combinations that contradict the ledger invariants.

Errors are fixed code/message pairs and never preserve the original driver,
provider, or input error as `cause`.

## Allowed adjudication actions

The contract has exactly three action classes:

| Action | Preconditions | Effect permitted by this contract |
| --- | --- | --- |
| `exact_sql_reconciliation` | The uncertain row has a persisted provider result. | Invoke the existing deployment-wide, bounded SQL correlation. The high-level signing ledger must already be `committed` and match request digest, key binding, signature, and provider receipt exactly. No provider call or bytes are accepted. |
| `provider_bound_verification` | A server-side provider adapter has explicitly registered a lookup/verification capability for this exact signer purpose. The contract's allowlist defaults to empty and is a closed list of registered purposes. | The adapter verifies the exact purpose/key/version/request binding against the provider. Any output is obtained and persisted inside that adapter; it is never supplied by the operator contract. A capability for one purpose cannot authorize lookup for another purpose. |
| `producer_specific_terminal_handoff` | The producer is the registered `managed_signer_key_lifecycle` producer. | Hand the unresolved operation back to that producer's own state machine. The command carries no `rejected`, `failed`, or other terminal state, so an operator cannot invent a terminal outcome. |

The command is fenced by the target `(purpose, operation_id)` and an exact
uncertain snapshot: algorithm, byte length, request digest, key ID, key
version, uncertainty reason, and whether a provider result is present. This is
an optimistic stale-state check, not a permission to interpolate those values
into SQL. The existing maintenance repository remains the only implementation
of deployment-wide SQL selection and uses its total bounded budget and
`SKIP LOCKED` rules.

There is intentionally no `retry_sign` action. An ambiguous provider call may
have succeeded. Re-running signing without provider-bound verification can
create a second provider attempt and cannot prove which result is authoritative.

## Result rules

Results contain only the action, target, fixed outcome, and resulting state.

- SQL reconciliation can be `reconciled`, `no_match`, `stale`, or
  `unavailable`.
- Provider verification can be `verified`, `no_match`, `stale`, `unsupported`,
  or `unavailable`.
- Producer handoff can be `handed_off`, `stale`, or `unavailable`.
- Only `reconciled` and `verified` may report `after_state: "committed"`.
- A handoff is never a terminal result; it reports `after_state: "uncertain"`.

The result never asserts provider acceptance merely because a provider request
was attempted. A `verified` result is valid only after the provider-bound
server path has checked the exact binding and persisted the result through the
existing repository invariants.

## Required operational handling

1. The maintenance worker may continue automatic quarantine, exact SQL
   reconciliation, and correlated retention. It must not call a provider or
   manufacture output.
2. A deployment operator may inspect only aggregate health or this redacted
   internal summary through a protected operator channel. There is no tenant
   authorization path for this contract.
3. Provider verification is enabled only when a provider adapter exposes an
   exact lookup/verification capability and the deployment supplies an
   explicit allowlist of exact registered purposes. The adapter must pin each
   purpose's key ID, key version, and provider identity; allowing one purpose
   never enables another. A generic `sign` method is not a verification
   capability. Key versions are bounded to PostgreSQL's signed bigint range
   (`1..9223372036854775807`).
4. If no exact verification is available, use producer handoff or leave the
   row uncertain. Do not turn `lifecycle_fenced`, `recovery_exhausted`, or any
   other closed reason into success.
5. Log and metrics may contain fixed action/outcome classes and aggregate
   counts only. They must not include organization IDs, signing bytes,
   signatures, receipts, provider diagnostics, claim tokens, or raw driver
   errors.
6. Retention remains governed by the existing correlated terminal-pair rule;
   an uncertain row is not prunable merely because it is old.

## What must exist before Human/Console exposure

A future producer ledger must record an immutable, exact organization
correlation in the same authority boundary as the operation binding. Before
that exists, a Human/tenant route would either leak deployment-wide state or
guess ownership. The correct behavior is absence of the route, not a filtered
route with an inferred organization.

The focused contract tests cover this boundary, including rejection of tenant
selectors, provider output and diagnostics, generic retry/terminal actions,
unsupported verification, false terminal result combinations, bounded pages,
and fixed opaque errors.
