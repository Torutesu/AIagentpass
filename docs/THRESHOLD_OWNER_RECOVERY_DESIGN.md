# Threshold Owner Recovery — production design

Status: implementation contract, 2026-08-14. This document defines the authority invariants for the Phase 2 recovery slice. A partial implementation must fail closed and must not be advertised as account recovery.

## Security objective

Recovery may restore one existing member's access to one organization after credential loss. It must never let one lost owner, one support operator, one stolen upstream identity, or one database replay silently gain organization authority.

The minimum threshold is two distinct, active owners other than the recovery subject. Every approval requires a fresh, operation-bound WebAuthn authorization. Support personnel may observe status and resend secret-free notifications, but cannot approve, shorten the delay, issue a recovery session, enroll a credential, or activate authority.

Organizations that do not have the required independent owners are not recoverable through this flow. The product must show that limitation before credential loss and direct the organization to add recovery owners; it must not silently fall back to support override.

## State machine

`pending -> approved -> delayed -> session_issued -> credential_enrolled -> activated`

Terminal states are `cancelled`, `expired`, and `failed`. No terminal state can return to a live state, and no state transition accepts an older resource version.

1. `pending`: the subject creates a versioned request through an authenticated upstream-identity session. Creation records no reusable plaintext material.
2. `approved`: two distinct eligible owners have each consumed a fresh `human.recovery.approve` authorization. The subject cannot approve their own request.
3. `delayed`: the approval threshold starts a fixed server-side delay. A new approval cannot shorten it. Any owner cancellation terminates the request.
4. `session_issued`: after the delay, one hashed one-time exchange value is atomically consumed to create a restricted recovery session. The raw value is returned once and is never logged, stored in browser storage, or included in notification payloads.
5. `credential_enrolled`: the restricted session may call only recovery status, recovery registration options/verify, and recovery activation endpoints. Credential insertion is serialized under the member credential lock.
6. `activated`: the newly enrolled credential must complete `human.recovery.activate` WebAuthn recent-auth. Activation consumes that proof, invalidates the restricted session and all prior normal sessions, advances the membership session epoch, records an audit event, and commits the notification outbox entry in one transaction.

## Durable records

The PostgreSQL model contains:

- `owner_recovery_requests`: organization, subject member, state, threshold, delay boundary, expiry, monotonic version, creator identity, and terminal reason;
- `owner_recovery_approvals`: one row per request/owner, the consumed authorization digest or challenge identifier, approval time, and owner membership epoch snapshot;
- `owner_recovery_exchanges`: SHA-256 digest of one random 32-byte value, issued/expiry/consumed times, and exact request binding;
- `owner_recovery_sessions`: SHA-256 bearer digest, request/member/organization binding, allowed-stage state, absolute/idle expiry, and revocation fields;
- `owner_recovery_outbox`: secret-free event type, organization/request/member identifiers, delivery state, bounded attempts, and no email address, token, credential, challenge, cookie, or assertion material.

Raw exchange values, raw session tokens, WebAuthn challenges, assertions, attestation objects, private keys, and notification destinations are prohibited from these tables.

### Outbox delivery contract

Recovery notifications use at-least-once delivery. Workers atomically claim rows with `FOR UPDATE SKIP LOCKED`; PostgreSQL stores only the SHA-256 digest of a random process-local claim token and a bounded lease expiry. Publish acknowledgement and failure transitions compare the organization, event, attempt, and claim digest, so a stale worker cannot acknowledge another worker's lease.

The public `event_id` is the provider idempotency key. A provider response can be lost after acceptance, so the same event may be sent again after lease expiry. Providers must persistently deduplicate that key and return the exact contract `{accepted:true,duplicate:boolean}` for accepted or duplicate delivery, or `{accepted:false,duplicate:false}` only when delivery is definitively rejected. Timeout, transport failure, malformed response, and PostgreSQL acknowledgement failure are unknown outcomes: the worker retains the claim lease and does not make the row immediately retryable. Attempts use bounded exponential backoff with jitter only after explicit rejection. Attempt 100 remains reclaimable after process loss and transitions to `dead_letter` only after an explicit delivery failure; successful delivery can still publish it. Stored diagnostics are stable error codes only—provider messages, response bodies, credentials, destination data, and webhook configuration are never persisted.

Claimed events in one batch are delivered concurrently so the configured publish timeout cannot serially exhaust later events' leases. Runtime shutdown first stops scheduling, tracks manual and scheduled cycles, waits a bounded time for active deliveries, then closes notification listeners and PostgreSQL. Concurrent drain callers share one result. A worker that cannot drain keeps storage open and makes shutdown fail closed. Operators observe only aggregate pending/dead-letter counts and age plus label-free claim, publish, retry, dead-letter, claim-loss, uncertain-outcome, failure, and lag counters. Readiness fails closed when the worker is unavailable, a dead letter exists, or the hard backlog/lag threshold is exceeded.

Dead-letter management is tenant-scoped and never edits the immutable event identity. Migration 0030 binds each event to the recovery request's exact subject, tracks a monotonic management version, at most three redrives, cumulative delivery attempts, and a terminal suppression state. Migration 0031 adds an optional 32-byte recent-authorization context to the WebAuthn challenge and human session while preserving legacy operation-only authorizations. Redrive and suppression require a current owner/admin session and consumed recent WebAuthn bound to the canonical SHA-256 context `{version, organization_id, event_id, action, expected_management_version}`. The HTTP boundary and PostgreSQL repository independently validate that context; the repository revalidates the current session, role, authority epochs, consumed proof, and context inside the same organization-locked transaction before idempotency claim, CAS mutation, audit append, and commit. The Human API exposes tenant-scoped list, redrive, and suppress routes with exact Origin, CSRF (including GET), bounded pagination, rate limiting, optimistic concurrency, stable secret-free errors, and an OpenAPI contract.

Migration 0032 fixes terminal delivery retention in the database rather than in
worker configuration: published rows remain for at least 30 days, dead letters
for 90 days, and suppressions for 365 days. A prune transaction locks at most
1,000 eligible rows with `SKIP LOCKED`, copies their immutable identity,
terminal status, timestamps, bounded counters, and stable error category into
an append-only secret-free retention ledger, and only then deletes the bulky
outbox rows. The ledger rejects update and delete; it contains no destination,
provider body, claim token, credential material, or free-form suppression
reason. Runtime maintenance runs through the delivery worker's bounded drain
lifecycle and a pruning failure cannot block authority transactions or widen
authority.

## Transaction and lock order

Every mutation uses the same order:

1. organization advisory lock;
2. recovery request row `FOR UPDATE`;
3. subject and approving membership rows in UUID order;
4. human/recovery session rows;
5. member credential advisory lock;
6. audit head and outbox rows.

Eligibility is re-evaluated under these locks. An approval is invalid if its owner is no longer active, is no longer an owner, or its membership epoch changed. Threshold completion, one-time exchange consumption, credential enrollment, and activation use compare-and-set predicates and return exactly one row.

## HTTP surface

All responses are `Cache-Control: no-store`, use closed JSON schemas, reject unknown fields, and expose stable secret-free errors.

- `POST /api/auth/organizations/{organization_id}/recovery-requests`
- `GET /api/auth/organizations/{organization_id}/recovery-requests/{request_id}`
- `POST /api/auth/organizations/{organization_id}/recovery-requests/{request_id}/approve`
- `POST /api/auth/organizations/{organization_id}/recovery-requests/{request_id}/cancel`
- `POST /api/auth/recovery/exchange`
- `POST /api/auth/recovery/webauthn/registration/options`
- `POST /api/auth/recovery/webauthn/registration/verify`
- `POST /api/auth/recovery/activate`

Approval requires `agentpass-recent-auth` bound to `human.recovery.approve`. Activation requires a proof created by the newly enrolled credential and bound to `human.recovery.activate`.

## Required negative evidence

- subject self-approval, duplicate owner approval, support approval, and non-owner approval are denied;
- approval replay, exchange replay, recovery-session replay, stale version, wrong operation, wrong session, wrong member, and wrong organization are denied;
- owner downgrade/revocation or epoch change between approval and threshold completion invalidates that approval;
- two API replicas racing approval, exchange, enrollment, activation, cancellation, and expiry produce one authoritative result;
- verifier timeout, process loss after commit, response loss, notification outage, and audit failure never widen authority;
- browser storage, telemetry, logs, error causes, URLs, and notification records contain no reusable recovery or WebAuthn material;
- one support operator and one lost owner cannot complete recovery, including by collusion.

## Operational requirements

Metrics are counts and latency only: request creation, approval denial reason, threshold reached, delay elapsed, exchange denial, activation success/failure, expiry, cancellation, and outbox lag. Labels must not contain organization, member, request, credential, challenge, session, IP, email, or token values.

Alerts cover repeated denied approvals, abnormal creation volume, stale delayed requests, exchange replay, activation replay, outbox lag, and audit-chain failure. Recovery remains unavailable when PostgreSQL, recent-auth verification, audit append, or required notification durability is unavailable.
