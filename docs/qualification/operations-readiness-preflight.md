# Operations readiness preflight qualification

This is the qualification contract for the operational controls attached to an
`agentpass.operations-readiness-checklist` in staging or production. It is
separate from the rollback, PITR, revoke, alerting, and tenant-isolation
checks, and is retained in the same candidate-bound evidence packet.

## Fail-closed input contract

The checklist root and `operational_controls` must bind the exact same:

- candidate ID;
- source commit; and
- deployed artifact/image digest.

The operational record additionally requires a protected execution ID,
observed timestamp, evidence digest, protected execution/origin markers,
immutable audited retention, page-tested and acknowledged on-call routing,
distinct incident/on-call/revoke/rollback owners, verified revoke evidence,
independent review-only reviewer with a separate signing key, fail-closed
target-bound rollback, measured fail-closed kill-switch propagation, and a
future expiry within 30 days of completion.

Missing, duplicated, placeholder, fixture, local, mock, stale, expired, or
substituted values are rejected. The verifier never infers owners, storage,
artifact identity, or qualification status from a caller-provided boolean.

## Decision rule

`operational_controls` is mandatory. A legacy checklist without it is
invalid—not a `structure_verified` partial result. A checklist with complete
controls may return `structure_verified` with
`production_readiness_blocker: "independent_qualification_required"`; this is
still not production approval. The bundle-backed command must also verify the
independent signed operations qualification and the independent security
review before any production-ready result is possible.

The local contract does not prove that an object-lock store exists, a page was
answered by the named on-call, a revoke reached every live instance, a
rollback reached the intended deployment, a kill-switch propagated, or a
reviewer is actually independent. Those facts require protected external
execution and independently bound evidence, and remain `not_proven` until
that evidence is collected.
