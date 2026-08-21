# Incident, emergency stop, and revoke

This is the short operational packet for the existing detailed
[`INCIDENT_AND_REVOKE_RUNBOOK.md`](../INCIDENT_AND_REVOKE_RUNBOOK.md). Use the
detailed runbook for API-specific authorization and recovery operations.

## Declare and contain

Declare an incident for suspected key/credential exposure, wrong tenant or
role authorization, purpose/key substitution, unexpected promotion generation,
provider response loss, database integrity failure, release secret-scan
failure, package/notarization mismatch, or a revoke bound that is not met.

1. Assign incident commander, security owner, deployment owner, and
   communications owner. Start a UTC timeline.
2. Capture only redacted source/artifact/deployment digests, request/operation
   IDs, stable reason codes, readiness, and audit state. Do not capture secrets,
   raw claims, WebAuthn assertions, database URLs, or raw provider output.
3. Stop promotion, canary expansion, affected signer issuance, and authority-
   changing traffic. Preserve the last independently qualified artifact.
4. If scope is global or unknown, apply the emergency stop at the authoritative
   deployment/control boundary and verify its durable audit event. A `404` or
   `503` is failure, not degraded authorization.

## Revoke by narrowest proven scope

For local broker/agent state:

```sh
agentpass agent revoke AGENT_ID --confirm REVOKE
agentpass revoke
agentpass status
agentpass audit --verify
```

For native sessions:

```sh
agentpass native revoke-sessions
agentpass control status
agentpass audit --verify
```

For device, organization, or human-session state, use the authenticated
Console/API mutation with organization role, recent resource-bound WebAuthn,
CSRF, idempotency, and expected version. On response loss, read authoritative
state by resource/version before retrying. A stale version or `409` is not
permission to force the mutation.

For a managed signer/provider incident, stop the affected purpose and key
version, mark ambiguous operations `uncertain`, reconcile by exact provider
lookup and signature/public-key verification, then disable or rotate the key
through the protected provider boundary. Never blind-retry or re-sign an
operation whose provider boundary was crossed.

For a release incident, quarantine the candidate, compare all bindings, revoke
possibly exposed release credentials through the protected owner, and roll
back only to the previous immutable qualified digest after forward-only
database compatibility and rollback-owner approval are recorded. Never rebuild
the promoted candidate or restore a revoked private key.

## Containment and closure checklist

- [ ] Affected authority is disabled/revoked at the authoritative boundary.
- [ ] New operations are denied and cached/offline paths meet the measured
  revocation bound.
- [ ] No `reserved`/`uncertain` operation is silently retried or deleted.
- [ ] Audit, deployment state, ledger, and incident evidence are durable and
  verifiable.
- [ ] Readiness fails closed for missing, disabled, or stale purposes.
- [ ] Candidate/source/tree/run/job/artifact bindings remain exact.
- [ ] Monitoring shows no continuing unauthorized activity.
- [ ] Recovery qualification, bounded canary, security review, and rollback
  ownership are recorded before resuming traffic.

Required incident fields: incident ID, severity, commander, UTC start/end,
scope, source/tree and artifact digests, purpose/key version, operation IDs,
stable reason codes, revoke timestamp and measured bound, post-revoke result,
audit event ID, rollback target, evidence digests/retention, reviewer, and
closure approval.
