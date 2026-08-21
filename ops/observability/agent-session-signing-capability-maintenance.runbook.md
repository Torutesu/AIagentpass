# Agent Session signing-capability expiry maintenance

This runbook covers the deployment-wide, bounded expiry-recovery worker for
Agent Session signing capabilities. It is an operational procedure only. It
does not grant authority, expose a tenant route, or authorize direct SQL
updates.

## Closed observability contract

The checked-in policy at
`ops/observability/agent-session-signing-capability-maintenance-alerts.v1.json`
is the source of truth. Its three alert names, metric names, aggregation
functions, thresholds, and evaluation windows are closed. Use the dedicated
validator before installing or changing the policy:

```text
node scripts/agent-session-signing-capability/validate-alerts.mjs \
  "$PWD/ops/observability/agent-session-signing-capability-maintenance-alerts.v1.json"
```

The policy has no labels. Metric samples and incident notes must contain only
deployment-wide counters, bounded deltas, timestamps at the approved reporting
precision, readiness state classes, and a final outcome. Never add an
organization, device, agent, session, request, reservation, key, provider,
database, URL, credential, or error-detail label.

The worker runs an initial bounded cycle and then uses a 60-second interval in
the hosted PostgreSQL runtime. Each cycle supplies a bounded batch limit and
exports only these fixed aggregate counters:

| Signal | Meaning | Normal action |
| --- | --- | --- |
| `agent_session_signing_capability_maintenance_cycle_total` | Cycle started | Compare deltas with the success counter. |
| `agent_session_signing_capability_maintenance_success_total` | Cycle returned a valid aggregate result | This is the staleness source. |
| `agent_session_signing_capability_maintenance_failure_total` | Cycle failed or returned an invalid aggregate result | Investigate the bounded maintenance path. |
| `agent_session_signing_capability_maintenance_expired_total` | Reservations moved to the expired terminal state | Treat as an aggregate workload count. |
| `agent_session_signing_capability_maintenance_uncertain_total` | Expired reservations fenced into the outcome-unknown state | Preserve uncertainty; never infer signing success. |

The `expired_total` counter is informational in this policy. A high value is
not by itself an outage. The `uncertain_total` counter is an escalation signal
because an outcome-unknown reservation requires the existing adjudication and
provider-verification process; it must not be silently retried or marked
completed by an operator.

## Alert thresholds

All thresholds use counter deltas, not absolute process-local values. A
restart-safe exporter must calculate the increase over the fixed window and
must treat a counter reset as an unknown delta rather than fabricating zero.

| Alert | Warning | Critical | First response |
| --- | --- | --- | --- |
| `agent_session_signing_capability_maintenance_staleness` | Fewer than 2 successful cycles in 5 minutes | Fewer than 1 successful cycle in 15 minutes | Check readiness, migration/schema state, maintenance pool health, and whether the worker is running. |
| `agent_session_signing_capability_maintenance_failures` | At least 1 failure in 5 minutes | At least 3 failures in 15 minutes | Preserve the fail-closed readiness state; inspect only aggregate health and deployment evidence. |
| `agent_session_signing_capability_maintenance_uncertain_recovery` | At least 1 newly uncertain recovery in 5 minutes | At least 5 in 15 minutes | Freeze changes to signer/provider bindings and escalate to the signing-capability uncertainty owner. |

Staleness uses the success counter rather than a wall-clock label. With the
fixed 60-second cadence, fewer than two successes in five minutes is warning
and zero successes across fifteen minutes is critical. If the cadence is
changed, the policy must be reviewed and revalidated as one bounded change;
operators must not tune the alert ad hoc during an incident.

## Response procedure

1. Record the alert name, deployment identifier, policy digest, bounded metric
   deltas, readiness status/code, worker state, and incident timestamps. Do not
   copy raw logs, SQL, request bodies, connection strings, stack traces, or
   environment dumps into the incident record.
2. Verify that the application is not accepting a request path that depends on
   a missing maintenance worker. A readiness failure is a safe containment
   signal; do not bypass it by disabling the worker or adding a local fallback.
3. For a failure or staleness alert, verify migration completion, schema-head
   agreement, maintenance-role connectivity, pool saturation, and deployment
   health through approved aggregate probes. Escalate infrastructure faults;
   do not run direct updates against signing-capability reservations.
4. For an uncertain-recovery alert, preserve the `outcome_unknown` boundary.
   Do not infer whether a provider signed, do not replay a provider call to
   test it, and do not turn the row into a completed capability manually. Use
   the bounded, purpose-specific adjudication procedure after the exact
   provider binding and current authority state have been verified.
5. After recovery, confirm two consecutive successful aggregate cycles, zero
   new maintenance failures, and that no critical uncertainty condition is
   still increasing. Record only the aggregate result and policy digest.

## Stop conditions and privacy

Stop the drill or incident evidence capture if any artifact contains a secret,
credential, token, private key, bearer value, URL, database DSN, raw provider
response, organization/device/session/request/reservation identifier, or
stack trace. Quarantine it under the approved incident-retention process and
produce a new scrubbed artifact; never edit a retained artifact in place.

The maintenance worker is auxiliary. Availability may be reduced while a
failure is investigated, but authority must not be widened. Only the
migration-owned database function and the dedicated maintenance role may
perform expiry recovery, and only the application’s existing signing and
adjudication boundaries may determine the final capability state.
