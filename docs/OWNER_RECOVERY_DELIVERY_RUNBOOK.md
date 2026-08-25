# Owner-recovery delivery operations

This runbook is the W1.6 operator procedure for the PostgreSQL-backed
owner-recovery notification path at schema version 36. It covers six drills:

1. provider outage;
2. worker restart or process loss;
3. shared limiter outage;
4. uncertain-delivery adjudication;
5. dead-letter redrive; and
6. retention/prune failure.

The runbook describes operational actions, not a new authority path. It does
not authorize SQL updates, manual deletion, a manual “mark delivered” action,
or a provider-binding change on an existing event.

## 1. Contract and authority boundary

The current production boundary is:

- PostgreSQL migrations 1–36 are applied with no pending or modified
  migration;
- the recovery worker claims only `pending` rows with an exact provider
  binding and a database-clock lease;
- a timeout, process loss, malformed response, or lost response is persisted
  as `uncertain`, not immediately retried;
- only an exact positive acceptance proof for the same binding and
  idempotency key may move `uncertain` to `published` automatically;
- `Owner` and `Admin` may list dead letters and uncertain deliveries; only
  their active, unexpired, non-revoked Human session may perform the four
  mutations below;
- every mutation requires a fresh, operation- and resource-bound WebAuthn
  authorization, CSRF and Origin checks, an `Idempotency-Key`, and
  `If-Match` with the current management version; and
- the mutation, operator audit event, and idempotency record commit in one
  organization-locked PostgreSQL transaction.

The four mutation operations are:

| State | Operation | Required decision | Terminal effect |
| --- | --- | --- | --- |
| `uncertain` | `human.recovery.outbox.retry_uncertain` | Retry is acceptable even if the provider accepted before the response was lost. | Returns the bound row to `pending`; the same public idempotency key is retained. |
| `uncertain` | `human.recovery.outbox.suppress_uncertain` | Do not send or retry this event. A reason is required. | Moves the row to terminal `suppressed`. |
| `dead_letter` | `human.recovery.outbox.redrive` | Retry the bounded dead-letter attempt. | Returns a bound row to `pending`; `redrive_count` is incremented and is capped at 3. |
| `dead_letter` | `human.recovery.outbox.suppress` | Permanently stop delivery. A reason is required. | Moves the row to terminal `suppressed`. |

`Auditor` and `Viewer` cannot perform these operations. The deployment
operator, database operator, and provider operator cannot impersonate an
Owner/Admin session; infrastructure access does not substitute for WebAuthn.
An Owner/Admin is still subject to organization, membership, session-epoch,
role, recent-auth, idempotency, and version checks.

### Authority-safety invariant

During every drill, preserve this invariant:

> No operator action may widen authority, fabricate provider acceptance,
> silently rebind an event, consume another organization’s authorization, or
> make a stale state update appear successful. Availability may be reduced;
> authority must not be widened.

The safe failure state is `uncertain`, `dead_letter`, `suppressed`, or a
bounded `503`. A `200` from an operational probe is not evidence that a
notification was accepted.

## 2. Fixed aggregate signals and alert semantics

Use only the authenticated, read-only operational endpoints and deployment
metrics exporter. The endpoints are `/health/ready` and `/health/metrics`;
both require the configured `AGENTPASS_OPERATIONAL_PROBE_SECRET` and return a
404 when the probe is not authorized. Do not put that secret in a shell
command, URL, log, trace, ticket, or evidence file.

The readiness response exposes these fixed, label-free outbox values:

`pending_count`, `uncertain_count`, `dead_letter_count`,
`oldest_pending_age_ms`, `oldest_uncertain_age_ms`, and `worker_state`.

The metrics response exposes fixed `counters` and an outbox-backed `gauges`
object. Gauge collection failure makes the metrics endpoint return `503`; it
must never silently substitute a healthy zero. The W1.6 alert contract uses
these names only:

| Operational condition | Fixed aggregate signal | Warning | Critical |
| --- | --- | --- | --- |
| Pending delivery backlog | `owner_recovery_outbox_pending_count`, `owner_recovery_outbox_oldest_pending_age_ms` | Age `>= 300,000 ms` or count `>= 10` in a 5-minute window. | Age `>= 900,000 ms` or count `>= 100` in a 5-minute window. |
| Unknown delivery result | `owner_recovery_outbox_uncertain_count`, `owner_recovery_outbox_oldest_uncertain_age_ms` | Count `>= 1` or age `>= 300,000 ms` in a 5-minute window. | Count `>= 10` or age `>= 1,800,000 ms` in a 5-minute window. |
| Dead letters | `owner_recovery_outbox_dead_letter_count` | Count `>= 1` in a 5-minute window. | Count `>= 10` in a 5-minute window. |
| Provider confirmation | `owner_recovery_outbox_confirmation_lookup_total`, `..._success_total`, `..._miss_total`, `..._failure_total` | Use the uncertain count/age thresholds; a confirmation failure is investigated as a provider or binding fault. | Use the uncertain critical threshold or a binding/key mismatch; do not retry notification content to test the provider. |
| Redrive | `owner_recovery_outbox_redrive_success_total`, `owner_recovery_outbox_redrive_failure_total` | Failure counter increase `>= 1` in 15 minutes; classify the API result before paging. | Increase `>= 5` in 15 minutes, or storage/audit unavailability during a requested mutation. A stale-version conflict alone is not an outage. |
| Limiter | `human_auth_rate_limit_denial_total`, `human_auth_rate_limit_unavailable_total`, `rate_limit_denial_total` | Denial increase `>= 20` or unavailable increase `>= 1` in 5 minutes. | Denial increase `>= 100` or unavailable increase `>= 3` in 5 minutes. |
| Recovery transition latency | `owner_recovery_state_latency_count` and `owner_recovery_state_latency_total_ms` | Delta mean `>= 1,000 ms` in 15 minutes. | Delta mean `>= 5,000 ms` in 15 minutes. |
| Worker state | `worker_state` and readiness `code` | `worker_state != running` for one fixed interval. | `worker_unavailable`, `database_unavailable`, `schema_version_mismatch`, or `migration_drift`. |
| Retention/prune | `owner_recovery_outbox_prune_total`, `owner_recovery_outbox_prune_failure_total` | Failure counter increase `>= 1` in 15 minutes. | Increase `>= 3` in 15 minutes, or a failure coincides with pool saturation, schema drift, or a database outage. |

The deployment uses one fixed metrics scrape interval that must not vary per
tenant or alert. The operator verifies it against the installed policy before
the drill; it is not added to the closed W1.6 evidence JSON. Counter alerts use
deltas over the stated window, never absolute values from a restarted process.
A process restart resets process-local counters; the database readiness counts
and the provider acceptance ledger remain the authoritative signals.

The fixed `owner_recovery_outbox_prune_failure_total` counter is emitted only
when the bounded retention call fails. Do not infer success from
`owner_recovery_outbox_prune_total == 0`: zero rows may simply have been
eligible. The checked-in alert policy at
`ops/observability/owner-recovery-alerts.v1.json` is the source of truth for
the exact fixed names and thresholds; the validator must reject invented
counters or tenant/member/event labels.

Readiness `503` is a fail-closed operational signal. It must not be “fixed” by
disabling the worker, skipping WebAuthn, changing the provider binding, or
adding a process-local limiter fallback.

## 3. Common prerequisites and evidence rules

Before each drill, the incident/drill lead verifies in the protected operator
systems:

- source commit, deployed image or package digest, and PostgreSQL schema
  version;
- the approved staging environment, fixed scrape interval, and drill scenario;
- pre-drill aggregate snapshot: readiness status/code, outbox counts/ages,
  worker state, pool saturation, and relevant counter values;
- the approved change or incident authorization; and
- that an Owner/Admin approver is available for any mutation, without copying
  their identity, session cookie, WebAuthn assertion, credential ID, or
  recent-auth proof into drill evidence.

The operator must have read-only health access and deployment observation
access. Only the Owner/Admin has the authority to execute an outbox mutation.
The database operator may inspect aggregate state and transaction health but
must not update `owner_recovery_outbox` directly.

During execution, observe only:

- fixed scenario names and timestamps rounded to the agreed reporting
  precision;
- state classes (`pending`, `published`, `uncertain`, `dead_letter`, or
  `suppressed`);
- bounded counts, ages, counter deltas, response status classes, readiness
  codes, schema version, worker state, and final outcome;
- the public event digest already permitted by the separate W1.5 evidence
  contract; and
- the SHA-256 of the final scrubbed W1.6 evidence file.

Those live observations and provider/incident records are not fields in the
retained W1.6 report. The final report contains only the exact source/image/
policy bindings, timestamps/duration, six fixed scenario outcomes, and fixed
aggregate observations accepted by
`scripts/owner-recovery/verify-w16-drill-evidence.mjs`.

Redact or reject notification URLs, destination addresses, authorization
values, provider bodies, provider diagnostics, DSNs, cookies, CSRF values,
WebAuthn options/assertions, credential IDs, member/organization/request/event
identifiers, claim tokens, private keys, message content, raw headers,
environment dumps, argv, and stack traces. Never use a full HTTP response,
database dump, browser trace, screenshot, or application log as drill
evidence.

If a captured artifact contains forbidden material, stop the drill, quarantine
the artifact under the incident’s approved retention policy, do not upload or
email it, and notify the security owner through the approved channel. Produce
a new scrubbed artifact; do not edit a previously retained artifact in place.

## 4. Procedure A — provider outage or lost provider response

### Preconditions

- Confirm this is the notification/acceptance provider, not PostgreSQL or the
  Cloud API, using aggregate readiness and pool signals.
- Freeze provider binding, key, destination, and endpoint rotation for the
  duration of the incident.
- Confirm the configured acceptance lookup endpoint and notification endpoint
  belong to the same immutable binding. Do not print either URL in the report.

### Detect

Use the confirmation counters and `uncertain_count`/oldest uncertain age.
Provider timeouts, transport errors, malformed responses, and lost responses
must appear as `uncertain` or as a bounded worker failure; they must never
appear as an unexplained successful publish.

### Contain

1. Keep the worker running so it can perform bounded acceptance lookups; do
   not force immediate notification retries.
2. Stop configuration rollouts and binding/key changes.
3. Do not disable the recovery authority API. A provider outage may reduce
   delivery availability but must not widen or block the authority checks
   needed to create, approve, revoke, or otherwise protect recovery state.
4. Do not infer acceptance from email arrival, a provider support statement,
   a provider dashboard screenshot, or an HTTP timeout.

### Recover

1. Restore the provider’s acceptance lookup first, with the exact binding and
   idempotency-key contract.
2. Allow the worker’s bounded lookup schedule to run. A positive exact proof
   moves the matching row to `published`; a negative, malformed, or timed-out
   lookup leaves it `uncertain`.
3. Confirm the counter delta and aggregate state transition. A lookup success
   is not a second notification publish.
4. For rows still uncertain, follow Procedure D. For new rejected deliveries,
   allow normal bounded retry/dead-letter behavior only after provider health
   is stable.

### Rollback and stop condition

Stop immediately if the provider returns a different binding, a different
idempotency key, extra response fields, or a response that cannot be framed
within the configured limit. Preserve the last known-good configuration and
leave rows uncertain. Never roll back a database migration to clear an
uncertain row.

### Evidence and post-drill verification

Record only the scenario, fixed binding version (not the binding secret or
destination), counter deltas, before/after state-class counts, and readiness
codes. Verify that the provider acceptance count for the public idempotency
key is at most one, no automatic confirmation used notification content, no
active lease remains, and no `uncertain` row was pruned.

## 5. Procedure B — worker restart or process loss

### Preconditions

- Confirm the deployed image supports schema 36 and the same provider binding
  as the running fleet.
- Confirm a graceful restart or the platform’s approved replacement action is
  available. The application handles `SIGTERM` by beginning drain, stopping
  new work, and closing the PostgreSQL runtime with a bounded timeout.
- Record the pre-restart aggregate snapshot.

### Detect

Use `worker_state`, readiness code, pending/uncertain ages,
`owner_recovery_outbox_claim_lost_total`,
`owner_recovery_outbox_failure_total`, and the process supervisor’s aggregate
restart count. A claim loss is not proof of duplicate delivery; inspect the
durable state and provider acceptance ledger.

### Contain

1. Pause rollout and do not start a second unmanaged worker with a different
   binding or schema.
2. Request the deployment platform’s approved graceful restart. Do not run an
   ad-hoc production `kill`, `pkill`, container deletion, or database update.
3. If the process does not drain within its bounded timeout, use only the
   platform’s documented force-replace procedure and record that it was used
   as a deployment placeholder in the report.
4. Do not manually release a claim or set a row to `pending`; lease expiry and
   the database recovery transition own that decision.

### Recover

1. Start exactly the previously approved image/configuration and verify
   schema version 36, provider binding, worker state `running`, and no
   readiness schema drift.
2. Wait for expired claims to become `uncertain` as designed, then let a new
   worker identity process eligible `pending` rows.
3. Verify that each affected row has one authoritative outcome and that
   `uncertain` remains non-claimable until exact provider proof or an
   Owner/Admin decision.

### Rollback and stop condition

Stop if readiness reports `schema_version_mismatch`, `migration_drift`, an
unknown binding, or a signer/provider configuration mismatch. Roll back the
application image only when the previous image supports the already-applied
schema 36 contract and the same immutable binding; never roll back PostgreSQL
migrations as an incident response.

### Evidence and post-drill verification

Capture restart count, worker states, bounded drain duration, aggregate claim
loss delta, and final state classes. Verify no active lease remains, no row
was silently rebound, provider acceptance count is unchanged except for the
single logical event, and readiness is `ready` only after all fixed checks
pass.

## 6. Procedure C — shared limiter outage

### Preconditions

- Identify the affected limiter purpose from fixed operation names only; do
  not record raw provider subjects, IP addresses, cookies, or assertions.
- Confirm PostgreSQL and schema health separately from the limiter signal.
- Confirm the deployment has no process-local hosted allowance fallback.

### Detect

Observe `human_auth_rate_limit_unavailable_total`,
`rate_limit_denial_total`, HTTP status classes (`429` versus `503`), database
readiness, pool saturation, and the two fixed session-bootstrap stages. A
`429` is a valid policy denial; an unavailable counter or `503` is a control
dependency failure.

### Contain

1. Keep human authentication, WebAuthn, session bootstrap, and management
   mutations fail closed while the shared limiter is unavailable.
2. Do not reset buckets by restarting one replica, bypass the limiter, raise
   capacity ad hoc, or reintroduce a process-local allowance.
3. Preserve existing valid sessions; do not revoke them merely because a
   limiter probe is unavailable.
4. If a limiter outage overlaps with a recovery mutation, require the normal
   WebAuthn proof and retry only after the shared limiter has recovered.

### Recover

1. Restore the shared PostgreSQL limiter dependency and confirm the fixed
   unavailable counter stops increasing.
2. Run the existing shared-control and session-bootstrap PostgreSQL
   qualification against a disposable database before enabling the affected
   deployment path:

   ```bash
   AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:REDACTED@127.0.0.1:5432/agentpass_w16' \
     node --test --test-concurrency=1 \
       apps/cloud-api/test/postgres/session-bootstrap-rate-limit.integration.test.mjs \
       apps/cloud-api/test/postgres/shared-abuse-control-hardening.integration.test.mjs
   ```

   `REDACTED` is a placeholder for a disposable test credential; do not use a
   production DSN in this command.
3. Verify two API instances observe the same bucket and that a denied or
   failed request creates neither a session nor a replay marker.

### Rollback and stop condition

Stop if the limiter can be reset by a replica restart, if unknown identifiers
create unbounded rows, if a denied request consumes replay state, or if the
limiter returns an unbounded `Retry-After`. Keep the path fail closed until
the shared-control test and aggregate health checks pass.

### Evidence and post-drill verification

Capture only operation-class counts, status classes, limiter unavailable and
denial deltas, pool state, and session/replay outcome counts. Verify no
principal-derived label exists in metrics, no session was created during a
denied request, and both replicas converge on the same shared bucket behavior.

## 7. Procedure D — uncertain-delivery adjudication

### Preconditions

1. Confirm the row is visible through the authenticated uncertain-delivery
   list and has a current `management_version`, fixed `uncertain_reason`, and
   a bound provider tuple. Do not enumerate by guessing event IDs.
2. The operator must be an active Owner/Admin in the same organization. A
   deployment or database operator cannot perform this action.
3. Obtain a fresh WebAuthn authorization for exactly one operation and one
   context containing the organization, event, action, and expected management
   version. The proof is single-use.
4. Use a new idempotency key for each intended mutation; reuse of a key with a
   different request is a conflict.

### Detect and decide

Use this decision tree:

```text
exact positive provider proof for same binding + same public key
  └─ allow automatic publish; do not retry notification
no exact positive proof
  ├─ duplicate delivery is acceptable → Owner/Admin retry_uncertain
  └─ duplicate delivery is not acceptable or event is obsolete → suppress_uncertain
binding absent, substituted, or provider unconfigured
  └─ stop; do not retry; investigate configuration and use suppression only
     after an explicit Owner/Admin business decision
```

An email, dashboard, log line, timeout, malformed lookup response, or human
statement is not an exact positive proof.

### Contain and execute

1. Do not edit the row or mark it published manually.
2. Refresh the list immediately before the mutation. Use the returned
   management version as `If-Match` and recompute the exact WebAuthn context.
3. Perform exactly one operation through the Human API. The UI/API must show
   the authoritative returned version before reporting success.
4. A stale-version conflict, consumed-proof result, authorization failure, or
   storage/audit failure is a stop condition. Refresh state and obtain a new
   proof; never repeat the same proof or force the old version.

### Rollback and stop condition

There is no rollback from `suppressed` or `published`. A retry creates a new
pending attempt under the same public idempotency key and may cause a
provider-side duplicate if the provider’s acceptance ledger is unavailable.
Stop when the business owner cannot accept that risk, when the row is
unbound, or when the exact provider tuple does not match.

### Evidence and post-drill verification

Record operation class, reason class, old/new state class, old/new management
version, counter deltas, and whether the result was committed, replayed, or
rejected. Never record WebAuthn material. Verify the audit event and
idempotency record are present, the proof cannot be reused, another tenant
cannot access the row, and no stale caller can publish it.

## 8. Procedure E — dead-letter redrive

### Preconditions

- Confirm the row is `dead_letter`, provider binding state is `bound`, and
  `redrive_count < 3`.
- Identify the stable error category from the bounded API field
  `last_error_code`; do not copy provider diagnostics.
- Obtain Owner/Admin recent WebAuthn for
  `human.recovery.outbox.redrive` and the exact event/version context.
- Confirm the provider is healthy enough to accept the same idempotency key.

### Detect and contain

Dead letters are terminal for automatic delivery. Do not redrive an entire
queue in bulk, change the retry ceiling, or create a new event to work around
the CAS. Process one bounded, reviewed item at a time. A redrive failure may
be an expected stale-version or idempotency conflict; classify the response
before treating it as an outage.

### Recover

1. Refresh the dead-letter page and use the current management version.
2. Confirm the reason and duplicate-delivery decision with the Owner/Admin.
3. Submit one redrive with a fresh proof and new idempotency key.
4. Confirm the returned state is authoritative `pending` and that
   `redrive_count` increased exactly once.
5. Let the worker perform normal bound, leased delivery. Do not call the
   provider from the operator workstation.

### Rollback and stop condition

Stop on any binding mismatch, `redrive_count >= 3`, version conflict,
idempotency conflict, audit failure, or storage unavailability. There is no
manual rollback from a committed redrive; if it becomes unsafe, use a fresh
Owner/Admin suppression operation after state refresh and recent WebAuthn.

### Evidence and post-drill verification

Record only error/state classes, attempt and redrive counts, response status
class, and aggregate provider acceptance count. Verify exactly one management
version increment, one audit event, one idempotency completion, no duplicate
provider acceptance, and eventual `published`, `dead_letter`, or explicit
`uncertain` convergence.

## 9. Procedure F — retention/prune failure

### Preconditions

- Confirm this is terminal-row retention, not an authority or outbox state
  mutation. `uncertain` rows are never eligible for terminal retention.
- Confirm schema 36, database readiness, pool utilization, and migration
  checksum status.
- Confirm the scheduled maintenance budget and last expected cycle from the
  deployment scheduler. Do not increase the prune limit during an incident.

### Detect

Use the conservative signal pair described in Section 2:
`owner_recovery_outbox_prune_total`,
`owner_recovery_outbox_prune_failure_total`, and the fixed expected-cycle
count. `owner_recovery_outbox_failure_total` may corroborate the incident but
is not a prune-specific alert.
Cross-check aggregate terminal-row age/count using an approved read-only
health/reporting view. Never export raw rows.

### Contain

1. Stop the maintenance rollout or configuration change; leave the current
   bounded worker schedule in place unless it is causing database harm.
2. Do not delete rows manually, run an unbounded `DELETE`, bypass
   `FOR UPDATE SKIP LOCKED`, or prune `uncertain` rows.
3. If PostgreSQL is saturated, protect authority traffic first and use the
   deployment platform’s approved maintenance pause control. The control is
   a deployment placeholder, not a repository command.

### Recover

1. Resolve database connectivity, lock, schema, or permission failure using
   the platform’s normal change process.
2. Run the repository’s bounded retention qualification on disposable
   PostgreSQL before resuming the scheduled worker:

   ```bash
   AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:REDACTED@127.0.0.1:5432/agentpass_w16' \
     node --test --test-concurrency=1 \
       apps/cloud-api/test/postgres/owner-recovery-outbox-retention.integration.test.mjs \
       apps/cloud-api/test/postgres/owner-recovery-retention-confirmation-races.integration.test.mjs
   ```

   `REDACTED` is a disposable-test placeholder. This command does not target
   production.
3. Resume the bounded scheduler only after readiness, migration checksum, and
   lock health are verified. The worker’s result must satisfy
   `published + dead_letter + suppressed == total` and `total <= limit`.

### Rollback and stop condition

Stop if the result envelope is malformed, the count exceeds the configured
limit, a row is not copied to the immutable retention ledger before removal,
or any `uncertain` row is selected. Do not roll back migrations. Keep terminal
rows until the bounded, ledger-backed procedure is healthy.

### Evidence and post-drill verification

Capture limit, bounded aggregate removal counts, cycle status, counter deltas,
schema version, and retention-ledger verification result. Verify no active
lease remains, the ledger count matches removed terminal rows, `uncertain`
rows remain, and a second bounded run is idempotent.

## 10. Reproducible W1 exit command sequence

The following is the current repository sequence. It uses disposable
PostgreSQL only; replace `REDACTED` with a test-only credential and never use
a production DSN. The evidence path must be an absolute, owner-only regular
file under a 0700 directory.

```bash
set -eu
umask 077
mkdir -p "$PWD/.w1-evidence"
chmod 0700 "$PWD/.w1-evidence"
export AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:REDACTED@127.0.0.1:5433/postgres'
export AGENTPASS_W15_EVIDENCE_OUTPUT="$PWD/.w1-evidence/owner-recovery-race-matrix.json"

npm run contracts:validate
npm run test:w16
npm test
npm run lint
npm run test:postgres:w15
npm run test:postgres:w15:composed
export AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:REDACTED@127.0.0.1:5433/agentpass_w15_upgrade'
node --test apps/cloud-api/test/postgres/owner-recovery-delivery-binding-upgrade.integration.test.mjs
node scripts/owner-recovery/verify-w15-evidence.mjs "$AGENTPASS_W15_EVIDENCE_OUTPUT"
git diff --check
```

The upgrade command needs a disposable database already created for that
purpose and the corresponding `AGENTPASS_TEST_DATABASE_URL`; the CI workflow
uses a PostgreSQL 16 service and an isolated `agentpass_w15_upgrade` database.
The exact CI commands are in `.github/workflows/ci.yml` and are the source of
truth for the W1.5 qualification lane.

The current worktree contains two machine-readable W1.6 gates and the policy
they validate:

```bash
# Validate and bind the exact fixed policy used by the staging drill.
export AGENTPASS_W16_ALERT_POLICY_DIGEST="$(node scripts/owner-recovery/validate-w16-alerts.mjs \
  "$PWD/ops/observability/owner-recovery-alerts.v1.json")"
node scripts/owner-recovery/verify-w16-drill-evidence.mjs \
  "$AGENTPASS_W16_DRILL_EVIDENCE_OUTPUT" \
  --commit-sha "$(git rev-parse HEAD)" \
  --image-digest "$AGENTPASS_STAGING_IMAGE_DIGEST" \
  --alert-policy-digest "$AGENTPASS_W16_ALERT_POLICY_DIGEST"
```

`AGENTPASS_STAGING_IMAGE_DIGEST` must be the non-secret immutable
`sha256:...` digest of the deployed staging image. The alert validator emits
only the exact policy digest. `validate-w16-alerts.mjs` validates the closed alert policy and
`verify-w16-drill-evidence.mjs` independently validates the source-bound
staging artifact. Their companion tests are
`scripts/owner-recovery/validate-w16-alerts.test.mjs` and
`scripts/owner-recovery/verify-w16-drill-evidence.test.mjs`. Neither tool may
mutate PostgreSQL or call a provider. The drill evidence verifier requires
schema version 36, all six scenarios in canonical order, zero active claims
and leases, source/image/policy digests, a passed outcome, and an owner-only
regular file no larger than 16 KiB.

W1 is not closed until the current sequence passes, both W1.6 gates
pass on the same source commit/image/schema, and a staging report covers all
six procedures with the evidence rules above.

## 11. Post-drill closure checklist

- [ ] All warning/critical observations use fixed aggregate signals and the
      recorded scrape interval.
- [ ] No Owner/Admin proof, session material, or provider secret appears in
      logs, URLs, metrics, tickets, screenshots, or evidence.
- [ ] Every authority-changing action has an exact role, organization,
      operation, context hash, recent WebAuthn, idempotency key, and
      `If-Match` result.
- [ ] Provider acceptance is never inferred from response loss or external
      statements.
- [ ] No `uncertain` row was automatically retried or pruned.
- [ ] No direct SQL authority update was used.
- [ ] Worker leases, PostgreSQL transactions, and maintenance cycles are
      bounded and settled.
- [ ] The final scrubbed evidence file is independently verified and its
      digest is recorded with the source commit, image/package digest, and
      schema version.
