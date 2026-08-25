# W1.6 operational closure

Status: documentation contract prepared; the fixed alert policy and
evidence validator/verifier are present in the current worktree, while staging
execution remains pending.

This document closes the operator-documentation slice of W1. W1.6 is not a
claim that AgentPass is production-ready. It is the bounded operational gate
for the recovery-delivery path after the W1.5 implementation and CI
qualification. Production deployment, cloud signer IAM qualification, signed
macOS distribution, restore drills, and independent security review remain
outside this slice.

## 1. Purpose and non-goals

W1.6 must make an operator able to answer, without reading application logs
or touching the database directly:

- Is delivery delayed, unknown, terminally failed, or merely rate limited?
- Which bounded action is safe for the current state?
- Who is authorized to take that action?
- What evidence proves that authority was not widened or provider acceptance
  fabricated?
- When must the operator stop and escalate?

W1.6 does not add an emergency backdoor, a manual state-edit procedure, a
provider-side workaround, an operator bearer token, or a generic threat model.
The repository-level [THREAT_MODEL.md](../THREAT_MODEL.md) records the
non-authoritative notification and aggregate-only observability boundary.

## 2. Authoritative current-state contract

The following facts are grounded in the current implementation:

| Boundary | Current contract | Evidence source |
| --- | --- | --- |
| Database | Migrations 1–36 are forward-only; readiness rejects pending, modified, dirty, or mismatched schema. | `apps/cloud-api/src/postgres/migration-runner.mjs`, `operational-health.mjs` |
| Delivery state | `uncertain` has no automatic claim path; terminal retention excludes it. | `apps/cloud-api/src/postgres/owner-recovery-outbox-worker.mjs`, migrations 34–36 |
| Provider proof | Automatic publish requires the exact bound provider tuple and the same public idempotency key. | `apps/cloud-api/src/postgres/owner-recovery-outbox-repository.mjs`, `owner-recovery-notification-publisher.mjs` |
| Operator role | Dead-letter and uncertain list/mutation paths accept only active `owner` or `admin` membership/session scope. | `owner-recovery-outbox-management-repository.mjs`, `human-auth/recovery/dead-letter-http-api.mjs` |
| Human step-up | Mutations require operation/resource/version-bound recent WebAuthn, CSRF, Origin, idempotency, and `If-Match`. | `human-auth/recovery/dead-letter-http-api.mjs`, `owner-recovery-outbox-management-repository.mjs` |
| Transaction | State mutation, audit append, and idempotency completion are committed in one organization-locked transaction. | `owner-recovery-outbox-management-repository.mjs` |
| Health | `/health/ready` and `/health/metrics` are probe-secret protected and expose fixed, label-free contracts. | `apps/cloud-api/src/server.mjs`, `operational-health.mjs` |
| Evidence | W1.5 verifier accepts only a protected regular file with a closed schema and public digests/state classes. | `scripts/owner-recovery/verify-w15-evidence.mjs` |
| W1.6 policy/evidence gate | The current worktree contains a closed alert policy, alert validator, drill evidence schema, and independent drill verifier. | `ops/observability/owner-recovery-alerts.v1.json`, `scripts/owner-recovery/validate-w16-alerts.mjs`, `scripts/owner-recovery/verify-w16-drill-evidence.mjs` |

The implementation, not this document, is authoritative if a wording conflict
is discovered. A conflict is a W1.6 stop condition and must be resolved by a
code/schema/documentation change before the drill is declared passed.

## 3. Operator and WebAuthn responsibility model

| Actor | May observe | May mutate recovery outbox | WebAuthn requirement |
| --- | --- | --- | --- |
| Deployment operator | Aggregate readiness/metrics and deployment state | No | Cannot substitute infrastructure access for Human authorization. |
| Database operator | Approved aggregate/reporting views and transaction health | No direct SQL updates | Not applicable; database credentials are not an authority grant. |
| Provider operator | Provider aggregate health and acceptance lookup status | No AgentPass state mutation | Not applicable. Provider support statements are not acceptance proof. |
| Owner | Organization-scoped dead letters/uncertain rows and all four bounded mutations | Yes | Active same-organization session plus fresh operation/resource/version-bound WebAuthn. |
| Admin | Organization-scoped dead letters/uncertain rows and all four bounded mutations | Yes | Same as Owner; Admin does not gain threshold-owner recovery powers merely by being Admin. |
| Auditor | Audit views where separately authorized | No | No recovery outbox mutation authorization. |
| Viewer | Non-mutating product views where separately authorized | No | No recovery outbox mutation authorization. |

The four mutation names are frozen as:

- `human.recovery.outbox.retry_uncertain`;
- `human.recovery.outbox.suppress_uncertain`;
- `human.recovery.outbox.redrive`; and
- `human.recovery.outbox.suppress`.

The proof context includes organization, event, action, and expected
management version. A proof is single-use. A stale version, consumed proof,
cross-tenant context, role mismatch, idempotency conflict, CSRF/Origin failure,
or audit/storage failure is a rejection, not a reason to bypass a control.

## 4. Fixed-signal alert contract

The alerting layer must consume only fixed aggregate fields and fixed metric
keys. It must not attach organization, member, request, event, destination,
provider, URL, subject, IP, or error-detail labels.

### Readiness fields

The outbox readiness subset is:

```text
worker_state
pending_count
uncertain_count
dead_letter_count
oldest_pending_age_ms
oldest_uncertain_age_ms
```

The top-level readiness `code` is also fixed. Operationally important values
include `ready`, `owner_recovery_outbox_worker_unavailable`,
`owner_recovery_outbox_uncertain_delivery_present`,
`owner_recovery_outbox_dead_letter_present`,
`owner_recovery_outbox_backlog_exceeded`,
`owner_recovery_outbox_lag_exceeded`, `database_unavailable`,
`pool_saturated`, `schema_version_mismatch`, and `migration_drift`. The nested
outbox check uses the corresponding unprefixed code.

### Metric fields

The authenticated metrics response exposes these PostgreSQL-backed,
label-free gauges under `gauges`:

```text
owner_recovery_outbox_pending_count
owner_recovery_outbox_uncertain_count
owner_recovery_outbox_dead_letter_count
owner_recovery_outbox_oldest_pending_age_ms
owner_recovery_outbox_oldest_uncertain_age_ms
```

When no matching row exists, the corresponding age gauge is zero. If the
outbox snapshot cannot be validated, `/health/metrics` returns `503` instead
of reporting zero and the drill cannot pass.

W1.6 may use these existing counter families:

```text
owner_recovery_outbox_claim_total
owner_recovery_outbox_publish_total
owner_recovery_outbox_retry_total
owner_recovery_outbox_dead_letter_total
owner_recovery_outbox_claim_lost_total
owner_recovery_outbox_uncertain_total
owner_recovery_outbox_failure_total
owner_recovery_outbox_lag_count
owner_recovery_outbox_lag_total_ms
owner_recovery_outbox_suppression_total
owner_recovery_outbox_redrive_success_total
owner_recovery_outbox_redrive_failure_total
owner_recovery_outbox_prune_total
owner_recovery_outbox_prune_failure_total
owner_recovery_outbox_confirmation_lookup_total
owner_recovery_outbox_confirmation_success_total
owner_recovery_outbox_confirmation_miss_total
owner_recovery_outbox_confirmation_failure_total
owner_recovery_state_latency_count
owner_recovery_state_latency_total_ms
human_auth_rate_limit_denial_total
human_auth_rate_limit_unavailable_total
rate_limit_denial_total
shared_control_maintenance_cycle_total
shared_control_maintenance_success_total
shared_control_maintenance_failure_total
shared_control_maintenance_removed_total
```

Counter deltas are calculated over a fixed scrape interval and are reset-safe.
An alert must not infer per-tenant or per-event behavior from a process-local
counter. Readiness database counts/ages and the provider acceptance ledger are
the durable cross-process signals.

The exact warning/critical values are defined in
[OWNER_RECOVERY_DELIVERY_RUNBOOK.md](OWNER_RECOVERY_DELIVERY_RUNBOOK.md),
Section 2, and materialized in
`ops/observability/owner-recovery-alerts.v1.json`. A dashboard that merely
displays these counters is not an alert qualification.

## 5. Six-drill execution matrix

Each drill is run against staging with a disposable or explicitly approved
test notification destination and a linearizable acceptance lookup. The drill
lead must announce the scenario and stop time before injecting or observing a
fault. No drill may use a real recovery message, production credential, or
unbounded queue operation.

| Drill | Fault or observation | Safe containment | Required final state | Primary evidence |
| --- | --- | --- | --- | --- |
| Provider outage | Publish timeout, lost response, or acceptance lookup outage. | Keep bounded lookup; freeze binding rotation; do not blind-retry. | `published` only after exact proof, otherwise explicit `uncertain` or reviewed terminal state. | Fixed counters, state classes, provider acceptance count, binding version. |
| Worker restart | Graceful `SIGTERM`, bounded drain, or approved process replacement. | Do not release claims or edit rows manually. | Expired claims converge to `uncertain`; new worker has `running` state and no active stale lease. | Worker state, drain duration, claim-loss delta, final state classes. |
| Limiter outage | Shared limiter unavailable across at least two API instances. | Auth/session/management fail closed; no local fallback. | No unauthorized session/mutation; recovery after shared bucket health returns. | 429/503 classes, limiter deltas, session/replay outcome counts. |
| Uncertain adjudication | Exact positive proof, negative proof, and no-proof cases. | Owner/Admin chooses retry or suppression only after fresh WebAuthn. | One CAS winner; never manual `published`; no stale proof reuse. | Operation class, versions, audit/idempotency result, final state class. |
| Dead-letter redrive | Bound dead letter below the redrive ceiling. | One bounded item, current `If-Match`, no bulk mutation. | One redrive increment and normal worker convergence. | Error/state classes, attempt counts, acceptance count, audit result. |
| Prune failure | Database/lock/schema/permission failure during bounded retention. | Preserve terminal rows; never prune uncertain; protect authority traffic. | Recovery only after bounded ledger-backed prune passes. | Limit, aggregate removal counts, cycle status, ledger match, schema version. |

The complete procedures, stop conditions, redaction policy, and post-drill
checks are in the runbook. The matrix is intentionally not a second source
for different thresholds.

## 6. Drill evidence contract

The W1.6 report is a new operational artifact, not an application audit log.
The current worktree schema and verifier accept this exact shape:

```json
{
  "source_commit": "<exactly 40 or 64 lowercase hex>",
  "image_digest": "sha256:<64 lowercase hex>",
  "alert_policy_digest": "sha256:<64 lowercase hex>",
  "schema_version": 36,
  "started_at": "2026-08-14T00:00:00.000Z",
  "completed_at": "2026-08-14T00:01:00.000Z",
  "duration_ms": 60000,
  "outcome": "passed",
  "scenarios": [
    { "name": "provider_outage", "outcome": "passed" },
    { "name": "worker_restart", "outcome": "passed" },
    { "name": "limiter_outage", "outcome": "passed" },
    { "name": "uncertain_adjudication", "outcome": "passed" },
    { "name": "dead_letter_redrive", "outcome": "passed" },
    { "name": "prune_failure", "outcome": "passed" }
  ],
  "aggregate_observations": {
    "scenario_count": 6,
    "passed_count": 6,
    "failed_count": 0,
    "alert_policy_rule_count": 10,
    "warning_alerts_observed": 10,
    "critical_alerts_observed": 10,
    "unauthorized_mutations": 0,
    "duplicate_provider_acceptances": 0,
    "forbidden_material_findings": 0,
    "active_claims": 0,
    "active_leases": 0
  }
}
```

`scripts/owner-recovery/w16-drill-evidence.schema.json` publishes the closed
structural contract, including nonzero bindings and canonical scenario order.
The verifier is the authoritative acceptance gate because JSON Schema cannot
express the required cross-field equality between timestamps and
`duration_ms`. It validates calendar timestamps, derives the duration,
requires a maximum of 30 minutes, and rejects all additional fields. No
free-form `details`, raw HTTP, SQL, provider, identity, or diagnostic field may
be added.

The evidence must be:

- an absolute-path, owner-only regular file;
- non-symlink and single-link;
- bounded in size;
- JSON encoded with a closed key set;
- independently verified after generation; and
- uploaded only after verification succeeds.

The W1.5 verifier is the current available pattern:
`scripts/owner-recovery/verify-w15-evidence.mjs`. W1.6 must not weaken it or
reuse its schema for a different artifact.

## 7. W1.6 validator and verifier

The current worktree contains these paths:

- `scripts/owner-recovery/validate-w16-alerts.mjs` — validates
  `ops/observability/owner-recovery-alerts.v1.json` against the closed
  fixed-name warning/critical policy and zero-label rule;
- `scripts/owner-recovery/verify-w16-drill-evidence.mjs` — independently
  verifies the source-bound staging artifact;
- `scripts/owner-recovery/w16-drill-evidence.schema.json` — publishes the
  machine-readable artifact schema;
- `scripts/owner-recovery/validate-w16-alerts.test.mjs` and
  `scripts/owner-recovery/verify-w16-drill-evidence.test.mjs` — contract tests.

The previously planned generic names
`validate-w16-operational-closure.mjs` and
`verify-w16-operational-evidence.mjs` are not the repository contract and must
not be used in runbooks or CI.

The alert validator validates the alert policy’s fixed signal names,
thresholds, windows, zero-label rule, and closed JSON shape. The drill verifier
performs the independent file, schema, redaction,
permission, link, size, timestamp, and public-digest checks before
retention/upload. Both tools are read-only and deterministic; they do not
connect to production, invoke a provider, mutate PostgreSQL, accept a token on
the command line, or print report contents.

The combined W1.6 gate must reject at least:

- an alert policy with an invented metric or label;
- a missing or reordered drill;
- warning/critical thresholds that differ from the runbook;
- `uncertain` treated as automatically retryable or prunable;
- a mutation without Owner/Admin and fresh operation-bound WebAuthn;
- a report that claims `published` without exact provider proof;
- a successful prune that does not prove ledger-backed bounded removal; and
- a report that calls staging, simulator, or local evidence production proof.

The verifier must reject at least:

- symlinks, hard links, group/other-readable files, oversized files, unknown
  JSON keys, invalid UTF-8, duplicate keys, and non-public identifiers;
- DSNs, URLs, cookies, CSRF values, WebAuthn assertions/options, credentials,
  tokens, claim values, private keys, provider bodies, notification content,
  stack traces, and raw headers; and
- a non-zero active lease, pending claim, missing source/digest binding, or
  scenario result inconsistent with its fixed final-state class.

## 8. Reproducible exit sequence

The current W1.5 repository sequence is reproduced in the runbook Section 10.
The source-bound CI workflow is `.github/workflows/ci.yml`; its PostgreSQL 16
lane runs the W1.5 race, composed HTTPS-provider, retention/confirmation, and
independent evidence-verifier commands.

The W1.6 sequence appends these current commands after the staging report is
written. `AGENTPASS_STAGING_IMAGE_DIGEST` is the non-secret immutable digest
of the exact deployed staging image:

```bash
export AGENTPASS_W16_ALERT_POLICY_DIGEST="$(node scripts/owner-recovery/validate-w16-alerts.mjs \
  "$PWD/ops/observability/owner-recovery-alerts.v1.json")"
node scripts/owner-recovery/verify-w16-drill-evidence.mjs \
  "$AGENTPASS_W16_DRILL_EVIDENCE_OUTPUT" \
  --commit-sha "$(git rev-parse HEAD)" \
  --image-digest "$AGENTPASS_STAGING_IMAGE_DIGEST" \
  --alert-policy-digest "$AGENTPASS_W16_ALERT_POLICY_DIGEST"
```

The evidence path is a staging-generated absolute owner-only file. The
commands validate the policy and artifact but do not themselves execute the
six staging fault drills. The current repository checks that can be run now
are:

```bash
npm run contracts:validate
npm run test:w16
npm test
npm run lint
npm run test:postgres:w15
npm run test:postgres:w15:composed
node scripts/owner-recovery/verify-w15-evidence.mjs "$AGENTPASS_W15_EVIDENCE_OUTPUT"
git diff --check
```

These prove implementation/CI contracts and W1.5 evidence hygiene; they do
not prove that a staging operator completed W1.6.

## 9. W1.6 exit gate

W1.6 passes only when all conditions hold on one source commit, deployment
image/package digest, and schema version:

1. All six drills have a staging result, including at least one negative or
   fail-closed observation for each relevant fault.
2. Fixed aggregate alerts show the documented warning/critical semantics and
   contain no forbidden labels.
3. Provider ambiguity converges to exact `published`, bounded retry,
   `uncertain`, `dead_letter`, or `suppressed`; no acceptance is fabricated.
4. Worker restart leaves no active lease or stale claim that can win later.
5. Limiter outage creates no unauthorized session or replay consumption and
   does not reset shared admission state on replica restart.
6. Only Owner/Admin recent WebAuthn can mutate a same-organization row; replay,
   tenant substitution, stale version, and role denial remain rejected.
7. Redrive is bounded and ledger/audit-backed; prune is bounded, ledger-backed,
   and never selects `uncertain`.
8. The staging report passes the W1.6 validator and verifier, and
   the retained artifact passes the same redaction policy as W1.5.
9. The post-drill checklist is signed by the drill lead and security owner,
   without including a reusable credential or assertion.

If any condition is missing, W1 remains open. The correct status is “not
qualified” rather than an operational bypass or a claim based on local unit
tests alone.
