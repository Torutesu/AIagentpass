# Protected staging drill evidence contract

This document is the evidence contract for the staging readiness and rollback
drills. It defines what a protected runner must retain before a candidate can
be considered for promotion. It does not create evidence and it does not make
local, mock, simulated, or self-reported results production evidence.

The contract is deliberately stricter than an operator checklist. A status
field is an assertion; it is not proof. Proof is the canonical, immutable
record plus an independently observed execution bound to the exact candidate
and deployment identities below.

## Fixed scenario set

The readiness record contains exactly one operation object for each of
`canary`, `drain`, `failover`, `pitr`, `signer_outage`, and `recovery`. The
separate rollback record contains exactly one resilience event for each of
`failover`, `pitr`, `recovery`, `rollback`, and `signer_outage`. Missing,
duplicated, extra, or `not_run` records are a hard stop:

| Scenario ID | Required exercise | Required measurements |
| --- | --- | --- |
| `canary` | Route bounded traffic to the candidate. | request/error counts, traffic percentage, application SLO target and observed value |
| `drain` | Stop new work and drain the prior revision. | in-flight before/after, drain duration, drain SLO target and observed value |
| `rollback` | Activate the immutable prior target and restore traffic. | target readiness, traffic restoration, rollback duration/RTO, target identity |
| `failover` | Exercise the database/service failure-domain transition. | failover start/end, measured RPO and RTO, old/new endpoint identities |
| `pitr` | Restore an isolated database to an explicit point in time. | recovery point, measured RPO/RTO, backup/restore/database digests |
| `signer_outage` | Deny signer/provider availability and recover it. | outage detection/recovery SLO, fail-closed result, fallback count, key/version identity |
| `recovery` | Recover the service and audit path after the exercised fault. | recovery duration/RTO, audit continuity, post-recovery SLO, resulting target identity |

The scenario records are projections of redacted observations. They must not
contain provider responses, credentials, database URLs, private keys, tokens,
cookies, request bodies, tenant identifiers, or raw logs.

## Canonical envelope

The implementation must accept only the canonical JSON shape below. Exact
object-key validation applies recursively; unknown keys, duplicate JSON keys,
accessors, arrays in place of objects, and non-canonical bytes are rejected.
Values shown as `<...>` are typed placeholders, not values to copy into a
qualification record.

```json
{
  "schema_version": 2,
  "kind": "agentpass.staging-drill-evidence",
  "environment": "staging",
  "service": "agentpass-cloud-api",
  "status": "passed",
  "qualified": true,
  "candidate": {
    "candidate_id": "release-pkg-sha256-v1-<artifact_sha256>",
    "artifact_sha256": "<64 lowercase hex>",
    "release_manifest_sha256": "<64 lowercase hex>",
    "source_commit": "<40 lowercase hex>",
    "source_tree": "<40 lowercase hex>"
  },
  "deployment": {
    "deployment_id": "<concrete immutable deployment id>",
    "deployment_digest": "<64 lowercase hex>",
    "revision": "<concrete revision>",
    "image_digest": "sha256:<64 lowercase hex>",
    "schema_digest": "<64 lowercase hex>",
    "catalog_digest": "<64 lowercase hex>",
    "database_schema_digest": "<64 lowercase hex>"
  },
  "rollback_target": {
    "candidate": { "...": "same candidate shape" },
    "deployment": { "...": "same deployment shape, different revision" },
    "status": "passed",
    "target_ready": true
  },
  "canary": { "...": "operation object below" },
  "drain": { "...": "operation object below" },
  "failover": { "...": "operation object below" },
  "pitr": { "...": "operation object below" },
  "signer_outage": { "...": "operation object below" },
  "recovery": { "...": "operation object below" },
  "issued_at": "<ISO-8601 UTC milliseconds>",
  "expires_at": "<ISO-8601 UTC milliseconds within the bounded window>",
  "evidence_sha256": "<SHA-256 of canonical object without this field>"
}
```

The `"..."` values above are documentation placeholders and are not valid
evidence values. The actual operation object has exactly these keys (plus the
scenario-specific keys already present for canary and drain):

```json
{
  "binding": {
    "artifact_sha256": "<exact candidate artifact>",
    "candidate_id": "<exact candidate id>",
    "catalog_digest": "<exact deployment catalog>",
    "database_schema_digest": "<exact database schema>",
    "deployment_digest": "<exact deployment>",
    "image_digest": "sha256:<exact image>",
    "rollback_target_sha256": "<SHA-256 of canonical rollback target>",
    "schema_digest": "<exact application schema>",
    "source_commit": "<exact source commit>",
    "source_tree": "<exact source tree>"
  },
  "completed_at": "<ISO-8601 UTC milliseconds>",
  "execution": {
    "environment": "staging",
    "kind": "protected_runner",
    "real_execution": true,
    "run_attempt": "<positive decimal>",
    "run_id": "<positive decimal>",
    "runner_id": "<concrete protected runner>"
  },
  "execution_id": "<unique protected execution id>",
  "expected": "<healthy|drained|available|restored|denied|recovered>",
  "limits": { "rpo_ms": <nonnegative integer>, "rto_ms": <nonnegative integer>, "slo_ms": <nonnegative integer> },
  "measurements": { "rpo_ms": <nonnegative integer>, "rto_ms": <nonnegative integer>, "slo_ms": <nonnegative integer> },
  "observed": "<same fixed value as expected on pass>",
  "observer": {
    "evidence_sha256": "<digest of observer projection>",
    "independent": true,
    "observed_at": "<ISO-8601 UTC milliseconds>",
    "observer_execution_id": "<different observer execution>",
    "observer_id": "<different protected observer>",
    "source": "independent_observer"
  },
  "started_at": "<ISO-8601 UTC milliseconds>",
  "status": "passed"
}
```

For the rollback verifier, `resilience.events` is an exact object with five
events (`failover`, `pitr`, `recovery`, `rollback`, `signer_outage`). Each
event has exactly `candidate`, `completed_at`, `deployment`, `event_type`,
`execution_id`, `measurements`, `observer`, `started_at`, `status`, and
`target`. The event candidate/deployment/target must equal the current
rollback record's identities. Its `observer` is a signed protected observer
object with exactly `attestation`, `kind`, `observed_at`, `observer_id`,
`observer_key_fingerprint`, `public_key_pem`, and `signature`; it must use
`attestation: "independent_external"` and `kind: "protected_observer"`.
The binding file supplies the same event types, execution IDs, observer IDs,
observer key fingerprints, and SLO/RPO/RTO limits. A compatibility adapter
must not silently discard a scenario, measurement, observer, signature, or
digest.

## Binding and independence rules

Every readiness operation repeats the candidate and deployment binding in its
exact `binding` object. Every rollback resilience event repeats the candidate,
deployment, and rollback target objects. The verifier must compare, at
minimum:

- candidate ID ↔ artifact digest ↔ release-manifest digest;
- source commit and full source tree;
- deployment/image digest and immutable revision;
- application schema, catalog, and database-schema digests;
- execution ID, scenario/event ID, protected runner run/attempt, start/end
  times, and observer evidence digest;
- rollback target candidate/deployment, which must be a different revision in
  the same staging service/deployment; and
- scenario-specific endpoint/key/backup identities where applicable.

For readiness operations, the observer is independent when it is produced by a separately controlled
protected process or control plane, has an identity distinct from the
operator/executor, deployer, signer/provider attestor, and approval signer,
and verifies the measured event rather than copying the subject's status. A
record that says `independent: true` without an independently verifiable
observer identity and evidence digest is self-reported and must be rejected.
The same key or execution identity may not serve as both subject and observer.
For rollback resilience events, the observer signature is Ed25519 and the
fingerprint must be the SHA-256 of the supplied SPKI public key. The verifier
checks the signature over the canonical event projection; a public key or
signature copied from the subject is not independent evidence.

`execution_id` values must be unique within an envelope and must not be
`local`, `mock`, `fixture`, `placeholder`, `simulator`, `synthetic`,
`unknown`, `not_run`, or `self-reported`. A provider request whose response was
lost is not a successful execution; retain it as failed or not proven and
reconcile it through the provider's durable lookup path before retrying.

## Status and freshness rules

The only terminal statuses are `passed`, `failed`, `not_run`, and
`not_proven`. The verifier derives the envelope status from all child records;
the root `qualified` flag is never trusted as authority.

- Any missing, malformed, duplicate, `not_run`, or `not_proven` scenario is a
  hard stop and cannot be converted to `passed` by editing the envelope.
- `failed` is retained as a failure artifact and blocks promotion. A rerun
  creates a new execution ID and a new record; the failed record is retained.
- A stale record is one outside the verifier's current bounded evidence
  window, with a completion time after verification time, or whose observer
  evidence is older than the scenario it claims to observe. Stale records
  block promotion even if their digest is valid.
- `source` must be `protected_external` and the execution mode must identify
  a protected runner. Local, mock, fixture, simulator, sandbox, or copied CI
  status is `not_proven`, never a pass.
- Self-reported, unsigned, unbound, or status-only observations are
  `not_proven`, even when the operator is trusted.
- A valid digest proves integrity of the supplied bytes only. It does not
  prove that the bytes came from the stated environment, observer, runner,
  provider, or database.

The evidence window must be finite, current, and bounded by the verifier. The
operator must never use an `allowExpired` or `allowFuture` option for a
promotion decision.

## Scenario-specific minimums

### Canary and drain

Canary evidence must include bounded traffic, request count, successful/error
counts, observed application health, and the application SLO. Drain evidence
must include the old/new revisions, stop-new-work observation, in-flight
before/after, and a measured drain duration. Both must carry the exact
operation `binding`, protected `execution`, `measurements` bounded by
`limits`, and independent observer projection. A claimed `healthy` or
`drained` value without measurements is self-reported.

### Rollback

Rollback evidence must prove execution, target readiness, artifact reuse,
traffic restoration, and the exact rollback target. It must bind the rollback
execution ID and independent observer to the target deployment and record the
rollback RTO. Rebuilding an equivalent image, changing a digest, or using the
same revision is not rollback evidence.

### Failover and PITR

Failover must identify distinct source and destination endpoint identities and
record the observed RPO/RTO. PITR must identify the immutable backup digest,
restore target, recovery point, schema/catalog/database digests, and observed
RPO/RTO. The restore target must be isolated and disposable; no production
database may be modified to manufacture evidence. A local PostgreSQL restore
or a copied `pg_last_wal_replay_lsn` is `not_proven`.

### Signer outage and recovery

Signer-outage evidence must bind the purpose, provider resource, key version,
deployment/image, and execution ID. It must demonstrate fail-closed behavior,
zero file/local fallback, no duplicate signing after response loss, and an
independently observed recovery. Recovery must bind the restored key/version,
audit continuity, and the recovery RTO/SLO. A report from the signer client
alone cannot prove provider outage or recovery.

## Operator procedure and handoff

1. Freeze the candidate, source/tree, artifact, deployment, schema/catalog,
   database-schema, and rollback-target identities from signed/immutable
   sources.
2. Allocate a unique protected execution ID and an independent observer before
   starting the first scenario.
3. Run each fixed scenario in order appropriate to the change. Record raw
   provider data only in the protected system of record; project redacted
   measurements into the canonical envelope.
4. Have the observer independently fetch/measure the event, bind its digest,
   and attest the scenario. Do not ask the subject operator to mark its own
   observation as independent.
5. Canonicalize, hash, and retain the envelope and all child observation
   digests. Run the readiness and rollback verifiers from the protected
   checkout using the current UTC clock.
6. If any verifier fails, preserve the failed/not-proven record, page the
   owner, and record `STOP`. Do not edit, delete, replay, or downgrade the
   failed record.
7. Promotion may consume only the independently verified, exact-candidate
   result. Local contract tests remain implementation evidence only.

This document is a contract and runbook, not a qualification result. At the
time of writing, absence of an actual protected staging envelope keeps the
external staging gate `not_proven`.
