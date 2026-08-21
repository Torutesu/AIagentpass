# Platform authenticator qualification

This is the qualification contract for the production Platform authenticator.
It is separate from C3 PostgreSQL migration and promotion-ledger
qualification. A local green result is not production evidence.

## Required invariants

- Platform roles are separate from organization roles.
- mTLS is verified from the authenticated TLS socket, with a valid certificate
  window, pinned SHA-256 fingerprint, and expected SPIFFE URI.
- Workload identity comes from a deployment-owned verifier and is bound to the
  expected workload ID, audience, operation, and mTLS fingerprint.
- Recent WebAuthn is durable, exact-member/operation bound, consumed once, and
  within the five-minute age and thirty-second future-skew bounds.
- Missing verifier wiring never falls back to organization authentication.
- Route absence is `404`; an installed route with unavailable auth dependencies
  is `503`; invalid credentials are `401`; insufficient platform role is `403`.
- Public responses and evidence contain no secret, private key, assertion,
  provider response, database URL, or credential value.

## Qualification matrix

| Lane | Required evidence | Failure cases |
| --- | --- | --- |
| Static/config | Secret-free preflight passes | missing factor, evaluation profile, invalid RP binding, mTLS/workload mismatch, local fixture provider |
| mTLS | Protected ingress and application observe the same authenticated peer | plaintext, unauthorized/expired peer, wrong fingerprint/SPIFFE, forwarded-header spoof |
| Workload | Real verifier result is exact and audience/operation/fingerprint-bound | missing verifier, outage, wrong identity/audience, expiry, claim injection |
| WebAuthn | Real durable challenge is verified and consumed | missing proof, replay, stale/future proof, different member/operation/context, outage |
| HTTP contract | Two instances return bounded fail-closed status and secret-free bodies | unexpected route, `404`/`503` counted as success, organization fallback |
| Rotation | Old/new public identifiers, protected probes, revoke/drain evidence | in-flight pin replacement, old identity accepted, rebuild or secret reuse |
| Resilience | Response loss, restart, provider outage, DB failover, durable reconciliation | blind re-sign, duplicate promotion, lost uncertain state, disagreement |

Every instance evidence record includes its deployment digest and the exact
`source_commit` used by that instance. The instance `source_commit` must equal
the report-level source commit; a current report cannot be assembled from
stale evidence produced by another source revision.

### Rotation and resilience evidence

The `rotation` and `resilience` scenario records retain `evidence_sha256` for
the existing report contract, but a passing or failing record is not accepted
from that digest alone. Each record also carries a typed scenario evidence
object with its own `instance`, `source_commit`, `source_tree`,
`deployment_digest`, `run_id`, `job_id`, timestamps, and ordered `checks`.
Every check records a stable `check_id`, typed `expected` value, typed
`result` value, and derived `status`. A check is `passed` only when its typed
expected and result values match; a scenario is `passed` only when every check
passes. The outer digest is recomputed from the canonical scenario evidence,
so changing a check or a binding without changing the digest fails closed.

The required rotation checks are old-identifier rejection, new-identifier
acceptance, in-flight draining, durable rotation state, and binding integrity.
The required resilience checks are response-loss reconciliation, restart
recovery, provider-outage fail-closed behavior, database-failover
reconciliation, and duplicate-operation prevention. These are typed records
from the injected production adapter; this module does not call AWS, an IdP,
or any provider SDK itself.

## Local command and evidence rule

```sh
npm run qualification:platform-auth-config
npm run qualification:platform-auth
npm run qualification:postgres-c3
npm test -- --test-name-pattern='Platform|platform-auth|C3'
```

The three qualification commands are fail-closed: without the hosted
deployment or a real PostgreSQL URL they emit `not_run` rather than claiming
success. The result proves metadata validation only. Mark it `local`, never
`qualified` or `production`, and do not use it to waive protected ingress,
real workload provider, real PostgreSQL, durable WebAuthn, KMS/provider,
rotation, or independent-review gates.

Protected external execution uses the adapter wrapper:

```sh
npm run qualification:platform-auth:external
```

It requires a non-local runner, an explicit `external` execution marker and a
`real_execution=true` marker, source/tree and both deployment digests, run/job
binding, an adapter module plus its SHA-256
(`AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_SHA256`), and an exclusive output
path. Missing adapter provenance or a failed/not-run report aborts without
writing qualification evidence.

The production evidence must also pass the source-bound release gate:

```sh
node scripts/release/ci-preflight.mjs platform-auth-qualification \
  platform-auth-qualification.json <40-char-source-sha> <40-char-source-tree> \
  <primary-64-char-deployment-digest> <secondary-64-char-deployment-digest> \
  <qualification-run-id> <qualification-job-id>
```

This rejects `not_run`, failed, unqualified, non-canonical, incomplete, or
source-mismatched evidence.

## Production exit gate

Accept the exact candidate and deployment configuration only when all lanes
pass with zero skips, both Cloud instances agree on the status contract,
rotation and response-loss evidence are retained, and independent secret
scans cover source, images, logs, and evidence. Otherwise record `not_run` or
`unverified` and keep release blocked.
# Protected release binding

Production release promotion requires these protected variables alongside the canonical evidence:

- `AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ID`
- `AGENTPASS_PLATFORM_AUTH_QUALIFICATION_JOB_ID`
- `AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST`
- `AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST`

The workflow derives the expected source tree from the release commit and checks source tree, source commit, both instance deployment digests, run ID, and job ID. The CLI requires every expected binding value; `not_run`, missing, non-canonical, or substituted evidence is rejected.
