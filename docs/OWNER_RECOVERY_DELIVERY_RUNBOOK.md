# Owner-recovery delivery operations

This runbook covers the PostgreSQL-backed owner-recovery notification path at
schema version 36. It does not authorize a manual “mark delivered” operation.
Only an exact provider acceptance lookup may move an `uncertain` event to
`published`; an Owner/Admin may instead retry or suppress it after
resource-bound recent WebAuthn.

## Safe operating state

- every Cloud replica has the same binding ID, key version, random binding
  digest, delivery URL, confirmation URL, and protected authorization file;
- the provider durably commits the exact binding plus `Idempotency-Key` before
  returning delivery acceptance;
- the confirmation endpoint is linearizable over that acceptance ledger and
  echoes the exact binding and idempotency key;
- readiness is `ready`, worker state is `running`, and pending/uncertain/dead
  letter counts contain no tenant labels;
- notification URL, authorization value, body, provider response, DSN, member
  ID, and claim token never appear in logs, metrics, or retained evidence.

## Alert policy

| Signal | Warning | Critical | First action |
| --- | ---: | ---: | --- |
| `uncertain_count` | `> 0` for 2 minutes | `> 0` for 15 minutes | Check confirmation success/miss/failure counters and provider health. |
| `oldest_uncertain_age_ms` | `> 300000` | `> 900000` | Verify the confirmation endpoint is linearizable and reachable. |
| `dead_letter_count` | `> 0` | `> 10` or any row older than 24 hours | Review stable error category; do not inspect or copy credentials into notes. |
| pending age | `> 60000` | `> 900000` | Check worker state, PostgreSQL locks, and provider availability. |
| confirmation failures | 3 consecutive intervals | failure ratio `> 20%` for 10 minutes | Stop configuration rollout and compare non-secret binding versions. |
| claim loss/process interruption | sustained increase | increase plus growing uncertain age | Check worker restarts, lease/publish timeout relation, and drain behavior. |

Alert dimensions are fixed deployment/environment labels only. Organization,
member, request, event, destination, URL, and provider diagnostics are forbidden
labels.

## Provider outage or lost response

1. Keep the worker running. A timed-out or interrupted delivery becomes
   `uncertain`; it is not blindly resent.
2. Confirm the delivery and confirmation endpoints use the configured binding
   version. Do not change the tuple while old events are queued.
3. Inspect aggregate confirmation lookup/success/miss/failure counters and
   oldest uncertain age.
4. Restore the provider acceptance lookup first. A positive exact proof
   automatically converges the event to `published`.
5. If the provider cannot prove acceptance, an Owner/Admin may choose:
   - retry, which may send the original public event again under the same
     idempotency key and binding; or
   - suppress, which is terminal and records the operator audit transaction.
6. Never infer acceptance from email arrival, provider logs, screenshots, a
   support statement, or an HTTP timeout.

## Binding or credential rotation

1. Drain workers and stop new recovery creation for the maintenance window.
2. Resolve every old-binding pending/uncertain event by provider proof,
   explicit retry, or suppression. Existing events cannot be rebound.
3. Configure a new positive key version and new random 32-byte lowercase-hex
   digest on every replica. Rotate the provider account/destination and
   authorization file in the same deployment.
4. Deploy all replicas, verify exact schema/readiness, then resume traffic.
5. A mixed binding fleet is expected to fail closed: each worker claims only
   its exact tuple.

## PostgreSQL 16 reproduction

Use disposable databases. The 34→35 test intentionally requires a database
whose migration history has not already advanced past 34.

```bash
export AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:…@127.0.0.1:5432/agentpass_w15'
export AGENTPASS_W15_EVIDENCE_OUTPUT="$PWD/w15-evidence.json"
npm run test:postgres:w15

export AGENTPASS_TEST_DATABASE_URL='postgresql://postgres:…@127.0.0.1:5432/agentpass_w15_upgrade'
node --test apps/cloud-api/test/postgres/owner-recovery-delivery-binding-upgrade.integration.test.mjs
```

When `AGENTPASS_W15_EVIDENCE_OUTPUT` is set, the race-matrix test writes the
already-validated JSON with owner-only permissions. The required evidence is
limited to fixed scenario names, final state classes,
bounded counts/timings, public event digests, and non-secret binding IDs. Reject
the artifact if it contains a DSN, UUID identity, claim/authorization token,
notification content, URL, credential, provider body, or free-form diagnostic.

## Closure checks

- all six hard-`SIGKILL` boundaries converge after a distinct worker restart;
- provider acceptance count remains one after lost response and retry;
- automatic confirmation performs no notification publish call;
- stale delivery, management, and confirmation CAS operations fail;
- retry/suppress and prune/redrive races have one authoritative winner;
- no active lease remains and terminal retention never deletes `uncertain`;
- `npm run lint`, `npm run contracts:validate`, the full Node suite, and the
  PostgreSQL 16 W1.5 lane pass from the same commit.
