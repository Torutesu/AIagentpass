# External qualification contract

This is the release-facing aggregate contract for evidence that must come from
an external runner. It is intentionally separate from local unit tests,
static SQL/source checks, provider mocks, browser emulation, and modeled
macOS behavior. The machine-readable contract is
[`external-qualification-evidence.schema.json`](./external-qualification-evidence.schema.json).

## Decision rule

`status: "passed"` and `qualified: true` are valid only when all five required
gates below contain a passed, source-bound, run-bound, artifact-bound
`external_runner` record. A missing gate, an extra gate, a failed check, a
`not_run` result, or a locally produced result is not a degraded pass; it is a
failed qualification decision.

The aggregate status is derived as follows:

| Aggregate status | Required meaning | `qualified` |
| --- | --- | --- |
| `passed` | Every required gate is `passed`; every check is `passed`; every execution is real and externally evidenced | `true` |
| `failed` | At least one external gate ran and failed, or evidence/binding/secret validation failed | `false` |
| `not_run` | At least one required gate has not executed on its required environment | `false` |

`qualified` is a derived field, not an operator assertion. The reason is
`null` only for a passed result. A local test suite may prove the contract
implementation, but it must never manufacture an external execution record.

## Required qualification matrix

| Gate | Required external environment | Minimum checks | Static/local result cannot prove |
| --- | --- | --- | --- |
| `github_actions` | The canonical GitHub Actions run for the exact protected source | terminal GitHub `status: completed`, `conclusion: success`, exact six lanes, per-job SHA/run/attempt binding | that GitHub actually executed the selected run or that an API response belongs to it |
| `postgresql` | Disposable real PostgreSQL 16 and PostgreSQL 17 instances | migration/catalog, role and RLS boundary, transaction/rollback, concurrency, version identity | server behavior, committed migration, real roles, or cross-version execution |
| `kms` | Real managed KMS/HSM provider with production IAM boundary | provider identity, exact key version, allow/deny IAM matrix, rotation/disable, response-loss reconciliation, canary sign/verify | provider IAM, non-exportability, key lifecycle, or provider outage behavior |
| `webauthn` | Real authenticator and deployed API/database path | challenge origin/RP binding, durable one-time consumption, replay rejection, stale/context rejection, outage fail-closed | hardware authenticator behavior, durable consumption, or deployed service races |
| `macos_hardware` | Protected macOS Apple Silicon and Intel/T2 hardware lanes | signed/notarized artifact, Secure Enclave/device identity, negative identity/entitlement cases, lifecycle and recovery | physical hardware, launchd/XPC boundaries, notarization ticket, or device-key non-exportability |

The PostgreSQL gate is one matrix gate but must retain independent 16 and 17
evidence. The macOS gate must retain both hardware classes. A single local
PostgreSQL version, simulator, fake KMS, software WebAuthn assertion, Linux
runner, or `macos-latest` static test is insufficient.

## Binding invariants

Every passed gate must bind to the same values in the aggregate `release`
object:

- repository, source commit, and independently obtained source tree;
- GitHub run ID and attempt, plus the qualifying job ID;
- canonical artifact SHA-256 and immutable evidence bytes; and
- start/completion timestamps and a non-secret external runner identity.

The producer must emit canonical JSON and only redacted, typed observations.
Credentials, private keys, WebAuthn assertions, bearer tokens, database URLs,
raw provider responses, and raw runner logs are forbidden in the evidence
artifact. Evidence is rejected if it is non-canonical, has unknown fields,
contains symlinks/hardlinks or opaque unscanned archives, or cannot be
recomputed from the uploaded bytes.

The schema cannot itself prove that an operator told the truth about
`real_execution`. The release gate must independently obtain the GitHub run,
job, artifact, commit/tree, and environment records and compare them to the
typed envelope. No signed claim or static fixture substitutes for that
independent lookup.

## Evidence layout

The external runner stores exactly these redacted outputs for the release
candidate:

```text
external-qualification/
  evidence.json                 # canonical aggregate envelope
  evidence.SHA256SUMS           # digest of evidence.json and retained members
  gates/
    github-actions.json
    postgresql-16.json
    postgresql-17.json
    kms.json
    webauthn.json
    macos-apple-silicon.json
    macos-intel-t2.json
```

The aggregate `evidence.json` references the child evidence by digest through
the typed check records. The artifact inventory is exact: missing or additional
files fail closed. The producer must not overwrite an existing evidence file
for a run; reruns receive a new run attempt and new artifact digest.

## Static-test boundary

The release/CI static tests are contract tests only. They must validate the
schema, matrix inventory, strict unknown-field rejection, and the negative
status cases. Their result must be reported as `static_only`; it must never be
copied into any gate's external execution record or used as `status: "passed"`.

For the current external state, absent evidence is represented as
`status: "not_run"`, `qualified: false`, with a stable reason such as
`external_runner_unavailable`. It is not acceptable to use `passed` with an
empty checks list, a fake run ID, a local runner ID, or a placeholder artifact
digest.

## Promotion stop conditions

Stop promotion and retain the evidence for review when any gate is missing,
`not_run`, failed, source/run/artifact mismatched, non-canonical, secret-scan
dirty, or produced outside the required environment. The release record must
state the unresolved gate and reason. Re-running static tests can confirm that
the contract remains intact, but cannot close an external qualification gap.

## Current checkout boundary

The repository's schema, verifier, and qualification producers are contract
implementation. They are not an external execution record. Unless the
protected runner has produced and independently verified
`external-qualification/evidence.json` and its exact child-gate inventory for
the same candidate, the aggregate state is `not_run`, `qualified: false`, and
promotion is `STOP`.
