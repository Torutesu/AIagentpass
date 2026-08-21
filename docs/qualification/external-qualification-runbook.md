# External qualification runbook

This runbook describes how a release owner obtains evidence for the aggregate
[external qualification contract](./external-qualification-contract.md). It
does not claim that any runner, cloud account, database, authenticator, or Mac
is available. Do not replace a missing execution with a fixture.

## 1. Freeze the candidate

Record the candidate's exact repository, commit SHA, commit tree SHA, and
release artifact digest. Obtain the tree SHA independently from the GitHub
commit API or an equivalently authoritative protected source. Record the
canonical CI run ID and attempt only after the protected-source API reports
terminal `status: completed` with `conclusion: success`.

The candidate is not eligible for aggregate qualification until all evidence
uses those same bindings. A rerun changes the run attempt and must produce a
new evidence artifact.

## 2. Provision the external lanes

Use isolated, disposable environments and the least-privileged identities
needed for the probe. The runner must keep secrets in its secret manager and
must emit only the schema's typed projections. Before execution, verify:

1. GitHub Actions can query the exact run, every expected job, and every
   artifact without accepting caller-supplied status as proof.
2. PostgreSQL 16 and 17 are separate disposable instances/databases, with the
   migration and role contract applied by the approved runner.
3. KMS/HSM is the real configured provider and the key version and IAM
   principals are pinned by deployment configuration.
4. WebAuthn uses the real authenticator, deployed origin/RP configuration, and
   the real durable API/database path.
5. macOS lanes are the protected Apple Silicon and Intel/T2 classes, with the
   signed/notarized candidate and the approved device/operator policy.

If any prerequisite is unavailable, emit a `not_run` record with a stable
reason and stop. Do not emit a zero-check passed record.

## 3. Execute and reduce

Run the complete matrix for the frozen candidate. Each child report records
only stable check IDs, typed expected/observed values, redacted environment
identity, timestamps, and a digest of retained evidence. It must not include
credentials, private keys, assertions, bearer tokens, connection URLs, raw
provider output, or unbounded logs.

The reduction rules are strict:

- a check is `passed` only when the external probe observed the expected value;
- an exception, timeout, partial run, missing child report, or uncertain
  response is `failed` or `not_run`, according to whether the probe actually
  executed;
- a gate is `passed` only when every one of its required checks passed;
- aggregate `passed` is possible only when all five gates passed; and
- `qualified:true` is never accepted as an independent operator input.

## 4. Seal and verify evidence

Write canonical `evidence.json` and the exact child evidence inventory under a
new run-specific directory. Compute the SHA-256 digest from the bytes that
will be uploaded. Verify the JSON Schema, canonical serialization, exact file
inventory, regular single-link files, and secret scan before upload. Verify
again after download from the external artifact store.

The release verifier must independently compare every gate's execution
`source_commit`, `source_tree`, `run_id`, `run_attempt`, `job_id`, and
`artifact_sha256` to authoritative records. It must reject unknown fields,
status/`qualified` contradictions, `not_run`, local/static execution kinds,
missing version/hardware lanes, and any cross-run or cross-candidate evidence.

The repository provides the same reduction as a machine-readable command:

```sh
npm run qualification:external -- evidence.json binding.json > verified-evidence.json
```

`binding.json` must be independently collected from the candidate CI and
artifact records. It contains the exact repository, source commit/tree,
release artifact digest, CI run/attempt, and every gate's artifact digest and
job ID. The verifier rejects a missing or substituted binding.

The protected promotion workflow consumes the same canonical files through
the repository variables `AGENTPASS_EXTERNAL_QUALIFICATION_EVIDENCE_JSON` and
`AGENTPASS_EXTERNAL_QUALIFICATION_BINDING_JSON`. Before invoking the
verifier, promotion compares the binding's repository, source commit, source
tree, release artifact digest, CI run ID, and CI run attempt with the
authoritative candidate and GitHub API results. The aggregate verifier then
checks every gate's independent artifact/job binding and secret-scans the
retained outputs. Missing variables stop promotion; they are not treated as a
successful qualification.

## Repository runner workflow

The repository also provides `.github/workflows/external-qualification-runners.yml`.
Dispatch it with the exact successful canonical CI run ID and attempt in
addition to the source commit and release artifact digest. The workflow
independently checks that run's source SHA, terminal success, and attempt before
starting any protected external lane; its own workflow run ID is retained only
as the external execution container, while evidence `run_id` remains bound to
the canonical CI run used by promotion.
Its PostgreSQL 16 and 17 jobs emit per-instance child evidence through
`npm run qualification:postgres-c3:external`. Each child binds the release
artifact separately from the migration SQL digest used by the C3 verifier;
the two child reports must be combined into the single aggregate `postgresql`
gate. A child report is not itself the aggregate gate and must not invent a
passing result for the other PostgreSQL major.
It is a separate manual workflow and does not alter the canonical six CI
lanes. Its first job obtains the source tree from the GitHub commit API and
rejects non-SHA inputs. The KMS, Platform Auth, and production WebAuthn jobs
then run only on their protected self-hosted labels, require adapter-module
SHA-256 bindings, run the typed external wrappers, verify the source/run/job/
deployment bindings, and secret-scan the child evidence before upload. The
WebAuthn job uses the production adapter path; the deterministic route harness
remains outside this external gate. The uploaded child evidence is
an input to the aggregate reduction. The `postgres-gate` job recomputes a
sealed child bundle digest and emits `postgres-gate.json` with the exact five
PostgreSQL checks; the bundle digest is distinct from both the release PKG
digest and the migration SQL digest. Completion of this workflow alone is not
an aggregate five-gate pass.

## 5. Record the decision

Publish the aggregate envelope and redacted child evidence only after the
verification step. If any check is unresolved, retain `status: "failed"` or
`status: "not_run"`, record the stable reason, and stop release promotion.
The phrase “static tests passed” is not an external qualification result.

The minimum handoff contains:

- aggregate evidence and its SHA-256;
- exact external runner/run/job/attempt identifiers;
- authoritative source commit/tree lookup result;
- exact artifact inventory and post-upload digest check;
- per-gate check counts and failure/not-run reasons; and
- the verifier output identifying the candidate and all five gates.

## 6. Rerun and incident handling

Never edit a sealed evidence file. On a provider outage, lost response,
database reset, authenticator failure, or hardware interruption, keep the
failed/not-run record, preserve the redacted diagnostics, and create a new
run attempt after remediation. Revalidate the entire matrix; do not carry
forward a previously passing gate from another source, deployment, run, or
hardware class.
