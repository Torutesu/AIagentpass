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

6. The Platform Auth companion lane has a protected runner and an explicit
   non-local `AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENVIRONMENT_ID`; an absent,
   local, or placeholder environment identity is a qualification failure.

If any prerequisite is unavailable, emit a `not_run` record with a stable
reason and stop. Do not emit a zero-check passed record.

For KMS, the provider identity projection is not sufficient on its own. Each
AWS/GCP identity must carry a signed `agentpass.kms-provider-identity-attestation`
bound to the qualification source/artifact/run/job, all KMS resources for that
provider, and a fresh challenge nonce. The protected runner pins the attestor
public-key fingerprint and rejects missing, expired, replayed, substituted, or
unknown-field attestations. Configure the attestor public-key map through the
protected `AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS` variable;
never put private attestor keys in repository variables or evidence. A runner
that cannot obtain this proof must return `not_run`, not a self-attested pass.

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

The release verifier must independently compare every KMS, PostgreSQL, and
WebAuthn gate's execution `source_commit`, `source_tree`, `run_id`,
`run_attempt`, `job_id`, and `artifact_sha256` to authoritative records. The
release artifact SHA-256 is a required verifier input; a GitHub archive digest
does not substitute for the product artifact digest. The verifier re-runs the
typed KMS matrix, PostgreSQL child/aggregate reduction, and WebAuthn check
digests from the retained bytes. It rejects unknown fields, status/`qualified`
contradictions, `not_run`, local/static execution kinds, missing
version/hardware lanes, and any cross-run or cross-candidate evidence.

The PostgreSQL reduction additionally requires distinct protected 16/17 child
lane identities and a separately identified aggregate controller. The
controller signature covers the exact source/tree/release artifact, both child
evidence digests, the aggregate bundle digest, and the qualification run/job
binding. A missing, reused, or unverifiable controller identity is fail-closed.

The same verifier validates the retained Platform Auth companion. It requires
a canonical passing report, two deployment-bound instances, an
`external_runner` execution projection, the qualification run attempt and
canonical CI run binding, and a known non-local runner/environment identity.
Missing or `not_run` Platform Auth evidence is rejected; it is never treated
as an optional empty artifact.

The repository provides the same reduction as a machine-readable command:

```sh
npm run qualification:external -- evidence.json binding.json > verified-evidence.json
```

The retained-artifact provenance verifier additionally requires the independent
product digest as `<release-artifact-sha256>`; it is not inferred from the
downloaded GitHub qualification archive digest.

`binding.json` must be independently collected from the candidate CI and
artifact records. It contains the exact repository, source commit/tree,
release artifact digest, CI run/attempt, and every gate's artifact digest and
job ID. Its exact top-level inventory is
`repository`, `source_commit`, `source_tree`, `release_artifact_sha256`,
`ci_run_id`, `ci_run_attempt`, `gate_artifacts`, and `gate_job_ids`; the two
gate maps must contain every external gate required by `ci-preflight`. The
verifier rejects a missing or substituted binding.

The protected promotion workflow consumes the same canonical files through
the repository variables `AGENTPASS_EXTERNAL_QUALIFICATION_EVIDENCE_JSON` and
`AGENTPASS_EXTERNAL_QUALIFICATION_BINDING_JSON`. Before invoking the
verifier, promotion compares the binding's repository, source commit, source
tree, release artifact digest, CI run ID, and CI run attempt with the
authoritative candidate and GitHub API results. The aggregate verifier then
checks every gate's independent artifact/job binding and secret-scans the
retained outputs. Missing variables stop promotion; they are not treated as a
successful qualification.

Promotion also requires detached Ed25519 signatures for both evidence
envelopes. Configure these six protected repository variables:

```text
AGENTPASS_EXTERNAL_QUALIFICATION_SIGNATURE_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_FINGERPRINT
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_SIGNATURE_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_FINGERPRINT
AGENTPASS_EXTERNAL_QUALIFICATION_TRUST_MANIFEST_JSON
```

The aggregate signature covers canonical `{ evidence, binding }`; the child
signature covers canonical `{ evidence, binding, child_evidence }`. Public keys
must be Ed25519 PEM or SPKI DER after base64 decoding, signatures must be
64-byte base64 values, and fingerprints must be pinned as
`SHA256:<43-character-base64url-SPKI-digest>`. The protected toolchain verifies
the signatures before child digest reduction and retains the `.sig`, `.pub`,
and verification JSON outputs. These signatures authenticate supplied bytes
and candidate binding; they do not by themselves prove that a provider or
runner actually executed the qualification. Never store private keys in
repository variables, evidence JSON, or release artifacts.

The trust manifest is signed by the protected release-toolchain root and maps
the aggregate and child signer fingerprints to an authority and validity
window. The workflow verifies it against the root's `manifest.pub` before
accepting either evidence signature; changing the repository variables without
the toolchain root signature therefore fails closed.

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
Before either PostgreSQL lane invokes `pg_dump`, `pg_restore`, `psql`, or the
C3 client, it must invoke `npm run postgres:require-live-env` on that protected
runner. The preflight requires the source, restore, and PITR URLs to be
distinct non-loopback TLS `verify-full` endpoints, validates the CA file as a
private regular file, requires the `isolated-disposable` confirmations, and
binds the source commit/tree, canonical CI run/attempt/job, and migration
artifact digest. Its `not_proven` result exits nonzero and is not ignored by
the workflow; missing or unsafe target configuration therefore stops the lane
before a database command can run. The subsequent C3 step also sets
`AGENTPASS_C3_REQUIRE_REAL_DATABASE=1` and uses the same protected target/CA
configuration, so a test pool cannot be substituted for the external service.
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
