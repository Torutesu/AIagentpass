# Cloud signer / KMS qualification

`scripts/qualification/cloud-signer-kms.mjs` is a provider-independent
qualification boundary. It does not import an AWS or Google SDK and it never
calls a KMS API. Cloud access, IAM evaluation, lifecycle operations, and the
PostgreSQL qualification are injected as probes by the separately controlled
qualification environment.

The runner is fail-closed:

- Unless `AGENTPASS_KMS_QUALIFICATION_ENABLED=true`, the result is
  `status: "not_run"`, `qualified: false`.
- Missing probes also produce `not_run`; a probe exception produces a typed
  `failed` result and never records the exception message.
- A successful run requires all eight frozen signer purposes, 64 ordered IAM
  cells (eight allows on the diagonal and 56 denies off-diagonal), 64 ordered
  purpose/scenario results, and two passing PostgreSQL instance records plus a
  passing resilience record.
- Every real provider scenario result is an exact typed envelope with
  `schema_version`, `kind`, purpose/key identity, key version, source commit,
  source tree, deployment digest, artifact digest, qualification run ID, job
  ID, scenario, status, and an allowlisted typed `details` record. The
  envelope binding must equal the aggregate report binding; a result copied
  from another deployment, source tree, run, job, artifact, purpose, or key
  version is rejected.
- The eight scenarios are `provider_contract`, `key_version_binding`,
  `rotation`, `disable`, `non_exportability`, `lifecycle_fence`,
  `response_loss_reconciliation`, and `canary_sign_verify`.
- Rotation evidence is typed: the new key version must be the bound version,
  the old version must remain verifiable, new signing must be enabled, old
  signing must be disabled, and the drain must complete. Disable evidence must
  show no post-disable reservation or provider call, signing disabled, and
  historical verification retained.
- Non-exportability evidence must include an export attempt that the provider
  rejected, `exportable: false`, and `private_material_observed: false`.
- Response-loss evidence must show zero blind retries, at least one provider
  call and lookup/reconciliation path, a durable uncertain transition, and a
  reconciled result. A deterministic Ed25519 output is not treated as proof
  that an ambiguous provider request was rejected.
- The PostgreSQL evidence must contain exactly two distinct instance records
  and typed resilience conditions proving restart recovery, failover recovery,
  response-loss reconciliation, one logical commit, durable uncertain state,
  and zero blind retries.

Probe return values are exact, small typed records. The scenario envelope is
`kind: "agentpass-cloud-signer-kms-provider-evidence"` and is validated before
its details enter the report. Provider SDK responses, signatures, private
material, credentials, diagnostics, and error messages are not copied into the
report. The verifier accepts either an object (which is normalized again) or
canonical JSON bytes; non-canonical bytes, extra fields, accessors, cycles,
incomplete matrices, key-version/deployment/source/tree/run/job substitutions,
and secret-like raw output are rejected.

`cloudSignerKmsQualificationSHA256()` produces the canonical report digest that
may be placed in the promotion-evidence v3 `qualification_report_digests`
array. The promotion-evidence v3 verifier remains the authority for the signed
deployment/approval envelope; this runner does not mint or validate that
envelope.

Release promotion must additionally pass the source-bound preflight gate:

```sh
npm run qualification:kms > evidence.json
node scripts/release/ci-preflight.mjs kms-qualification \
  evidence.json <40-char-source-sha> <40-char-source-tree> \
  <64-char-deployment-digest> <qualification-run-id> <qualification-job-id>
```

The gate rejects malformed, non-canonical, `not_run`, failed, unqualified, or
source-mismatched evidence. A local contract test or a `not_run` report cannot
be used as production qualification.

For a protected external run, use the adapter-loading wrapper:

```sh
npm run qualification:kms:external
```

It requires external execution mode, a non-local runner identity, all
source/tree/deployment/artifact/run/job bindings, an adapter module supplied
by the protected environment, its SHA-256
(`AGENTPASS_KMS_PROVIDER_ADAPTER_SHA256`), and an exclusive evidence output
path. It
rejects `not_run` and failed reports and verifies the canonical report before
writing it. The adapter owns SDK, workload identity, IAM, and KMS calls; raw
credentials and provider responses never enter the report.

This local lane proves contract and evidence handling. It does not qualify AWS,
GCP, IAM, workload identity, HSM non-exportability, or production PostgreSQL
until an independently controlled environment supplies the injected probes and
retains the corresponding redacted evidence.

The focused local tests intentionally use dependency injection and synthetic
public metadata. They do not verify that a real AWS KMS or GCP Cloud KMS key
exists, that workload identity/IAM policy is deployed as expected, that HSM
export is impossible, that rotation/disable was executed in the provider
account, that an ambiguous provider request was reconciled in production, or
that the two PostgreSQL instances are real and independently operated. Those
external gates remain required and are never inferred from a green local test.
# Protected release binding

Release signing requires all of the following protected environment variables in addition to the canonical JSON evidence:

- `AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST`
- `AGENTPASS_KMS_QUALIFICATION_RUN_ID`
- `AGENTPASS_KMS_QUALIFICATION_JOB_ID`

The release workflow derives the expected source tree from the tagged commit and verifies deployment digest, source tree, run ID, and job ID before accepting `passed` evidence. The CLI requires all five expected binding values; omission is not an opt-out. Missing or mismatched values fail closed.
