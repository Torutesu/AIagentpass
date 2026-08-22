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
- Provider identity is not accepted from an adapter's plain metadata alone.
  Each provider must return a signed `agentpass.kms-provider-identity-attestation`
  over the exact run binding, provider account/project, workload identity,
  region, and complete expected resource ID set. The protected
  `AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST` map pins the
  provider attestor public key, fingerprint, and key ID. Nonce replay,
  resource substitution, attestor-key substitution, expired proof, and
  cross-run proof are rejected before IAM or scenario qualification.

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
path. It also requires the protected
`AGENTPASS_KMS_QUALIFICATION_EXPECTED_BINDINGS` resource allowlist and
`AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST` attestor map. It
rejects `not_run` and failed reports and verifies the canonical report before
writing it. The adapter owns SDK, workload identity, IAM, and KMS calls; raw
credentials and provider responses never enter the report.

This local lane proves contract and evidence handling. It does not qualify AWS,
GCP, IAM, workload identity, HSM non-exportability, or production PostgreSQL
until an independently controlled environment supplies the injected probes and
retains the corresponding redacted evidence.

The focused local tests intentionally use dependency injection and synthetic
public metadata plus generated attestation keys. They do not verify that a real AWS KMS or GCP Cloud KMS key
exists, that workload identity/IAM policy is deployed as expected, that HSM
export is impossible, that rotation/disable was executed in the provider
account, that an ambiguous provider request was reconciled in production, or
that the two PostgreSQL instances are real and independently operated. Those
external gates remain required and are never inferred from a green local test.

## Cloud production qualification workflow contract

`.github/workflows/cloud-production-qualification.yml` consumes two distinct
KMS evidence layers and must not treat either one as a substitute for the
other:

1. The signed hosted-KMS report is verified by
   `verify-cloud-promotion.mjs` with the independently pinned production KMS
   public key. Its source commit and image digest must match the signed
   deployment evidence.
2. The canonical Cloud signer v2 report is verified with
   `ci-preflight.mjs kms-qualification`. The workflow supplies the exact
   source tree, deployment digest, artifact SHA-256, external qualification
   run ID, and `kms` job ID. `not_run`, failed, unqualified, non-canonical, or
   substituted reports terminate the job.

Before accepting the v2 report, the workflow queries GitHub for the exact
external run and job. It requires the canonical repository, the
`External qualification runners` workflow path, a successful completed
`workflow_dispatch` on `main`, the requested source commit and run attempt,
and one successful `kms` job with the requested job ID. This prevents a URL
or a report field from being used as the only run provenance.

The workflow also derives the exact external artifact name from the source
commit, run ID, and run attempt. It requires one live artifact from that run,
validates the canonical GitHub archive URL, recomputes the archive digest,
extracts exactly one regular `kms-qualification.json` entry, and compares its
bytes with the HTTPS evidence URL. A successful run/job with a different
artifact or a different URL therefore cannot satisfy this gate.

The workflow also re-verifies every provider identity attestation using the
protected `AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST` map. It
recomputes the nonce and binding digest, checks provider/account/region and
the complete resource set, verifies the Ed25519 signature and validity
window, and checks the attestor response digest against the identity record.
The protected canonical `AGENTPASS_KMS_QUALIFICATION_EXPECTED_BINDINGS` map
is an additional authority: every purpose, provider resource, key ID/version,
public-key fingerprint, account/project, workload identity, identity
fingerprint, and region must match it. The evidence cannot define its own
qualification target.
The deployment-attestation key, hosted-KMS qualification key, and provider
identity-attestor keys must be distinct. Public-key material is never
accepted solely because it was embedded in downloaded evidence.

The uploaded qualification artifact retains the canonical v2 report, both
verification results, and a closed `qualification-binding.json` containing
source, tree, image, deployment, evidence-archive, artifact, run, attempt,
and job identities.
The complete artifact is secret-scanned before upload. Absence of protected
trust, run/job evidence, or any required binding is an error; it is never
represented as a successful `not_proven` or `not_run` qualification.
# Protected release binding

Release signing requires all of the following protected environment variables in addition to the canonical JSON evidence:

- `AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST`
- `AGENTPASS_KMS_QUALIFICATION_RUN_ID`
- `AGENTPASS_KMS_QUALIFICATION_JOB_ID`

The release workflow derives the expected source tree from the tagged commit and verifies deployment digest, source tree, run ID, and job ID before accepting `passed` evidence. The CLI requires all five expected binding values; omission is not an opt-out. Missing or mismatched values fail closed.
