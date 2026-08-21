# Offline release preflight

`scripts/release/validate-release-evidence.mjs` validates one exact macOS
universal PKG candidate without contacting Apple and without reading signing or
notarization credentials. It is deliberately an evidence validator, not a
replacement for the protected macOS release job.

```sh
node scripts/release/validate-release-evidence.mjs \
  release-preflight-evidence.json \
  release-staging-directory
```

The input must conform to
`scripts/release/release-preflight-evidence.schema.json`. Every object is
closed (`additionalProperties: false`) and every referenced file is a basename
inside the supplied root. The validator opens each file with `O_NOFOLLOW`,
requires a single-link regular file, and checks its size and SHA-256 while
checking the file identity before and after the read.

The evidence bundle binds all five release-critical identities to the same
candidate SHA-256:

| Evidence | Required proof | Offline result |
| --- | --- | --- |
| Candidate PKG | Actual bytes match `candidate.artifact_sha256` and the manifest product | `candidate_sha256` |
| Release signature | Ed25519 detached signature verifies the canonical manifest and pinned public-key fingerprint matches | `signature_verified: true` |
| Notary ticket | Accepted notarytool submission ID plus a typed candidate-bound ticket record | `ticket_evidence_bound: true` |
| Staple | Typed validation record says the ticket is present for the candidate | `staple_evidence_bound: true` |
| Gatekeeper | Typed install assessment record says the candidate was accepted | `gatekeeper_evidence_bound: true` |

The notary result is the raw `notarytool --output-format json` file. The ticket,
staple, and Gatekeeper files are small canonical JSON projections emitted by a
credentialed macOS job only after its corresponding command succeeds. They must
contain the exact candidate digest; a status string in the preflight document
alone is never sufficient.

The command exits non-zero for missing, changed, malformed, unbound, or
unknown evidence. A successful offline validation reports
`status: "validated_offline"`, never a release `passed` status, and intentionally reports
`apple_ticket_verified: false`, `gatekeeper_verified: false`, and
`promotion_ready: false`: it did not run `xcrun stapler validate`, Gatekeeper,
or the protected release workflow. Therefore it cannot turn a repository-only
record into a production claim.

## Credential and identity preflight

The protected signing job runs the following before importing a certificate or
notary key:

```sh
scripts/release/require-credentials.sh
```

This gate requires all signing, profile, manifest-key, and App Store Connect
inputs. It accepts only `Developer ID Application` and `Developer ID Installer`
identities whose Team ID matches `AGENTPASS_TEAM_ID`; ad-hoc and development
identities fail closed. Missing or malformed inputs exit non-zero without
calling `codesign`, `xcrun`, `stapler`, or `spctl`.

For local contract validation without credentials, use:

```sh
scripts/release/require-credentials.sh --dry-run
```

This command returns `dry_run_not_proven` and exits successfully only to report
what was not attempted. It never proves that credentials, signing, notarization,
stapling, Gatekeeper, or production promotion succeeded. The protected workflow
never uses the dry-run flag.

## Current audit status

In this checkout, the release workflows implement the protected candidate,
notarization, hardware-qualification, and public GitHub Release promotion
boundaries. They do not prove those external gates locally, and no workflow in
`.github/workflows/cloud-production-qualification.yml` is the protected
`production-cloud` environment gate for the hosted Cloud/API production
environment. It does not deploy an image: the provider operator deploys the
exact digest, produces signed evidence, and then dispatches this gate. The
workflow downloads only HTTPS evidence and fails closed unless the deployment
attestation and independently signed AWS/GCP KMS report bind to the requested
commit and digest. `promote-qualified-release.yml` publishes a fully qualified
public release; it is not a Cloud deployment mechanism.

Therefore the current production status remains `not_proven` until a protected
macOS run supplies real Developer ID signatures, an Accepted notary submission,
a stapled ticket, Gatekeeper results, both physical hardware reports, and the
separately operated hosted deployment evidence. The Cloud API image workflow
(`.github/workflows/cloud-image.yml`) now creates an immutable GHCR image for
each exact commit, with provenance and SBOM attestations. It intentionally does
not choose an AWS/GCP deployment target or receive provider credentials.
The target operator must deploy the exact `sha256:` image digest and produce a
strict evidence JSON, then validate it with:

```sh
node scripts/ops/verify-cloud-deployment.mjs \
  cloud-deployment-evidence.json \
  deployment-attestation-public.pem \
  PINNED_PUBLIC_KEY_SHA256
```

The command requires the path to the pinned deployment-attestation public
key as its second argument and the exact SHA-256 fingerprint of that key as its
third argument. The evidence JSON contains an Ed25519 signature
over the exact canonical unsigned payload. The validator requires the
production service revision, full source commit, immutable image digest, and
an authenticated HTTPS `/health/ready` result. It does not contact the provider
and cannot turn an absent or fabricated provider record into proof. Ad-hoc artifacts, missing
credentials, offline-only evidence, or a green local test suite cannot close
these rows.

The final Cloud promotion gate cross-checks that signed deployment evidence
and the independently signed, production AWS/GCP KMS qualification report
refer to the exact same source commit and image digest:

```sh
node scripts/ops/verify-cloud-promotion.mjs \
  cloud-deployment-evidence.json deployment-attestation-public.pem \
  DEPLOYMENT_PUBLIC_KEY_SHA256 \
  signed-kms-qualification.json qualification-public.der \
  qualification-evidence-production-1
```

This command is provider-neutral and performs no deployment itself. It fails
closed unless both evidence chains verify and their commit/image bindings are
identical.

The live evidence producer is:

```sh
node scripts/ops/produce-cloud-deployment-evidence.mjs \
  https://api.example.com/health/ready FULL_SOURCE_SHA sha256:IMAGE_DIGEST \
  deployment-attestation-private.pem cloud-deployment-evidence.json
```

Set `AGENTPASS_CLOUD_HEALTH_AUTHORIZATION` to a short-lived Bearer credential
for that invocation; the producer sends it only to the HTTPS health endpoint
and never includes it in evidence.

The endpoint must return exactly `{"status":"ready","revision":...,"commit_sha":...,
"artifact_digest":"sha256:..."}`. The producer compares the endpoint's commit
and digest with the requested immutable release, signs the canonical evidence
with Ed25519, and creates the output file with exclusive creation and mode 0600.
It never treats a local fixture, a floating tag, or a health status without
deployment identity as evidence.

Before enabling the protected environment, operators must configure:

* `AGENTPASS_CLOUD_DEPLOYMENT_KEY_FINGERPRINT` and
  `AGENTPASS_CLOUD_DEPLOYMENT_PUBLIC_KEY_PEM` for the independently held
  deployment-attestation key;
* `AGENTPASS_KMS_TRUSTED_KEY_ID` and `AGENTPASS_KMS_PUBLIC_KEY_DER_B64` for the
  independently pinned production AWS/GCP KMS qualification signer;
* a provider deployment identity capable of deploying the exact GHCR digest,
  querying authenticated HTTPS `/health/ready`, and producing the signed
  evidence; and
* a protected GitHub `production-cloud` environment with required reviewers.

The workflow itself does not receive AWS/GCP credentials and cannot prove a
deployment merely because the image workflow passed. Real provider deployment,
health, KMS/IAM, and PostgreSQL qualification evidence remain prerequisites.

## Matrix relationship

This validator supports the candidate identity/signature and evidence-binding
rows in [`docs/RELEASE_QUALIFICATION_EVIDENCE_MATRIX.md`](../RELEASE_QUALIFICATION_EVIDENCE_MATRIX.md).
It does not mark the matrix's Apple notarization, macOS package/Gatekeeper, or
protected-environment rows as passed. The existing commands remain required:

```sh
node scripts/release/verify-release.mjs MANIFEST SIGNATURE PUBLIC-KEY 'SHA256:PINNED'
scripts/release/verify-macos-release.sh MANIFEST SIGNATURE PUBLIC-KEY \
  'SHA256:PINNED' 'TEAMID1234'
```

`verify-release.mjs` remains the full signed-manifest, checksum, SBOM, and
release-evidence verifier. `verify-macos-release.sh` remains the only path in
this release tooling that performs the live stapler, Gatekeeper, code-signing,
and package checks on macOS. Missing credentials or hardware must remain
`not_proven` in the matrix.
