# Release qualification evidence matrix

This matrix is a promotion handoff artifact for one exact release candidate.
It separates evidence that repository-only checks can establish from gates that
require protected credentials, Apple services, or physical hardware. A blank or
`not_proven` entry is a release blocker; it must not be converted to a pass by
simulated, ad-hoc, or unsigned evidence.

## Candidate identity

Record these values from the signed release manifest and use the same candidate
through every row:

| Field | Value |
| --- | --- |
| Version | ` ____________________ ` |
| Source commit | ` ____________________ ` |
| Source tree | ` ____________________ ` |
| Product artifact | ` ____________________ ` |
| Product SHA-256 | ` ____________________ ` |
| Release-key fingerprint | ` ____________________ ` |

The CI preflight is a required gate before protected credentials are used and
again before promotion. It fails closed when the checkout is dirty, the
manifest source commit/tree or product SHA-256 differs from the selected
candidate, any supplied gate document contains `not_proven`, or the workflow
is not a manual dispatch on canonical protected `main`. The preflight does
not create Apple evidence and does not turn offline evidence into a pass.

## Gate matrix

| Gate | Evidence required | Validation | Status |
| --- | --- | --- | --- |
| Manifest identity and detached signature | Canonical manifest, detached signature, public key, independently pinned fingerprint | `node scripts/release/verify-release.mjs MANIFEST SIGNATURE PUBLIC-KEY 'SHA256:PINNED'` | `not_proven` |
| Checksums and SBOM binding | Manifest-bound `SHA256SUMS` and SPDX 2.3 SBOM | Included in `verify-release.mjs` output: `checksums_bound: true`, `sbom_bound: true` | `not_proven` |
| macOS code-signing and package structure | Staged universal PKG, nested helper bundles, profiles, entitlements, designated requirements | `scripts/release/verify-macos-release.sh MANIFEST SIGNATURE PUBLIC-KEY 'SHA256:PINNED' 'TEAMID1234'` | `not_proven` |
| Apple notarization and stapled ticket | Accepted notarytool result plus successful stapler validation for the exact staged artifact | The macOS verifier must run `xcrun stapler validate` and Gatekeeper assessment; repository-only verification reports `apple_ticket_verified: false` | `not_proven` |
| Apple silicon Secure Enclave lane | Signed qualified report and evidence directory bound to the candidate digest | `node scripts/release/validate-hardware-qualification.mjs ...` | `not_proven` |
| Intel/T2 Secure Enclave lane | Separate signed qualified report and evidence directory bound to the same candidate digest | `node scripts/release/validate-hardware-qualification.mjs ...` | `not_proven` |
| Aggregate hardware promotion | Both lane reports, approved operator policy, and aggregate evidence for the same candidate | `node scripts/release/verify-hardware-qualification-set.mjs ...` | `not_proven` |
| Protected release environment | Manual protected job configuration with short-lived signing/notary credentials and no PR secret path | Review the protected workflow/environment configuration and record the run URL | `not_proven` |
| Dedicated Host/Child XPC identity gate | Candidate-bound closed projection with live audit-token digest, Child-specific requirement digest/evaluation, authenticated-XPC activation, and four denial-before-sign cases | `node scripts/release/xpc/verify-xpc-qualification.mjs XPC-EVIDENCE.json` | `not_proven` |
| CI release preflight binding | Clean checkout, exact source commit/tree, product candidate SHA-256, manual protected dispatch, and no PR credential path | `node scripts/release/ci-preflight.mjs ...` in `release-candidate.yml` and `promote-qualified-release.yml` | `not_proven` |

## Promotion rule

Promotion is permitted only when every row is `passed`, every artifact hash is
the same candidate hash, and the evidence files are retained with the release.
`not_proven` is the correct status when credentials or hardware are unavailable.
Do not write `accepted_stapled`, `qualified`, or `production` into a report
unless the corresponding external evidence has actually been collected and
validated. In particular, this repository artifact makes no notarization claim.

The CI preflight is a provenance and boundary check, not a substitute for the
Apple or hardware rows. Without real protected Apple credentials, accepted
notary output, stapler/Gatekeeper results, and both physical hardware lanes,
the release remains blocked as `not_proven`.

The A7/A8 aggregate boundary is checked by
[`scripts/release/verify-production-evidence.mjs`](../scripts/release/verify-production-evidence.mjs).
It requires an independently pinned bundle signature and candidate-bound KMS,
PostgreSQL, offline release, and protected macOS attestation inputs. Missing
inputs remain `not_proven`; offline evidence is never promoted to a production
pass by this repository-side validator.

## Operator record

| Field | Value |
| --- | --- |
| Operator | ` ____________________ ` |
| Review date (UTC) | ` ____________________ ` |
| Evidence bundle path | ` ____________________ ` |
| Blocking rows / follow-up | ` ____________________ ` |
