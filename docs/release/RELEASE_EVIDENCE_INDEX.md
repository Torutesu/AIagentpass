# Release evidence index

`release-evidence-index.mjs` is the final, provider-neutral completeness gate
for a release candidate. It is an index of immutable evidence files; it does
not manufacture evidence and it does not turn local or simulated results into
a pass.

## Required inventory

The index has exactly eleven evidence slots, in this order:

1. `release:candidate`
2. `qualification:aggregate`
3. `ci:canonical`
4. `external:aggregate`
5. `external:child`
6. `macos:apple_silicon`
7. `macos:intel_t2`
8. `staging:readiness`
9. `staging:rollback`
10. `deployment:cutover`
11. `operations_review:independent`

Each item contains a unique evidence-file name and SHA-256, a protected
`run_id`/`run_attempt`/`job_id` tuple, `status: "passed"`, `qualified: true`,
the exact `candidate_id`, source commit/tree, artifact digest, and bounded
`produced_at`/`expires_at` timestamps. Missing slots, duplicate names,
duplicate evidence digests, or reused run tuples are rejected.

The candidate object is the exact six-field identity:

```json
{
  "artifact_name": "AgentPass-v1.2.3-macos-universal.pkg",
  "artifact_sha256": "<64 lowercase hex characters>",
  "candidate_id": "release-pkg-sha256-v1-<artifact_sha256>",
  "release_manifest_sha256": "<64 lowercase hex characters>",
  "source_commit": "<40 lowercase hex characters>",
  "source_tree": "<40 lowercase hex characters>"
}
```

## Reviewer binding and expiry

The independent reviewer record must be bound to the same candidate/source/tree
and artifact. `reviewer.evidence_sha256` is the SHA-256 of the canonical JSON
encoding of the complete ordered `evidence` array, so replacing or removing a
single lane invalidates the review. The reviewer must be independent and the
review approval must be current and no more than 30 days long. Evidence records
use the same 30-day validity limit.

Any `not_proven`, `not_run`, failed, unqualified, local, mock, fixture, or
simulator marker is a hard failure. The verifier also rejects zero digests,
future timestamps, unknown fields, accessors, noncanonical JSON, and duplicate
JSON object members in the file-based CLI path.

## Verification

The release-candidate.yml workflow first derives the immutable candidate
identity from the exact signed release manifest and the downloaded product
PKG. It retains that canonical projection as
release-evidence-expected-candidate.json in the release-integrity-evidence
artifact. The release-preflight.yml workflow retrieves the exact successful
candidate run, independently recomputes the projection, and requires the
candidate slot's run_id/run_attempt to match that run before it invokes the
verifier. This prevents a source, tree, package, manifest, or workflow-run
substitution from being hidden by a copied index.

The protected promotion job supplies an independently derived candidate
identity. The index is verified against that identity rather than trusting the
candidate fields copied into the index:

```sh
node scripts/release/release-evidence-index.mjs verify \
  /secure/evidence/release-evidence-index.json \
  /secure/evidence/expected-candidate.json
```

Verification uses the verifier process's current UTC clock; callers cannot
backdate the expiry check. A successful command prints only a
bounded pass result and the index digest. Any failure exits with code `2` and
prints `status: "not_proven"` with a stable reason code. No private key,
credential, or raw evidence output is emitted.

The module API is also available to protected callers:

```js
import { verifyReleaseEvidenceIndex } from "./scripts/release/release-evidence-index.mjs";

verifyReleaseEvidenceIndex(index, {
  expectedCandidate,
  now: new Date()
});
```

This verifier proves the index contract and cross-record binding. It does not
replace the lane-specific qualification verifiers, an external runner, real
PostgreSQL/KMS/macOS execution, or an independent security review. Those
inputs remain `not_proven` until their protected evidence is actually supplied.

The production preflight obtains the index from the protected
AGENTPASS_RELEASE_EVIDENCE_INDEX_JSON environment variable. Its value must be
canonical JSON without a trailing newline; an absent, noncanonical, or
malformed value is a hard failure. Every evidence record must carry the exact
source commit/tree and artifact digest, and a unique nonzero
run_id/run_attempt/job_id tuple. The release candidate slot is additionally
bound to the exact successful release-candidate.yml run selected by preflight.

Before this index is promoted, `promote-qualified-release.yml` runs the
`production-readiness-gate.mjs verify` stage against the raw
`AGENTPASS_PRODUCTION_READINESS_EVIDENCE_JSON` bundle. The workflow derives the
candidate artifact digest, candidate ID, source commit, and independent source
tree from the signed manifest, exact product package, and selected workflow
runs; it compares every raw row and its run tuple with the protected
`AGENTPASS_PRODUCTION_READINESS_RUN_BINDINGS_JSON` map before invoking the
gate. Both inputs must be canonical JSON without a trailing newline. Missing,
unknown, duplicate, stale, `not_proven`, `not_run`, failed, or out-of-scope
run bindings fail closed, and no pull-request or local execution path receives
production credentials. The signed manifest and this index are reached only
after the raw bundle has passed this gate.
