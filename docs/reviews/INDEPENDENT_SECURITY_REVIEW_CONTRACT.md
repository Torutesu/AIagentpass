# Independent security-review contract (schema v2)

## Status of this repository

`not_proven` — this checkout contains the verifier, documentation, and adversarial
tests for the review gate. It does not contain a claim that a real third-party
security review was commissioned or completed. Local test output is implementation
evidence only.

## What a production decision must prove

A production decision needs both:

1. an operations bundle with an independently signed protected-runner
   qualification; and
2. a separately signed security-review record from an expected external reviewer,
   with no open critical/high findings and an unexpired validity window.

The operations bundle's self-attested signature is not a security review. An
operations qualification witness is not a security reviewer. A document named
`INDEPENDENT_SECURITY_REVIEW*.md` is not a signed third-party review record.

The verifier therefore returns `production_ready: false` for a structurally valid
operations bundle unless the production-only path receives the review record, its
protected public key, expected reviewer identity, expected source-tree digest, and
the separate reviewer fingerprint. Schema v2 additionally requires a protected
artifact digest, schema digest, signed retest evidence, and a second signed approval
from an approver separate from the reviewer.

## Reviewer identity and independence

The protected verifier configuration supplies `expectedReviewerId`,
`expectedReviewerOrganization`, and `expectedSecurityReviewFingerprint`. The signed
record must contain exactly the same values and must identify itself as
`independent_external` / `security_reviewer`. The reviewer key must differ from both
the operations self-attestation key and the operations qualification key.

The record also contains an `approval` object with protected expected approver ID,
organization, and Ed25519 fingerprint. Its decision must be `approved`, its
signature covers the complete review statement, and its approver identity and key
must differ from the reviewer, self-attestation, and qualification identities. A
field claiming separation without this second signature is not sufficient.

This is an identity and key-separation contract, not a magical proof of human
independence. Operator provisioning, organization ownership, conflict-of-interest
checks, and the actual review engagement remain external controls and must be
retained as protected evidence before approval.

## Review lifetime

The record must contain `started_at`, `completed_at`, `expires_at`, and
`retest_evidence` in canonical UTC format. The record is schema version `2`, and
`schema_digest` must equal the verifier's digest for the exact root, reviewer,
findings, retest, approval, and signature key sets. Unknown or missing fields fail
closed.

`retest_evidence` must contain exactly `status`, `completed_at`, and
`evidence_sha256`; status must be `passed`, and its SHA-256 digest must be present.
The retest completion must fall between review start and completion. This remains
required when critical/high findings are zero; a plan or `not_proven` marker is not
a retest. The record is valid only while:

```text
started_at <= retest_evidence.completed_at <= completed_at < now < expires_at
```

The verifier rejects an expired record, a future completion time, a missing expiry,
or a validity window longer than 90 days. A renewal creates a new signed record; the
old record is immutable and retained for audit.

## Binding contract

The signed review bytes bind the reviewer decision to:

- candidate ID;
- source commit and full source-tree SHA-256;
- release artifact digest;
- deployed image digest;
- canonical operations index digest; and
- canonical operations qualification-record digest.

The verifier compares those values with protected expected inputs and recomputes the
two evidence digests. This prevents replay of a review for another candidate,
another tree, another artifact or image, or a later-mutated operations archive.

## Minimum negative matrix

The dedicated test must keep the following cases covered:

- no review record / no review key;
- `self_attested`, local, mock, fixture, or internal reviewer identity;
- static-analysis-only, `not_reviewed`, or `not_proven` status;
- reviewer ID or organization substitution;
- reuse of either existing operations trust key;
- reviewer/approver identity or signing-key reuse;
- missing or substituted artifact/schema digest;
- missing, failed, stale, or `not_proven` retest evidence;
- missing or invalid second approval signature;
- expired or overlong review window;
- `not_reviewed` / pending status;
- non-zero critical/high/open-critical-high findings;
- candidate, commit, source-tree, artifact, image, index, or qualification digest substitution;
- changed canonical bytes, signature, symlink, hard link, or extra evidence file.

No case in this matrix is evidence that the corresponding real-world attack was
executed against a production deployment. It is a local fail-closed contract test.
