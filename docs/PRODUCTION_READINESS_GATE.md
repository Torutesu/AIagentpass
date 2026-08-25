# Production readiness gate

`scripts/release/production-readiness-gate.mjs` is the final, independent
fail-closed gate for a production evidence envelope. It does not run tests,
contact a provider, or turn a local result into production evidence. It only
accepts evidence that was already produced by an external protected
environment and is bound to one release candidate.

## CLI

```sh
node scripts/release/production-readiness-gate.mjs verify \
  /absolute/path/to/production-readiness-gate.json
```

The input must be one canonical JSON document: object keys are sorted by the
repository canonical JSON encoder, there is no trailing newline, and duplicate
keys are rejected before parsing. The file must be an ordinary, single-link,
non-symlink regular file. On success the CLI emits a small summary containing
`production_ready: true`. On every failure it emits only a stable reason code
with `status: "not_proven"` to stderr and exits nonzero; input values and
evidence contents are never printed.

## Contract

The top-level object has exactly these fields:

```json
{
  "candidate": {
    "artifact_sha256": "<64 lowercase hex>",
    "candidate_id": "release-pkg-sha256-v1-<artifact_sha256>",
    "source_commit": "<40 lowercase hex>",
    "source_tree": "<40 lowercase hex>"
  },
  "evidence": [],
  "kind": "agentpass.production-readiness-gate",
  "reviewer": {},
  "schema_version": 1
}
```

`evidence` has exactly one row, in the policy-defined order, for every fixed
slot below. The caller cannot provide a reduced `required` list:

| kind | slot |
| --- | --- |
| `release` | `candidate` |
| `ci` | `canonical` |
| `qualification` | `aggregate` |
| `external` | `aggregate` |
| `postgresql` | `protected` |
| `kms` | `protected` |
| `webauthn` | `external` |
| `macos` | `apple_silicon` |
| `macos` | `intel_t2` |
| `staging` | `readiness` |
| `deployment` | `rollback` |

Each row has an exact closed schema. It must have `status: "passed"`,
`qualified: true`, a distinct evidence name, evidence digest and
`run_id/run_attempt/job_id` tuple, valid `produced_at` and `expires_at`, and
the same candidate ID, artifact digest, source commit and source tree as the
top-level candidate. Its validity window is at most 30 days and it must not be
expired at verification time.

The row's exact `provenance` object must be:

```json
{
  "environment": "production",
  "execution_class": "protected_external",
  "runner_class": "protected_runner | physical_hardware | managed_provider",
  "source": "external"
}
```

This deliberately excludes local, static, mock, fixture, sandbox, simulator,
emulator and fake evidence. Those markers are rejected even when they occur in
an otherwise plausible name or provenance value. Unknown fields are rejected;
the gate has no permissive extension field.

## Independent review

`reviewer` is an exact object containing the reviewer identity, report digest,
the candidate bindings, `independent: true`, and a digest of the complete
canonical evidence array. The reviewer ID cannot equal an evidence job ID or
evidence name. Its review time and expiry are checked using the same current
clock and 30-day maximum window. A missing, expired, self-associated,
candidate-mismatched, or evidence-mismatched review is `not_proven`.

This envelope gate does not claim that a digest is a cryptographic signature;
signature and protected-runner trust remain separate qualification gates. The
reviewer report must therefore be retained and independently verified by the
release process before this document is used as a production decision.

## Failure policy

The gate rejects malformed or ambiguous JSON, duplicate keys, unknown fields,
missing or duplicate required rows, `open`, `not_proven`, `not_run`, `failed` or
`skipped` statuses, expired evidence, future evidence, overlong validity,
candidate/source/tree/artifact/run binding mismatches, duplicate run tuples,
non-production provenance, and insufficient independent review. It returns
`production_ready: true` only after every fixed row and the independent review
pass all checks. A local/static/mock/fixture/sandbox result can never be
converted into a production pass by this CLI.
