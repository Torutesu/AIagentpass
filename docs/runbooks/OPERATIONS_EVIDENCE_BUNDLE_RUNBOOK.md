# Operations evidence bundle verification

The readiness envelope and the operations evidence bundle are separate gates.
`operations-readiness.mjs` performs a candidate/source/artifact-bound
operational check; its `structure_verified` result is not external
qualification. A checklist that declares `protected_external` or `verified`
does not prove that a protected runner executed the checks. Missing on-call,
retention, revoke, rollback-owner, reviewer-separation, kill-switch, expiry,
or binding input fails closed.

The qualification gate must verify the signed operations archive and its
independent qualification record together:

```sh
node scripts/ops/operations-readiness.mjs verify \
  /secure/evidence/operations-readiness.json \
  release-pkg-sha256-v1-<64-hex> <40-or-64-hex-source-commit> \
  /secure/evidence/operations/index.json \
  /secure/evidence/operations \
  sha256:<64-hex-image> \
  /secure/keys/operations-evidence-public.pem <64-hex-self-attested-key-fingerprint> \
  /secure/evidence/operations-qualification.json \
  /secure/keys/operations-qualification-public.pem <64-hex-qualification-key-fingerprint>
```

The command succeeds only when both the readiness envelope and
`verify-operations-evidence-bundle.mjs` succeed. The archive verifier requires
exact candidate/source/image bindings, canonical regular files, complete child
coverage, recomputed child digests, true semantic assertions, and an Ed25519
signature. It then requires a separate canonical qualification record signed
by a different Ed25519 key, with an independent protected-runner witness and
all five `independent_external` qualified measurements bound to the archive.

The lower-level archive result is deliberately `structure_verified` and has
`qualification_required: true`. Only the full result containing both
`readiness_status: "structure_verified"` and
`qualification_status: "independently_qualified"` is a successful local
verification of the supplied packet. This still does not fabricate or replace
the real runner, database/PITR, provider, fleet, alert receiver, or deployment
execution. If those records were not collected from the protected systems,
the operational gate remains `not_proven`.

Missing qualification files, reused keys, local/fixture runner identifiers,
stale or substituted bindings, changed archive bytes, extra files, and missing
measurements are stop conditions. Preserve the failed evidence and collect a
new record; do not edit a failed JSON file into a pass.
