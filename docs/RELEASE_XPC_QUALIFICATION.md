# Host/Child XPC release qualification gate

This is one bounded, candidate-bound release gate for the dedicated Host/Child
XPC boundary. It does not change the native implementation and it does not
turn unit or synthetic evidence into macOS qualification.

Validate an evidence document with:

```sh
node scripts/release/xpc/verify-xpc-qualification.mjs XPC-EVIDENCE.json
```

This evidence contract is schema version 3. Older projections without the
complete release binding and external execution record are rejected.

The top-level `binding` is closed and must contain `candidate_sha256`,
`source_commit`, `source_tree`, `artifact_sha256`, `run_id`, `run_attempt`, and
`job_id`. The same values are required in the execution, launch observation,
and Child requirement records. Each of those records also carries the
SHA-256 digest of the canonical binding object. A document that omits or
substitutes any source, tree, artifact, run, attempt, or job identity cannot
pass.

The closed projection must show authenticated-XPC Host activation; an explicit
`live_eight_field` audit-token capture marker with
`kernel_live_audit_token_t` as its source and its digest (never the raw token);
the observed Child process identity; and a `launch_observation` with
`mode: "launchd_mach_nsxpc"`, the fixed Mach services
`dev.agentpass.agent-host` and `dev.agentpass.child-git`, distinct positive Host
and Child PIDs, decimal process start-time values, `status: "passed"`, and
binding fields exactly equal to the release binding. This is the
machine-verifiable criterion that the evidence describes a real candidate
launch, not only a synthetic XPC projection.

It must also include a live Child-specific signed requirement evaluation for
the fixed `dev.agentpass.git-sign-xpc` principal whose digest equals the Host
activation record, plus four live denial-before-sign probes. Each denial must
report `sign_attempts: 0` for same-UID wrong Child, wrong Team, wrong
entitlement, and stale/reused audit-token cases.

The execution record must be `kind: "external_runner"`,
`environment: "protected_macos"`, `real_execution: true`, `status: "passed"`,
and use a protected GitHub Actions runner identity. `local`, `static`,
simulator, mock, sandbox, fixture, synthetic, `not_run`, and `not_proven`
markers are rejected before any production pass is returned.

The live evidence remains external: signed/notarized artifacts, protected
runner execution, launchd Mach services, real NSXPC audit-token extraction, and
actual Child-helper requirement evaluation on macOS. A passing validator only
proves that the submitted document is closed and internally bound. Until those
observations exist, the release-matrix row remains `not_proven`.
