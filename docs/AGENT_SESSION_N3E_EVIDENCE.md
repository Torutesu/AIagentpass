# Agent session N3-E lane 3 evidence: secret and path leakage

Status: deterministic recovery/fault/leakage core implemented. Signed-daemon N3-E qualification is **not complete**.

This lane freezes the public leakage boundary for the process-bound Agent
session lifecycle. It covers the XPC start/status/close result DTOs, the
connection endpoint's error projection, and the service's Agent-session audit
adapter. The test is intentionally a source/contract test: it is a review gate
for the shape and wiring, not a substitute for an on-device XPC serialization
or restart qualification.

## Frozen boundary

The lifecycle result surfaces contain only the following categories:

| Surface | Allowed values |
| --- | --- |
| start response | UUID correlation IDs, fixed-width process/worktree SHA-256 digests, expiry timestamp, signature budget counter |
| status response | UUID session ID, closed status enum, expiry timestamp, maximum/used counters |
| close response | UUID session ID, fixed `closed` status, close timestamp |
| NSError | fixed domain, fixed numeric reason code, fixed localized message |
| audit adapter | bounded action/reason, UUID IDs, SHA-256 digests, control/authority/key generations, sequence/counter values |

The start request has one explicit carve-out: `proof` is an opaque, bounded,
one-time inbound handoff needed to activate a session. It is not a session
token, is not copied into a response, NSError, or audit record, and is not
accepted as a field of the result DTO. `challenge` is similarly confined to
the bootstrap handoff. A session `leaseID` and `sessionID` are UUID-shaped
opaque correlation identifiers; they are not bearer credentials.

The source contract rejects public fields/coding keys for raw paths, cwd,
argv/environment, PID, audit tokens, credentials, private keys, grants, and
bearer/session tokens. It also rejects widening the audit object beyond its
exact allowlist. The binding type feeding audit contains IDs, fixed-width
digests, and numeric authority generations only; raw OS paths remain
process-local to the observer.

## Evidence and commands

The new gate is:

```sh
node --test test/native-agent-session-leakage-requirement.test.mjs
```

It proves, from the current source contract, that:

1. start/status/close response fields and secure-coding keys match the frozen
   allowlists exactly;
2. the inbound start proof is the sole deliberate proof carrier and is absent
   from response construction;
3. the Agent endpoint maps coordinator failures to the closed
   `NativeAgentSessionDenialReason.nsError` projection without forwarding
   `NSError` diagnostics, request data, or OS errors;
4. the audit adapter emits the exact bounded key set, hashes the canonical
   evidence object, and sends only the resulting digest through the existing
   audit append boundary; and
5. `signGitCommit` still returns the fixed unavailable denial and has no signer
   call or private-key path.

The focused gate must be run from the repository root. The broader checks that
must accompany this evidence in CI are:

```sh
npm run lint
node --test test/native-client-authorization-requirement.test.mjs
swift test --package-path native/macos
npm run contracts:validate
npm run test:native-app
npm run test:native-installer-preservation
```

The first command is the authoritative evidence for this lane. The remaining
commands are integration/release gates and must be recorded with their actual
output for the commit under review; passing this static test alone is not
evidence that the full N3-E gate passed.

Recorded in this worktree on 2026-08-13:

```text
node --test test/native-agent-session-leakage-requirement.test.mjs
7 tests, 7 pass, 0 fail

npm run lint
exit 0

swift test --package-path native/macos
550 tests, 550 pass, 0 fail

npm test
1111 tests, 1083 pass, 28 environment-dependent skip, 0 fail

npm run contracts:validate
13 schemas, 2 OpenAPI documents, 5 fixtures, 22 PostgreSQL migrations validated

npm run test:native-app
AgentPass app bundle verification passed

npm run test:native-installer-preservation
installer preservation qualification passed; root-only postinstall positive path skipped

node --check test/native-agent-session-leakage-requirement.test.mjs
git diff --check -- test/native-agent-session-leakage-requirement.test.mjs docs/AGENT_SESSION_N3E_EVIDENCE.md
exit 0
```

The native deterministic gate additionally proves:

- durable consume recovery stores only the Grant proof digest, tenant/device/agent IDs,
  adapter kind, process/ancestry/worktree digests, authority generations, and a bounded expiry;
- a different bootstrap ID and issuance time after restart can recover only the same immutable
  Grant/authority tuple;
- Cloud commit followed by response loss converges on the same Cloud Session after a fresh
  coordinator, fresh bootstrap, fresh in-memory registry, and reloaded recovery file;
- no active local Session is reconstructed from disk;
- canonical state, capacity, expiry pruning, mode/link/tamper checks, atomic rename/fsync, and
  crash-remnant cleanup fail closed; and
- faults across connection, challenge, observation, Cloud ambiguity, clocks, registry, audit,
  response abort, boot change, and cross-connection access cannot publish usable authority.

Focused native commands:

```sh
swift test --package-path native/macos --filter NativeAgentSessionConsumeRecoveryStore
swift test --package-path native/macos --filter NativeAgentSessionCoordinator
```

## What this does not prove yet

The following physical or runtime gaps remain open and prevent an N3-E claim:

- real `NSXPCConnection` encode/decode tests on supported macOS versions;
- runtime inspection of every reply and `NSError.userInfo` produced by the
  signed daemon, including failure paths outside the coordinator;
- audit-file serialization, fsync failure, rotation, crash, and recovery
  tests proving that no transient proof, Grant, credential, path, PID, argv,
  or environment value is persisted;
- a real launchd-managed, signed daemon kill/restart at every activation boundary, especially
  after Cloud Grant commit but before local activation or before the reply; the deterministic
  object/process-reconstruction harness now proves the state-machine invariant, but not launchd,
  XPC transport, or filesystem behavior of the notarized candidate;
- sleep/wake, boot identity change, wall-clock rollback/advance, PID reuse,
  connection death, and worktree mutation tests on physical macOS hosts;
- process inspection of a real Agent launcher to verify that credentials,
  proof material, paths, and session authority do not enter argv, environment,
  shell history, temporary files, crash reports, or diagnostic logs; and
- independent security review and signed/notarized Apple-silicon/Intel
  qualification.

Accordingly this document records a **secret/path leakage source boundary**,
not production readiness. N4 signing remains disabled until the full N3-E
fault/restart gate and its physical evidence are complete.
