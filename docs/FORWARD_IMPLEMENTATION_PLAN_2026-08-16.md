# AgentPass forward implementation plan — 2026-08-16

Status: active

Source baseline: `codex/agent-platform` at committed `09eb561` (the last
clean contract/CI diagnostic slice inspected for this plan)

Execution checkpoint: the merge slice containing this plan also carries the
F1d/F1e native contract candidates (`AgentHostXPCProtocol.swift`, the private
Git session state machine, and `AgentSigningCapability.swift` plus
tests/vectors). They are implemented and locally verified, but are not a
qualified baseline until the resulting commit passes the exact-SHA CI gate.

This is the authoritative day-to-day plan after the native launch, child
supervision, and private Git transport primitives landed. Product and release
requirements remain defined by [`V1_EXECUTION_PLAN.md`](./V1_EXECUTION_PLAN.md).
Older checkpoint queues are historical context when they conflict with this
document.

## 0. Repository reality and execution rules

The repository is a mature security-boundary codebase, not an empty product
scaffold. The plan below must extend existing seams rather than introduce a
second authority model.

Current facts to preserve:

- `contracts/openapi/device-v1.json` already declares
  `POST /v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities`
  as `frozen-f1a`. Its body is only `{request_id}`; all authority fields are
  server-derived. The route is not yet wired into the production handler in
  `apps/cloud-api/src/agent-session-device-api.mjs`.
- `contracts/schemas/agent-signing-capability-v1.schema.json` and
  `contracts/schemas/agent-session-signing-capability-response-v1.schema.json`
  require tenant-bound, canonical, one-use signing material. The committed
  `09eb561` slice specifically binds `organization_id` and `issued_at` and
  caps `remaining_session_signatures` at one.
- Existing Cloud seams include the Grant/Lease lifecycle, capability
  reservation repository, signer-purpose registry, managed-signer provider
  operation adjudication, Device authentication, Human WebAuthn, and
  PostgreSQL migration/checksum enforcement. Reuse these seams; do not create
  a parallel session table, token format, or local signer fallback.
- The current PostgreSQL migration head is `0073_possession_receipt_control_trust.sql`.
  The next migration must be the next contiguous number and must update the
  catalog, schema-head tests, least-privilege checks, and integration fixtures
  in the same merge unit.
- Native has separate products for the service, manager/client, agent Host,
  onboarding, and helper tools in `native/macos/Package.swift`. The Host is a
  supervisor boundary; it is not the Agent and must not receive capability or
  key authority.
- `Formula/agentpass.rb` intentionally installs an evaluation JavaScript
  broker and marks the production XPC boundary unavailable. The signed
  native bundle produced by `native/macos/scripts/build-app.sh` is the
  production boundary. Keep this distinction visible in every user-facing
  status and release artifact.
- CI is split into `test`, `browser-e2e`, `p0b-live-process`,
  `postgres-integration`, and `postgres-authority-matrix`; PostgreSQL 16 and
  17 qualification is part of the integration matrix. A local macOS sandbox
  failure to bind a listener is not a substitute for CI evidence.

Execution rules:

1. Each slice below is one reviewable merge unit with one contract owner,
   bounded file scope, and a named exit gate. Do not mix a schema redesign,
   native transport rewrite, and release packaging in one PR.
2. Contract changes land before producer/consumer changes. The canonical
   schema, OpenAPI, catalog, Swift DTO, JavaScript validator, and vectors are
   one versioned set; generated or derived changes are checked in when the
   repository convention requires them.
3. Every database change is forward-only, contiguous, checksum-registered,
   transactionally applied, and tested on PostgreSQL 16 and 17. Application
   rollback is the rollback mechanism; authority history is never rewritten.
4. A provider response lost after an external sign is `outcome_unknown`.
   Retries are prohibited until durable reconciliation proves that no key use
   occurred or proves the exact completed result.
5. “Implemented” means source tests pass. “Qualified” additionally requires
   the protected CI, physical macOS, managed-provider, or staging evidence
   named by the relevant gate. These words must not be interchanged in status
   reports.

## 1. Outcome and current boundary

The v1 outcome is a clean-machine journey in which a human approves a bounded
Agent Session once, Claude Code makes two policy-compliant signed commits
without another human prompt, both signatures verify independently, and
revocation stops further key use. Cursor must reuse the same authority and
signing path. Private keys remain non-exportable and reusable Grant, Lease,
Capability, session, and authentication material never enters agent-visible
argv, environment, URLs, Git configuration, browser storage, logs, or files.

At this baseline the repository already has:

- PostgreSQL-backed Human, organization, Device, Agent Session, lifecycle,
  provider-operation, audit, and recovery foundations;
- strict Console BFF and UI implementations for organization, passkey, Human
  Session, device, control, recovery, and emergency workflows;
- a canonical one-use FD3 launch-authority handoff;
- a signed Host child-supervision primitive with fixed Claude Code adapter,
  directory-descriptor binding, executable qualification, process-group
  ownership, signal forwarding, and deterministic cleanup;
- a Host lifecycle coordinator that pins the XPC connection and activation,
  reobserves authority, and terminates the child on authority loss;
- one-shot private Git socketpair, frame, client, and server primitives;
- a durable native sign-once transaction that does not retry ambiguous key use;
- source-complete resumable onboarding through `control_acknowledged`.

It does not yet have a production end-to-end agent path:

- `agentpass launch` still returns `unavailable` after validation;
- the Host executable does not launch Claude Code in its normal command path;
- the private Git bridge is not wired to a real `git commit -S`;
- one socketpair currently permits one request, so it cannot support two
  commits in one approved session;
- the existing Agent XPC signing method observes the XPC peer, which would be
  the Host rather than the supervised Claude Code child;
- no Device-authenticated API issues the next one-use `git.commit.sign`
  Capability from an active Agent Session Lease without human WebAuthn;
- real managed-KMS, physical-Mac, Developer ID/notarization, staging, and
  independent-review evidence remains external and incomplete.

## 2. Non-negotiable implementation decisions

1. Claude Code, Cursor, Git, and the Git helper receive no Capability, Grant,
   Lease, key selector, algorithm selector, session bearer, or reusable socket
   path.
2. The signed Native Service, not the agent or Git helper, derives request ID,
   operation, session, scope, signing key purpose, Capability sequence, and
   budget consumption.
3. A Host-reported child PID is an observation hint only. The Native Service
   independently verifies PID version, ancestry, executable identity, code
   signature, worktree, repository identity, branch, and remote before every
   key-use boundary.
4. Host traffic uses a separate, code-requirement-gated XPC surface. It cannot
   reuse the existing direct-Agent method in a way that silently binds policy
   to the Host PID.
5. The multi-commit private transport uses message boundaries and explicit
   monotonically increasing request/response sequences. One outstanding
   request is allowed. Malformed, concurrent, replayed, skipped, or excess
   messages quarantine the transport.
6. The current one-shot bridge remains a tested primitive; it is not weakened
   to simulate a session. A new session protocol must be versioned explicitly.
7. A provider/key invocation followed by response loss becomes durable
   `outcome_unknown`. Neither Host, helper, CLI, nor Cloud may retry signing
   until the exact transaction is authoritatively reconciled.
8. Production Hosted mode has eight purpose-separated, immutable-version,
   non-exportable managed keys and no local/file/environment private-key
   fallback.
9. Direct download, Homebrew, physical qualification, and staging consume one
   identical signed/notarized PKG digest; no executor rebuilds it.

## 3. Dependency graph

```text
F0 exact-SHA CI baseline
  |
  +--> F1 contract/security freeze
          |
          +--> F2 Device signing-Capability API ----+
          |                                         |
          +--> F3 Host XPC + child binding ---------+--> F5 Git bridge integration
          |                                         |          |
          +--> F4 multi-request private transport --+          v
                                                           F6 lifecycle closure
                                                                  |
                                                           F7 Claude qualification
                                                                  |
                                               +------------------+------------------+
                                               v                                     v
                                      F8 Console/Cursor                    F9 release/provider
                                               +------------------+------------------+
                                                                  v
                                                        F10 production closure
```

F2 and F3/F4 may be implemented in parallel after F1. Managed-provider and
release preparation may proceed in parallel, but F7 cannot qualify against a
mock Capability issuer and F10 cannot promote without all protected evidence.

## 4. Merge-sized implementation packages

### F0 — close the exact-SHA CI baseline

Implementation:

- qualify the Console security E2E request against the current body/header
  contract: `If-Match` and idempotency are headers, not duplicated body fields;
- run the complete safe P0-B marker registry without retaining child output;
- use the resulting fixed marker to repair only the owning wake boundary;
- rerun root/native, browser, P0-B, PostgreSQL integration, PostgreSQL 16, and
  PostgreSQL 17 on one unreplaced SHA.

Evidence and exit gate:

- all six jobs are terminal green on one SHA;
- retained reports bind that SHA and pass secret scans;
- local sandbox listener restrictions are recorded as environment limitations,
  not counted as qualification or product failures.

### F1 — freeze the end-to-end authority contracts

Deliverables:

- a versioned Host XPC contract for prepare, child attach, payload-only sign,
  status, and close;
- an independently observed child-binding DTO containing only public digests,
  PID version, and bounded identity metadata;
- a versioned multi-request private Git frame with request sequence, response
  sequence, bounded payload/result, terminal close, and protocol-error classes;
- a Device API request/response schema for one-use signing Capability issuance;
- fixed two-commit budget semantics and stable `outcome_unknown`, revoked,
  expired, policy-drift, process-drift, and transport-quarantined errors;
- catalog, JSON Schema, OpenAPI, generated validator, Swift DTO, and canonical
  vector updates in one serialized contract series.

Required negatives:

- unknown/duplicate fields, duplicate JSON keys, noncanonical bytes, oversized
  frames, sequence replay/skip, caller-supplied scope/key/algorithm/TTL,
  downgrade, cross-protocol decoding, and secret-bearing public DTOs.

Exit gate: every producer and consumer validates the same canonical vectors;
the threat model confirms that no caller-controlled authority field was added.

### F2 — implement Device-authenticated signing-Capability issuance

Deliverables:

- `POST /v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities`;
- request body limited to a public request identity; operation, repository,
  worktree, agent, TTL, sequence, budget, Control generation, authority
  generation, and key purpose are server-derived;
- one PostgreSQL transaction that validates active Device and Agent Session,
  current generations, unrevoked authority, remaining budget, idempotency, and
  monotonic Capability sequence before reserving issuance;
- exact-byte managed-signer operation intent/result/uncertainty and replay
  reconciliation;
- a Native Service HTTP consumer using Device authentication, no bearer in
  argv/environment, bounded deadlines, no redirects, pinned contract parsing,
  and no raw provider diagnostics.

Primary boundaries:

- `apps/cloud-api/src/human-auth/agent-sessions/`
- `apps/cloud-api/src/postgres/`
- `contracts/openapi/` and `contracts/schemas/`
- `native/macos/Sources/AgentPassNativeCore/`

Required tests:

- no/invalid Device authentication, cross-tenant/device/agent/session,
  revoked/expired Lease, stale Control or authority generation, exhausted
  budget, request replay, idempotency conflict, concurrent issuance, wrong
  signer purpose/version, timeout, response loss, and signer uncertainty on
  PostgreSQL 16 and 17.

Exit gate: an active Lease can obtain exactly the next server-scoped one-use
Capability; every ambiguous result converges without duplicate signing.

### F3 — implement Host XPC and independently observed child binding

Deliverables:

- a Host-only exported interface gated by the frozen Host designated
  requirement and one authenticated XPC connection;
- prepare/attach ordering that rejects sign or status before child attachment;
- OS-backed observation of child PID version, parent/ancestry, executable inode
  and code identity, Team ID/designated requirement, cwd/worktree, repository
  and `.git` identity, branch, and remote;
- connection-owned session state; requests carry payload and sequence only;
- final reobservation before Capability acquisition, budget reservation, and
  Secure Enclave use;
- deterministic close on child exit, Host exit, XPC interruption, authority
  loss, or observation drift.

Required tests:

- untrusted Host, PID reuse, unrelated/escaped child, executable replacement,
  code-signature drift, worktree move, repository or `.git` substitution,
  branch/remote drift, sleep/wake, Service restart, concurrent attach, sign
  before attach, sign after close, and cleanup failure.

Exit gate: the Native Service proves the supervised child identity itself and
never treats the Host PID or Host-provided paths as Agent authority.

### F4 — implement a bounded multi-request private Git session

Deliverables:

- a message-preserving private transport, preferably an unnamed Unix
  `SOCK_SEQPACKET` socketpair after Darwin qualification;
- session client/server types separate from the one-shot primitive;
- monotonically increasing sequences, one outstanding request, maximum request
  count bound to the Lease budget, and terminal/quarantine state;
- a child-only endpoint installed at fixed FD3; activation FD3 is consumed and
  closed before child spawn; no sibling or unrelated descriptor inheritance;
- deterministic commit/abort ownership transfer around `posix_spawn`.

Required tests:

- two sequential requests, third request over budget, concurrent helpers,
  partial/malformed/oversized/trailing messages, sequence replay/skip, wrong
  response sequence, EOF, signer failure, child/Host termination, spawn failure,
  FD collision, FD leak scan, and no filesystem/TCP fallback.

Exit gate: two helper processes can safely share the approved session transport
without interleaving authority or leaving a reusable endpoint after close.

### F5 — wire CLI, Host, Claude Code, Git helper, and sign-once

Deliverables:

- replace the `agentpass launch` unavailable stub with a fixed-path signed Host
  launch using the one-use activation handoff;
- compose lifecycle coordinator, child supervisor, private session server, and
  Host XPC client in the production Host executable;
- configure Claude Code/Git to invoke a fixed `agentpass-git-sign` helper;
- make the helper read Git's bounded payload, exchange one private message,
  write the SSHSIG result, and exit; missing FD3 fails closed;
- route Host payload-only signing through F3, F2, and the existing durable
  sign-once transaction.

Required tests:

- real Git SSH signing vectors, `git commit -S`, `git verify-commit`, wrong
  repository/branch/remote, helper without Host/FD3, adapter or executable
  substitution, child and sibling denial, argv/environment/config/log/state
  secret scans, and no legacy broker fallback.

Exit gate: one supervised real commit verifies while the helper and Agent never
receive a Capability or authority selector.

### F6 — lifecycle, revocation, and ambiguous-outcome closure

Deliverables:

- production `launch`, `status`, `close`, `revoke`, `doctor`, and uninstall
  states backed by one Host/Service session lifecycle;
- durable public recovery evidence for pre-key retry, completed replay, and
  post-key `outcome_unknown` without persisting reusable authority;
- deterministic cleanup ordering for transport, child process, Agent Session,
  Capability reservation, workers, provider clients, and database pools;
- actionable Japanese and English remediation for unavailable, approval
  required, expired, revoked, process/worktree changed, budget exhausted, and
  unknown outcome.

Required tests:

- kill/restart before and after every durable transition, response loss before
  and after key use, exact completed replay, duplicate request/Capability,
  revocation and budget races, clock rollback/advance, stale key generation,
  emergency stop, network loss, and cleanup failure.

Exit gate: every interruption converges to a documented safe state and no
ambiguous operation can invoke the key twice.

### F7 — Claude Code clean-machine qualification

Deliverables and evidence:

- idempotent install/setup, Git configuration backup/restore, doctor, revoke,
  uninstall-preserve, and reinstall behavior;
- a clean user/repository run that creates two unattended commits after one
  approval and independently verifies both SSH signatures and audit links;
- third-sign budget denial and immediate revocation evidence;
- process list, argv, environment, shell history, repository, Git config,
  logs, crash reports, and durable-state secret scans.

Exit gate: two policy-bounded commits succeed without a second human prompt;
wrong context and post-revoke signing fail closed.

### F8 — non-engineer Console onboarding and Cursor parity

Deliverables:

- Console states for installation, browser-led enrollment, approval, policy
  preview, active session, activity, expiry, revoke, emergency stop, resume,
  and remediation;
- Cursor as a second fixed launcher using F1-F6 unchanged; no new XPC selector,
  signer path, key input, or authority field;
- CLI remains the headless installer/diagnostic path; the native onboarding UI
  stays optional and authority-free.

Required tests:

- Owner/Admin/Auditor/Viewer visibility and mutation matrix, operation-bound
  WebAuthn, response loss, stale state, keyboard, screen reader, focus restore,
  200% reflow, reduced motion, Japanese/English actions, browser storage and
  artifact scans, and Claude/Cursor parity.

Exit gate: a non-engineer can install, approve, understand, revoke, recover,
and uninstall without internal IDs or Cloud credentials.

### F9 — managed providers and immutable macOS distribution

Deliverables:

- eight distinct AWS/GCP KMS/HSM purposes with immutable key versions,
  fingerprints, algorithms, workload identities, rotation, drain, disable, and
  reconciliation workers;
- one universal hardened-runtime PKG with frozen bundle IDs, Team ID,
  designated requirements, entitlements, Mach services, and XPC selectors;
- nested Developer ID signatures, notarization, stapling, SBOM, provenance,
  direct-download metadata, and Homebrew formula pinned to one digest.

Evidence:

- provider IAM allow/deny, non-exportability, version/fingerprint binding,
  outage/throttle/timeout/response-loss, rotation and no-fallback reports;
- `codesign`, `spctl`, `pkgutil`, notarization/stapler, install/upgrade/
  uninstall/reinstall/rollback, Apple silicon Secure Enclave, Intel/T2, and
  channel digest equality.

Exit gate: both channels and hardware classes verify the same immutable PKG;
Hosted readiness cannot start with a local, shared, aliased, or stale signer.

### F10 — staging, independent review, and production promotion

Deliverables:

- immutable Console/API images, forward-only migrations, queues/workers,
  managed signer configuration, dashboards, SLOs, alerts, backup/PITR,
  emergency controls, tenant isolation, and incident runbooks in staging;
- migration/canary/drain/rollback, restore with measured RPO/RTO, database/KMS/
  network outage, compromise/rotation, revoke-latency, and tenant-isolation
  drills;
- SAST, DAST, dependency, container, IaC, SBOM/provenance, and independent
  security assessment findings tied to the exact source and artifact digest;
- independently verified promotion evidence and explicit human go/no-go.

Exit gate: no critical/high finding remains, SLO/RPO/RTO targets are met,
rollback is rehearsed, and production promotion names the exact source,
database migration head, images, PKG, and provider key versions.

## 4-A. Executable package ledger

This ledger turns F1-F10 into bounded work packages. File names are intended
targets; when a package discovers that an existing seam already owns the
responsibility, extend that seam and record the substitution in the PR rather
than creating a duplicate implementation.

### F1 — contract and security freeze

Package: `F1d-lifecycle-errors`, `F1e-capability-codec`, and
`F1f-threat-matrix`.

Dependencies: the committed F1a JSON Schema/OpenAPI/catalog changes in
`09eb561`; no Cloud, database, or external provider dependency.

Files and API surface:

- `native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift`
  defines prepare, attach, payload-only sign, status, and close with fixed
  two-signature semantics and no caller-selected authority fields.
- `native/macos/Sources/AgentPassNativeCore/NativeAgentPrivateGitSessionMessage.swift`
  and `NativeAgentPrivateGitSessionStateMachine.swift` define the versioned
  request/response/close frame, one outstanding request, EOF, and quarantine
  semantics. The existing one-shot bridge files remain unchanged primitives.
- `native/macos/Sources/AgentPassNativeCore/AgentSigningCapability.swift`
  must separate decode/shape validation from Ed25519 verification. Verification
  pins issuer, key purpose, key ID, domain, organization, device, agent,
  session, time window, TTL, and sequence; it must verify the exact bytes
  `domain || canonical(statement)` and the statement hash.
- `contracts/schemas/*signing-capability*`, `contracts/openapi/device-v1.json`,
  `contracts/catalog-v1.json`, `test/fixtures/`, and the Swift/JS vector tests
  are updated together. No new authority-bearing field may be added to an
  untrusted request.

Tests and gate:

- `AgentHostXPCProtocolTests`, `NativeAgentPrivateGitSessionTests`, and
  `AgentSigningCapabilityTests` cover zero timestamps, PID reuse/version
  bounds, duplicate/unknown fields, noncanonical JSON, wrong domain/key,
  tenant/session mismatch, expired/not-yet-valid statements, signature
  mutation, sequence replay/skip, close/EOF, and outcome-unknown paths.
- `test/agent-signing-capability-vector.test.mjs` must agree byte-for-byte
  with Swift vectors. Run focused Swift tests with the repository's disabled
  sandbox/module-cache setup, then run all CI jobs on one SHA.
- Exit only when a reviewer can show that no untrusted input selects operation,
  scope, key, algorithm, budget, session, or adapter identity.

### F2 — Device API issuance and PostgreSQL reservation

Package: `F2a-issuance-service`, `F2b-postgres-reservation`, and
`F2c-device-route`.

Dependencies: F1 vectors; existing Device request authentication; active
Agent Session/Lease and authority-generation repositories; capability signer
and managed-signer provider-operation infrastructure.

Files, migration, and API:

- Extend `apps/cloud-api/src/agent-session-device-api.mjs` with the already
  declared signing-capability route. Add a dedicated
  `apps/cloud-api/src/agent-session-signing-capability-api.mjs` only if the
  existing handler cannot keep Grant and Capability parsing isolated.
- Add `apps/cloud-api/src/human-auth/agent-sessions/signing-capability-issuance-service.mjs`
  to derive `git.commit.sign`, scope, key purpose, `issued_at`, `not_before`,
  `expires_at`, sequence, `control_sequence`, `authority_generation`, and
  budget from the locked server records. The request may contribute only
  `request_id`.
- Extend or add the narrow repository in
  `apps/cloud-api/src/postgres/capability-reservation-repository.mjs` and
  `capability-authority-repository.mjs`; reuse `capability-signer.mjs` and
  `agent-session-signer-config.mjs` for the purpose-separated Cloud key.
- Add the next contiguous migration after `0073` (planned name:
  `0074_agent_session_signing_capability_reservations.sql`) for the exact
  request identity, canonical statement hash, capability hash, tenant/device/
  session bindings, sequence, reservation state, budget, generation fields,
  and safe timestamps. Add unique constraints for tenant+request, session+
  sequence, and capability hash; add checks for one-use and max two session
  signatures. Register it in `contracts/catalog-v1.json` and update schema
  head/privilege fixtures.
- Consume `capability_id + statement_hash` atomically through the existing
  durable sign-once transaction. A verified envelope is not consumed merely
  because its Ed25519 signature is valid; duplicate use must return the exact
  prior result or terminal `outcome_unknown`, never invoke the key again.
- Keep external provider intent/result/uncertainty in the existing provider
  operation tables when Cloud signing is remote. Do not store raw capability,
  nonce secret, private key, or provider response diagnostics in logs.

Tests and gate:

- Unit/API tests cover exact raw-body Device authentication, path/auth binding,
  missing or extra body keys, cross-tenant/device/session, stale control or
  authority generation, expired/revoked Lease, sequence contention, exhausted
  budget, same-request retry, conflicting request reuse, response loss, and
  managed-signer timeout/uncertainty.
- PostgreSQL tests cover two concurrent issuers, rollback after signer failure,
  migration upgrade from the current head on PostgreSQL 16 and 17, role
  privileges, and schema checksum/catalog consistency.
- Exit only when one active Lease can issue exactly the next server-scoped
  capability and an ambiguous provider outcome cannot reserve or use a second
  signature.

### F3 — Host XPC and independent child observation

Package: `F3a-host-runtime`, `F3b-child-observer`, and `F3c-close-paths`.

Dependencies: F1 Host contract; existing
`NativeAgentHostLifecycleCoordinator`, `NativeAgentHostChildSupervisor`,
`NativeDarwinProcessObservationSource`, `NativeAgentWorktreeBinding`, and
the signed launch-authority handoff.

Files and API surface:

- Implement the frozen Host interface in
  `native/macos/Sources/AgentPassNativeAgentHost/main.swift` and
  `native/macos/Sources/AgentPassNativeService/main.swift`, with shared DTOs
  only in `AgentPassNativeCore`.
- Make prepare assign session identity, attach accept only observation hints,
  and sign accept payload plus request sequence. The Service independently
  checks PID version, ancestry, executable/code identity, Team ID/designated
  requirement, cwd/worktree, repository/.git identity, branch, and remote.
- Bind the XPC connection to one lifecycle object; terminate on child exit,
  XPC interruption, authority loss, observation drift, or close. The Host may
  report a PID but never becomes the signing subject.
- Construct Capability verification context only from current, verified
  Control/Device state. Bind key ID to an enrolled public-key fingerprint,
  reject generation rollback, and keep connection-owned expected sequence and
  used-signature state so DTO range validation cannot substitute for runtime
  ordering.

Tests and gate:

- Extend `NativeAgentHostChildSupervisorTests`,
  `NativeAgentHostLifecycleCoordinatorTests`,
  `NativeDarwinProcessObservationSourceTests`, and XPC negative harnesses for
  untrusted Host, PID reuse, ancestry escape, binary replacement, signature
  drift, worktree/repository/branch/remote drift, sleep/wake, restart, attach
  races, early sign, post-close sign, and cleanup failure.
- Exit only with an evidence record showing the child identity was observed by
  the Service immediately before reservation and key use.

### F4 — multi-request private Git transport

Package: `F4a-frame-runtime`, `F4b-fd3-handoff`, and `F4c-concurrency-tests`.

Dependencies: F1 frame/state machine and F3 Host lifecycle; existing
`NativeAgentPrivateFDTransport`, private bridge socket pair/client/server, and
launch authority handoff.

Files and API surface:

- Add the session transport adapter alongside
  `NativeAgentPrivateGitBridgeClient.swift` and
  `NativeAgentPrivateGitBridgeServer.swift`; prefer unnamed Darwin
  `SOCK_SEQPACKET` only after platform qualification, otherwise retain a
  length-preserving bounded transport with an explicit decoder.
- Install the child-only endpoint at fixed FD3. Consume and close the launch
  FD3 before spawn, clear all unrelated descriptors, and transfer ownership
  deterministically around `posix_spawn`.
- Keep one outstanding request, sequence 1 then 2, no third request, bounded
  payload/signature sizes, and a terminal close that quarantines malformed or
  ambiguous traffic.

Tests and gate:

- Extend the bridge and FD transport tests for two sequential commits, third
  request denial, concurrent helper/interleaving, partial or oversized frames,
  trailing bytes, replay/skip/wrong response sequence, EOF, signer failure,
  process termination, spawn failure, FD collision/leak, and no TCP/filesystem
  fallback.
- Exit only when two helper invocations share one approved session without
  authority interleaving and the endpoint cannot be reused after close.

### F5 — CLI, Host, Git helper, and sign-once integration

Package: `F5a-real-launch`, `F5b-git-helper`, and `F5c-signing-composition`.

Dependencies: F2 Device issuance, F3 Host runtime, F4 transport, existing
`NativeAgentGrantLeaseHTTPConsumer`, `NativeSigningTransaction`, `SSHSIG`,
`lib/agent-launch-contract.mjs`, and `lib/git-signing.mjs`.

Files and API surface:

- Replace the validated-but-unavailable path in the root CLI/launch contract
  with the fixed signed Host launch; keep all authority in the Service.
- Make `agentpass-git-sign` (native or fixed-path helper as selected by the
  distribution) accept only Git's bounded payload, read only FD3, request one
  signature, write SSHSIG, and exit. Missing or inherited-wrong FD3 fails
  closed.
- Configure Claude Code through the existing adapter path and add Cursor as a
  second adapter descriptor only; do not add an adapter-specific key or XPC
  selector. `git commit -S` and `git verify-commit` are the black-box contract.

Tests and gate:

- Run real repository vectors for SSHSIG, `git commit -S`, two commits after
  one approval, third-commit denial, wrong branch/remote/worktree, helper
  without Host/FD3, executable/adapter substitution, child/sibling denial,
  and response-loss after key use.
- Scan argv, environment, Git config, shell history, logs, crash output,
  repository state, and durable state for capability, key, token, and socket
  path leakage. Exit only when the Agent and Git helper see payload/result, not
  authority.

### F6 — lifecycle, revocation, and recovery closure

Package: `F6a-state-composition`, `F6b-reconciliation`, and
`F6c-user-remediation`.

Dependencies: F2-F5; `NativeAgentSessionCoordinator`,
`NativeAgentSessionRegistry`, `NativeAgentSigningIntentStore`, existing
Cloud lifecycle repositories, audit transaction, and recovery code.

Files and API surface:

- Compose `launch`, `status`, `close`, `revoke`, `doctor`, and uninstall in
  the existing CLI/native lifecycle seams. Add no second session state store.
- Persist only public transaction identity, state, hashes, and recovery
  evidence. Reconcile `pending`, `completed`, `outcome_unknown`, revoked,
  expired, process-drift, and transport-quarantined states after restart.
- Make revocation authoritative in PostgreSQL/Control state, propagate via
  existing Device refresh, and require a final authoritative read before
  native key use.

Tests and gate:

- Kill/restart before and after every transition; cover network loss, clock
  rollback/advance, stale generations, revoke races, exact replay, provider
  uncertainty, emergency stop, cleanup failure, and Japanese/English stable
  remediation.
- Exit only when every interruption converges safely and the same provider
  operation can never be invoked twice because of response loss.

### F7 — clean-machine Claude Code qualification

Package: `F7a-installer-doctor`, `F7b-two-commit-run`, and `F7c-leak-audit`.

Dependencies: F1-F6; a clean supported macOS machine, real Git, Claude Code,
Developer ID artifact, and managed or qualification Cloud endpoint.

Files and API surface:

- Extend the existing root CLI setup/doctor/uninstall modules and the native
  onboarding status model. Do not require a full Mac GUI; browser approval and
  CLI diagnostics are the supported workflow.
- Capture secret-free qualification evidence bound to source SHA, PKG digest,
  contract hashes, migration head, and provider key version.

Tests and gate:

- On a clean user account, install, enroll, approve once, create two unattended
  signed commits, verify both signatures/audit links, deny the third, revoke,
  and prove immediate denial. Repeat after restart and with install/upgrade/
  uninstall/reinstall-preserve.
- Exit only with process/argv/env/config/log/crash/repository/durable-state
  scans clean and the evidence independently reproducible.

### F8 — Web Console onboarding and Cursor parity

Package: `F8a-console-flow`, `F8b-policy/activity`, and `F8c-cursor-adapter`.

Dependencies: F2/F6 public states and current Web Console BFF, Human WebAuthn,
organization/role/session APIs, and accessibility test conventions.

Files and API surface:

- Extend `apps/web-console/app/components/AgentPassConsole.tsx`,
  `HostedOnboarding.tsx`, `SecurityPanel.tsx`, the existing console API/BFF
  routes, and `apps/web-console/app/globals.css` with install, enrollment,
  approval preview, active session, activity, expiry, revoke, emergency stop,
  resume, and remediation states.
- Add only public metadata to Console APIs: display name, state, expiry,
  last activity, bounded reason, and audit references. Never return a raw
  capability, device credential, private key, or bearer session to browser
  storage.
- Cursor consumes the same CLI/Host adapter contract as Claude Code. No new
  authority object or native selector is allowed.

Tests and gate:

- Extend Console unit and Playwright tests for Owner/Admin/Auditor/Viewer,
  operation-bound WebAuthn, response loss/stale state, keyboard/screen reader,
  focus restoration, 200% reflow, reduced motion, Japanese/English, and
  browser-storage/artifact scans. Run Claude/Cursor parity vectors.
- Exit only when a non-engineer can install, approve, understand activity,
  revoke, recover, and uninstall without seeing internal authority IDs.

### F9 — managed signer and signed distribution

Package: `F9a-provider`, `F9b-package`, and `F9c-channel-equality`.

Dependencies: F2 provider-operation state, F7 qualification workflow, Apple
Developer ID credentials, notarization service, supported Apple silicon and
Intel/T2 hardware, and Homebrew release review.

Files and API surface:

- Extend existing AWS/GCP KMS provider/runtime/key-lifecycle modules and
  `contracts/postgres/0037_managed_signer_lifecycle.sql`-era repositories;
  assign immutable purpose/key-version/fingerprint/workload-identity records
  and a disable/drain/reconcile worker. Hosted mode must reject local/file
  private-key fallback.
- Keep `native/macos/scripts/build-app.sh` as the reproducible assembly path;
  add a release manifest, SBOM/provenance, notarization/stapling checks, and
  digest publication around the existing signed bundle. Do not make a full
  Mac GUI a prerequisite for production.
- Keep Homebrew as the easy evaluation/CLI channel (`Formula/agentpass.rb`)
  and distribute production enforcement as one signed/notarized PKG. The
  formula must point users to the PKG for the XPC identity boundary; it must
  never silently claim production protection.

Tests and gate:

- Provider tests cover IAM allow/deny, non-exportability, purpose/version/
  fingerprint binding, outage/throttle/timeout/response loss, rotation,
  drain, disable, and no fallback.
- Release tests run `codesign`, `spctl`, `pkgutil`, notarization/stapler,
  install/upgrade/uninstall/reinstall/rollback, and arm64/x86_64 checks. The
  direct-download manifest, PKG, and any production installer must have the
  same digest; Homebrew source mode is explicitly a different evaluation
  status.
- Exit only when the production package is signed/notarized and physical
  qualification proves the same identity boundary on both hardware classes.

### F10 — staging, independent review, and production promotion

Package: `F10a-staging`, `F10b-review`, and `F10c-promotion`.

Dependencies: all previous exits; protected Cloud/Console accounts; immutable
container registry; PostgreSQL backup/PITR; KMS; observability; incident
owners; independent security reviewer; release approvers.

Files and API/runbook surface:

- Add immutable deployment manifests, migration allow-list, worker/drain
  configuration, dashboards/alerts, SLO definitions, and staging evidence
  under the existing `ops/` and release/runbook conventions.
- Use `docs/POSTGRES_CUTOVER_RUNBOOK.md`,
  `docs/POSTGRES_BACKUP_RESTORE.md`, provider rotation runbooks, and release
  manifests as the operator contract. Every promotion record names source
  SHA, schema head/checksums, image digest, PKG digest, and provider versions.

Tests and gate:

- Rehearse migration canary/drain, restore with measured RPO/RTO, database/KMS/
  network outage, tenant-isolation attack, revoke latency, signer compromise/
  rotation, queue/dead-letter recovery, and rollback.
- Run SAST, DAST, dependency/container/IaC scans, SBOM/provenance verification,
  full E2E, and independent security review. No critical/high unresolved
  finding, unmet SLO/RPO/RTO, or unreviewed exception may pass promotion.
- Production is a human-approved canary followed by measured expansion; it is
  never an automatic consequence of a green build.

## 4-B. Next three merge-sized slices

These are the immediate queue after the current `09eb561` baseline. They are
intentionally small enough to review independently and ordered so that the
first Cloud implementation cannot outrun the native contract.

### Slice 1 — accept or reject the pending F1 native contract candidates

Scope: only the uncommitted F1d/F1e files and their tests/vectors. Review the
Host XPC DTOs, private Git lifecycle state machine, and
`AgentSigningCapability.swift` as one contract set; do not add runtime wiring.

Required checks:

- Confirm Host prepare has no caller-supplied agent/adapter/session authority;
  sign requests carry only payload and sequence; timestamps/PID versions reject
  zero and out-of-range values; stale reserved authority keys are rejected.
- Confirm capability verification performs real pinned-key Ed25519 verification
  over the exact domain plus canonical statement, not shape-only parsing, and
  binds organization/device/agent/session, issuer/purpose/key ID, time, TTL,
  sequence, and one-use budget.
- Run focused Swift tests, JS vectors, and native-source typecheck; then run
  all six CI jobs on one SHA. Record any local listener restriction as an
  environment note only.

Exit artifact: one reviewable F1 contract commit (or a documented rejection
with a follow-up fix), no API/database/source-runtime changes, and updated
threat-matrix evidence.

### Slice 2 — implement F2 issuance behind the frozen Device API

Scope: the signing-capability route, service, repository, migration, and
contract tests only. Do not launch Claude Code or change the private Git
transport in this slice.

Required implementation order:

1. Add the next migration after 0073 and its catalog/schema-head/role checks.
2. Add the PostgreSQL reservation transaction with unique retry identity,
   session sequence, budget, generations, and `outcome_unknown` state.
3. Add the issuance service and route using the existing Device verifier and
   signer-purpose/provider-operation seams. Parse the body only after raw-byte
   authentication; accept only `request_id`.
4. Add unit, adversarial HTTP, PostgreSQL 16/17 integration, concurrency, and
   provider uncertainty tests. Update OpenAPI only if implementation exposes a
   mismatch; do not widen the already-frozen request.

Exit artifact: a Device-authenticated active Lease can issue/replay exactly
one server-scoped capability, while unauthorized, stale, exhausted, or
ambiguous cases are stable denials. F3 cannot begin integration until this
slice is green in protected CI.

### Slice 3 — connect one native sign boundary without Git automation

Scope: F3 plus the F4 transport adapter, using a deterministic test signer or
test Device endpoint only at unit-test seams. Do not claim a real unattended
commit yet and do not alter Console/UI or distribution.

Required implementation order:

1. Connect Host prepare/attach/status/close to the Service lifecycle and
   independent child observer.
2. Connect the two-request session state machine to FD3 with bounded framing,
   ownership transfer, and quarantine/EOF behavior.
3. Inject a signed-capability verifier and fake signing transaction in tests;
   prove that Host/child/process drift prevents reservation and that response
   loss becomes `outcome_unknown`.
4. Run Swift unit/integration/XPC negative harnesses, FD leak scans, and
   sanitizer or stress coverage where available.

Exit artifact: a supervised child can perform two in-memory sign exchanges
through the Service boundary with no authority in the Host/child DTOs. The
next slice (F5) is the first one allowed to touch real `git commit -S`.

## 5. Parallel execution and ownership

After F1, use at most three disjoint lanes:

1. Native lane: F3, F4, F5, F6, F7.
2. Cloud authority lane: F2 and the provider half of F9.
3. Console/release lane: F8 and distribution preparation for F9.

One integration owner serializes catalog/OpenAPI/schema versions, PostgreSQL
migrations, signing domains, XPC selectors and DTO encoding, private-frame
versions, Mach service identifiers, entitlements, Developer ID identities, and
promotion records. A lane needing one of these submits the smallest boundary
change first instead of carrying a divergent private contract.

## 6. Per-merge acceptance contract

Every merge unit includes:

- implementation and generated artifacts;
- positive plus denial, replay, stale, malformed, cross-tenant, contention,
  timeout, response-loss, and process-loss tests applicable to the boundary;
- threat-model and operator/remediation documentation for new states;
- secret-free evidence schemas that bind source SHA and relevant migration,
  artifact, provider version, and command digests;
- focused tests before commit and complete contract/lint/root/Console/native
  CI after push.

Mocks, simulators, ad-hoc signatures, skipped tests, and sandbox-restricted
local runs demonstrate source progress only. They never satisfy protected,
physical, provider, notarization, staging, or production gates.

## 7. External requirements

Source work cannot manufacture:

- protected AWS/GCP accounts, KMS keys, and workload identities;
- Apple Developer ID Application/Installer and notarization credentials;
- supported Apple silicon and Intel/T2 Macs;
- protected staging/production accounts and release approvers;
- an independent security reviewer.

These are scheduled before F7-F10, but their absence does not justify a local
key fallback, unsigned distribution claim, mock qualification, or automatic
production promotion.
