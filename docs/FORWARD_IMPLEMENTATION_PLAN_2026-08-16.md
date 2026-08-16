# AgentPass forward implementation plan — 2026-08-16

Status: active

Source baseline: `codex/agent-platform` at `89e61fb`

This is the authoritative day-to-day plan after the native launch, child
supervision, and private Git transport primitives landed. Product and release
requirements remain defined by [`V1_EXECUTION_PLAN.md`](./V1_EXECUTION_PLAN.md).
Older checkpoint queues are historical context when they conflict with this
document.

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
