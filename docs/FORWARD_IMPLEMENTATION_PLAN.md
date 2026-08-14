# AgentPass forward implementation plan

Status: active

The current merge-sized execution order and production gates are maintained in
[NEXT_IMPLEMENTATION_PLAN.md](./NEXT_IMPLEMENTATION_PLAN.md). This document
retains the longer historical and architectural work breakdown.

Updated: 2026-08-14

Baseline branch: `codex/agent-platform`

## 1. Current boundary

AgentPass has a locally verified Cloud/Console/native foundation and a fail-closed physical-release harness. The physical harness fixes 16 gates and 20 tests to one source commit, one notarized PKG digest, one Developer ID Team ID, and two independently operated Mac hardware lanes.

All 16 frozen physical scenario procedures are now implemented in software:

1. exact PKG/Gatekeeper installation, launchd/XPC identity, Secure Enclave enrollment, Cloud possession, and negative peer probes;
2. unattended Claude Code/Cursor signed commits with independent Git verification;
3. policy reduction, offline expiry, revoke/emergency stop, and local-to-Cloud audit observation;
4. crash/reboot, sleep/wake/network/clock, upgrade, uninstall/reinstall, and explicit current-user purge.

These procedures are locally/adversarially tested but are not production-qualified. A passing modeled test, simulator test, ad-hoc signed build, or operator assertion cannot replace execution of all 16 exact scenarios against the same notarized PKG on both protected hardware lanes.

The process-bound Agent-session foundation now also includes the frozen Human Grant and Device Lease contracts, PostgreSQL-backed issuance/consumption, a split privileged Agent XPC service, a fixed-FD activation document, and a signed Agent Host lifecycle. The protected qualification runner now has a candidate-checkpoint-bound release trust, fixed root release staging, one-shot root-private input consumption, per-step run-binding materialization, durable fired-evidence recovery across daemon loss, bounded Controller/Agent Host supervision, and a seven-step unarmed-plus-six-scenario suite. Both hardware lanes pin and invoke the installed composition and fail when the protected seven-Grant inbox is absent.

The qualification relay contract is now implemented locally: Human/WebAuthn authorization returns public metadata only; a purpose-separated Cloud-signed manifest binds the exact ordered seven existing Agent Session Grants; the Device API authenticates the raw claim, verifies both Grant and manifest signatures, and delegates atomic one-shot/exact-retry state to PostgreSQL; the macOS client validates HTTPS, the signed response, and every binding; and the root relay publishes one canonical suite inbox without putting proof bytes in argv, environment, or logs. Secret-free suite evidence has a closed canonical schema. Production runtime composition, packaged native invocation, report integration, and execution on both physical lanes remain open, so none of these local results is physical-release evidence.

## 2. Delivery rule

Work proceeds in five ordered milestones. A later milestone may be developed in parallel but cannot be called qualified until all of its dependencies and evidence gates pass.

```mermaid
flowchart LR
  M1["M1: device and Cloud identity"] --> M2["M2: real agent signing"]
  M1 --> M3["M3: authority reduction and audit"]
  M2 --> M4["M4: destructive lifecycle"]
  M3 --> M4
  M4 --> M5["M5: hosted production and release"]
```

Every implementation slice must keep these invariants:

- no private key or reusable capability crosses the Secure Enclave boundary;
- no scenario accepts an executable, endpoint, path, identity, or test name from mutable job input;
- every authority increase comes only from a verified, current ControlBundle; wake notifications carry no authority;
- every reduction is durable before it is observable and remains effective after process or OS restart;
- all evidence is public metadata or a hash of bounded private evidence;
- release, Cloud, device, browser, and qualification results bind to the same source and artifact identities.

## 3. Milestone M1 — device and Cloud identity closure

### M1.1 Cloud possession verification

Status: the strict v2 contracts, deterministic candidate-bound challenge, P-256 proof verification, canonical Cloud receipt signer, file/PostgreSQL persistence, device-authenticated receipt read, native v2 Secure Enclave signing, and a fail-closed physical scenario are implemented and locally verified on 2026-08-13. A one-time operator-authorized qualification ticket/relay, production KMS/HSM wiring, and execution from both physical qualification runners remain open.

Implement `cloud-possession-verification` as an authenticated enrollment round trip, not a local signature-only assertion.

Required flow:

1. request a single-use enrollment challenge from the pinned Device API;
2. bind the challenge to organization, enrollment, candidate artifact SHA-256, source commit, Team ID, public-key fingerprint, expiry, and server nonce;
3. sign the exact canonical preimage through the pinned native service executable;
4. submit the public key and signature over trusted TLS;
5. require a signed server receipt containing the same bindings and the committed device/key epoch;
6. fetch the device identity through an independently authenticated read and compare the committed key fingerprint and epoch;
7. retain only the receipt hash and allow-listed public identity fields in qualification evidence.

Server changes:

- add an idempotent, one-time challenge/receipt repository contract;
- consume the challenge in the same transaction that activates the device key;
- reject replay, cross-tenant/device substitution, stale challenge, public-key replacement, wrong artifact binding, and ambiguous commit outcome;
- emit a non-secret enrollment audit event and expose an authenticated receipt lookup.

Exit evidence: exact duplicate is idempotent; conflicting duplicate, expired challenge, wrong key, wrong candidate, TLS failure, database rollback, and process loss after commit all fail closed or recover the same receipt.

### M1.2 Candidate-bound machine identity

Status: checkpoint creation, six nested identity bindings, before/after revalidation, and execution from a root-private immutable copy created from the already verified bytes are implemented and locally verified on 2026-08-13. Execution against the first real notarized candidate remains open.

Replace static candidate executable assumptions with a two-level identity model:

- machine baseline: root-owned paths, service label, approved agent locations, OS/hardware identity;
- release checkpoint: installed code-object identities and hashes derived only after exact PKG installation.

The Gatekeeper scenario atomically writes a root-owned, exclusive candidate checkpoint after successful installation. Later scenarios read and verify that checkpoint before and after use. It binds source commit, artifact digest, Team ID, nested designated requirements, CodeDirectory hashes, and file identities. Reinstall or upgrade creates a new checkpoint through an explicit transition; it never edits the active checkpoint in place.

Exit evidence: same-content replacement, symlink/hard-link substitution, stale checkpoint replay, mixed nested binaries, original-path replacement after snapshot, and mutation of the private execution copy are rejected. The private copy is removed after child completion.

### M1.3 Negative identity and entitlement probe

Status: the strict four-role manifest/verifier, release signing helper, four probe applications, physical scenario, and service-side exact Developer ID/Team ID/approval-entitlement requirement are implemented and locally verified. Production Developer ID signing and physical XPC allow/deny execution against the notarized candidate remain open.

Implement `negative-identity-and-entitlement-cases` with signed probe binaries created by the release pipeline:

- approved client with the exact designated requirement and entitlement;
- same-Team-ID client without the required entitlement;
- differently signed client with a look-alike bundle identifier;
- unsigned/ad-hoc client;
- approved client launched through an unapproved identity/path mutation.

The scenario must prove the approved probe reaches only the allow-listed XPC method and every negative probe is denied before signing. Service audit must record stable denial classes without code-signature blobs, repository data, or secrets.

Exit evidence: denial remains effective after service restart and cannot be bypassed by PID reuse, copied binaries, parent-process substitution, or concurrent approved/unapproved calls.

## 4. Milestone M2 — unattended Claude Code and Cursor signing

The frozen implementation sequence, process/ancestry boundary, contracts, migrations, state machine, tests, and rollout gates are specified in `PROCESS_BOUND_AGENT_IMPLEMENTATION_PLAN.md`.

### M2.1 Agent adapter contract

Foundation status (2026-08-13): frozen grant/lease/request-v2 schemas, Human issuance and Device consumption OpenAPI operations, PostgreSQL migrations 0018–0022, the atomic PostgreSQL Human issuance repository, low-level consumption authority, separate Cloud/device audit-chain schemas, protected process-policy registry, purpose-separated hosted signer boundary, exact hosted runtime route composition, and injectable native process/ancestry identity model are implemented. External KMS/drain qualification, consumption audit runtime integration/outbox completion, audit-token-scoped Darwin peer observation, the split Agent XPC service, and physical qualification remain open.

Freeze one local adapter contract shared by Claude Code and Cursor:

- agent executable identity is captured at setup and revalidated for every session;
- a session is short-lived, process-bound, repository/worktree-bound, operation-bound, and ControlBundle-bound;
- Git receives only a signing response; it never receives key bytes or a reusable bearer secret;
- setup may involve a human once, but normal policy-authorized commits require no recurring biometric prompt;
- agent authentication material is obtained through a service-mediated handoff and is never stored in the machine scenario configuration.

Implement a root-owned broker endpoint that exchanges a one-time, short-expiry bootstrap nonce for a process-bound agent session after code-identity and policy checks. The broker must not trust environment variables as identity.

### M2.2 `claude-code-unattended-sign`

Run the pinned Claude Code executable in its documented non-interactive mode against a dedicated root-validated test repository. The scenario creates a deterministic change, requests one commit, verifies the Git signature and signer fingerprint, confirms repository/worktree scope, and waits through a configured unattended interval before a second authorized commit.

Negative cases: different repository, expired session, changed executable, child process with a different identity, extra signing request, and policy-disallowed branch/path.

### M2.3 `cursor-code-unattended-sign`

Apply the same contract to Cursor Agent using its production-supported headless interface. Cursor-specific authentication must be provisioned through the protected runner environment and exposed only to the exact process for the bounded run. Qualification refuses to start when a stable supported headless/auth contract is unavailable.

Exit evidence for M2: both agents produce verified signed commits without biometric interaction, cannot export or directly invoke the key, cannot cross repository/session scope, and stop signing immediately when the installed bundle no longer authorizes the operation.

## 5. Milestone M3 — authority reduction, expiry, and audit

### M3.1 `policy-reduction-refresh-ack`

Issue an initially valid bounded signing policy, prove one authorized signature, narrow the policy transactionally, and require the online Mac to poll, verify, atomically install, enforce, and ACK the exact newer bundle. The formerly valid operation must be denied after activation. Console must show the signed ACK only after the authoritative database commit.

Fault matrix: duplicate/reordered wake, stale bundle, sequence/generation rollback, statement-hash substitution, ACK replay, activation crash, ACK timeout, and concurrent signing at the activation boundary.

### M3.2 `offline-expiry`

Install a short-expiry bundle, disconnect all network routes to the Device API, prove allowed operation before expiry, and prove denial at and after expiry using monotonic-safe evaluation. Wall-clock rollback or forward adjustment must not widen authority. Reconnection may install only a valid newer bundle.

### M3.3 `revoke-emergency-stop`

Test device revoke and organization emergency stop as separate reductions. Each mutation, authority generation, refresh outbox, and admin audit must commit atomically. An online device must deny after refresh/ACK; an offline device must deny no later than its already-installed expiry. No wake, reenrollment replay, stale session, or old bundle may restore authority.

### M3.4 `audit-upload-observation`

Add a native audit uploader that authenticates with the Secure Enclave device key and uploads a hash-chained, bounded batch over trusted TLS. Cloud verifies device signature, sequence, previous hash, event schema, and tenant/device binding before committing. Console reads only the authoritative committed projection.

The scenario performs an allowed sign and a denied sign, uploads both, then independently queries Console/API until both public event summaries appear. It must verify ordering and linkage without retaining repository content, command text, policy bodies, or signature material.

Exit evidence for M3: every reduction is visible end-to-end, audit loss/reorder/equivocation is detected, offline expiry cannot be bypassed, and no Cloud or Console path can grant authority.

## 6. Milestone M4 — destructive lifecycle and environmental recovery

### M4.1 `crash-restart-recovery`

Use a supervisor outside the tested service to inject `SIGKILL` at every durable boundary: refresh snapshot, bundle staging/fsync/publication, active-pointer update, local audit append/checkpoint, session revocation, ACK submission, ACK persistence, and audit upload. Each case restarts launchd and proves convergence to the old valid state or the complete new state, never a mixed state.

OS reboot is a separate two-phase protocol because one GitHub Actions job cannot survive reboot honestly:

1. `prepare` creates a root-owned candidate-bound reboot checkpoint and schedules a one-shot continuation LaunchDaemon;
2. the machine reboots through an operator-controlled runner action;
3. `resume` validates boot identity, checkpoint freshness, candidate binding, pre-reboot hashes, launchd state, key identity, bundle state, and pending ACK/audit convergence;
4. completion consumes the checkpoint and unregisters the continuation.

### M4.2 `sleep-wake-network-clock`

Drive real system sleep/wake and network loss/restoration through protected runner controls. Apply bounded forward/backward wall-clock changes only on isolated qualification machines, always restore time synchronization, and verify that monotonic deadlines and signed server times prevent authority widening. Test long-poll cancellation, retry bounds, DNS/TLS failure, and wake coalescing.

### M4.3 `upgrade-preserves-state`

Install the previous qualified PKG, enroll and activate a bundle, create pending ACK/audit state, then install the exact candidate. Verify root ownership, state/key continuity, schema migration, rollback protection, launchd replacement, and completion of pending work. A failed upgrade must preserve the previous usable installation or fail closed with a documented recovery action.

### M4.4 `uninstall-reinstall-recovery`

Define uninstall semantics explicitly: binaries and launchd jobs are removed; protected device identity and audit continuity are retained by default. Reinstalling the same or newer qualified build must recover only after code identity, organization/device continuity, and current Cloud state are reverified. A different Team ID or tenant cannot claim retained state.

### M4.5 `current-user-purge`

Provide a separate, explicit destructive purge operation requiring local administrator authorization and recent owner WebAuthn. It revokes the Cloud device first, records a receipt, unloads services, removes retained keys/state using exact root-owned paths, and verifies absence. Partial failure leaves a resumable purge journal and signing remains denied.

Implementation checkpoint (2026-08-14): the product CLI now exposes an explicit preview and `--confirm PURGE_USER_STATE --execute` flow, validates a closed current-user state tree, quarantines it before deletion, rejects symlink/hardlink/mutation/substitution cases, preserves unrelated home and system state, and uses target-specific native session revocation. Cloud device revocation, recent-owner WebAuthn authorization, a durable cross-process purge receipt/journal, service unloading, and protected-key destruction remain production work; the current physical procedure must not be interpreted as proof of those later controls.

Exit evidence for M4: process loss, OS reboot, sleep, network loss, clock changes, upgrade, uninstall/reinstall, and purge have deterministic recovery with no authority widening and no orphaned signing path.

## 7. Milestone M5 — hosted production and release

Run these lanes after the physical behavior exists:

1. PostgreSQL-backed shared abuse controls and organization/member session epochs;
2. purpose-separated managed KMS/HSM adapters for bundle, capability, refresh, Console identity, and release evidence signing;
3. threshold owner recovery and secret-free notifications;
4. immutable Cloud/Console deployment, forward-only migration job, trusted TLS, backup/PITR, restore, canary, rollback, metrics, and alerts;
5. independent security review covering native authorization, XPC identity, canonical signing, tenant SQL, WebAuthn/recovery, KMS IAM, release provenance, and the physical runner trust boundary;
6. first Developer ID/notarized universal PKG release and CLI/Homebrew bootstrap that install and verify that same PKG.

Production exit requires zero unresolved critical/high findings and one promotion record that binds source commit, PKG digest, nested code identities, notarization ticket, Cloud/Console image digests, migration set, signer key versions, browser evidence, and both physical-Mac reports.

## 8. Parallel work lanes

| Lane | Immediate work | May run with | Integration lock |
| --- | --- | --- | --- |
| A — native identity | candidate checkpoint, negative probes | B, C | entitlements and designated requirements |
| B — Cloud device | possession challenge/receipt, audit ingest | A, D | Device API/OpenAPI and migrations |
| C — agent adapters | broker contract, Claude/Cursor fixtures | A, B | local XPC protocol and session schema |
| D — authority | policy/revoke/offline scenarios | A, C | ControlBundle/ACK contracts |
| E — lifecycle | crash supervisor, reboot continuation | after checkpoint contract | installer and durable-state layout |
| F — hosted | abuse controls, signer provider, deployment | B–E development | migration numbers and signer purposes |

One integration owner serializes schema migrations, OpenAPI changes, entitlement changes, release identities, and durable native storage changes. Parallel lanes may not independently change these shared boundaries.

## 9. Implementation order and merge gates

1. Candidate checkpoint and signed negative probes.
2. Cloud possession challenge/receipt and physical scenario.
3. Native audit upload plus Cloud ingest/Console observation.
4. Process-bound agent session broker.
5. Claude Code unattended signing, then Cursor unattended signing.
6. Policy reduction, offline expiry, revoke, and emergency-stop scenarios.
7. Crash supervisor and two-phase reboot continuation.
8. Sleep/wake/network/clock scenario.
9. Previous-build fixture and upgrade scenario.
10. Uninstall/reinstall retention and explicit purge scenarios.
11. Execute all 16 gates on Apple Silicon and Intel T2 against one candidate.
12. Complete hosted production, review, restore, and promotion gates.

Each merge requires:

- contract/schema validation where affected;
- full Node, Swift, Console, and lint/build gates;
- deterministic unit and adversarial tests with injected boundaries;
- real PostgreSQL or real macOS boundary evidence where applicable;
- fail-closed timeout, replay, substitution, and restart behavior;
- log, artifact, browser-storage, and evidence secret scans;
- operator runbook and compatibility/migration note;
- no production-ready claim for a scenario not physically executed on both lanes.

## 10. Next executable slice

The next slice converts the locally verified seven-step N3-E suite into independently verifiable physical-release evidence. The fixed materializers, candidate-bound release trust, distinct-Grant suite, and installed workflow entrypoint are already implemented. Work now proceeds through four ordered boundaries:

1. add a device-authenticated qualification relay that obtains seven independent, operation-bound Grants and publishes exactly one closed suite document to the fixed root inbox;
2. version the hardware report schema so it binds the suite digest, ordered public step digests, release-trust digest, candidate-checkpoint digest, source commit, PKG digest, Team ID, lane identity, and timestamps, then verify the report independently before upload;
3. inject interruption at every release publication, inbox publication, run-binding, fired-receipt, restart, disarm, restoration, and cleanup boundary and prove deterministic recovery with no reusable authority or partial trust root left behind;
4. execute the same source commit and notarized PKG on Apple Silicon and Intel T2, preserve both untouched signed reports, and cross-check that every bound identity agrees.

The relay must use the existing Device API authentication and lease/grant verification boundaries; proof bytes may exist only in bounded protected memory and root-private files and must never appear in argv, environment, stdout/stderr, workflow logs, cache, or uploaded artifacts. Publication must be exclusive, canonical, fsynced, one-shot, and rejected if the fixed inbox or active run already exists.

The evidence change must be additive and versioned. The workflow may print only bounded result classes and public digests. A report is invalid if a step is missing, reordered, duplicated, uses a repeated Grant or run binding, disagrees with the candidate checkpoint, or was signed by an unapproved lane/operator key.

The slice is complete only when all adversarial relay/report/recovery tests pass, the full Node/Swift/contracts/package gates pass from a clean source tree, both physical lanes validate independently, and the two signed reports bind the same candidate. Until then, N3-E remains locally verified rather than physically qualified.

## 11. Post-checkpoint implementation plan

This is the implementation sequence after the 16/16 software-procedure checkpoint. The recommended product shape is one hosted Web Console plus a signed/notarized macOS PKG, with Homebrew acting only as a bootstrap and update-discovery channel for that same verified PKG. The privileged native boundary is not replaced by a browser, Electron shell, or a Homebrew-only Node process.

### Phase 1 — freeze Core protocol and schema contracts

The authority split and compatibility rules are fixed by [`ADR-003-contract-authority-and-versioning.md`](./ADR-003-contract-authority-and-versioning.md). CI must validate the machine-readable catalog before running product tests so missing or ambiguous contracts cannot merge behind unrelated green tests.

Implementation status (2026-08-14): Phase 1 has a 28-schema, 41-operation, 24-migration, 17-fixture inventory, but remains open. Organization, membership, invitation, WebAuthn credential/ceremony/recent authorization, policy, capability, and ControlBundle now have explicit closed schemas aligned to current runtime projections; duplicated Human and Device OpenAPI components reference those schema files. Purge authorization/receipt and promotion evidence are frozen as `specified`, not implemented: the current local purge and release-attestation code must not be represented as conforming to those future authority envelopes. The machine-readable catalog records this distinction for all 93 entries. Device identity remains represented by enrollment, possession, Device API, and Console read-model contracts; Agent identity remains represented by Agent Session Grant/Lease and sign-request contracts rather than an unused parallel identity envelope. The public Node protocol exposes a closed immutable parser manifest; the macOS management and Agent XPC surfaces have a runtime-verified selector/DTO/type-encoding fingerprint; raw PostgreSQL tenant queries reserve `$1` for the repository tenant; and Console capability responses are reduced to tenant- and audience-bound lifecycle metadata. CI and release-candidate workflows validate the catalog before product or signing steps. Phase 1 closes only when purge and promotion producers/verifiers implement their specified envelopes, compatibility tests exercise those exact bytes, and the two legacy raw-canonical-JSON signature preimages are either explicitly accepted as legacy or migrated through a versioned domain-separated contract.

Deliverables:

1. publish versioned schemas for organization, membership/role, human session, WebAuthn credential, device, enrollment, agent, policy, ControlBundle, capability, Agent Session Grant, audit event, purge authorization/receipt, and promotion evidence;
2. give every request an organization binding, actor binding, idempotency key, expiry, purpose, and canonical signing preimage;
3. add compatibility fixtures for the current native client, Cloud API, Console BFF, PostgreSQL repositories, and release verifier;
4. reject unknown fields, mixed schema versions, tenant ambiguity, signer-purpose reuse, stale epochs, and downgrade paths;
5. record an architecture decision for which authority is Cloud-owned, device-owned, and human-only.

Exit gate: contract validation and cross-language fixtures pass; no open schema question can change a database key, XPC selector, signature preimage, or tenant boundary in later phases.

### Phase 2 — production Console identity and organization control

Implementation status (2026-08-14): the organization/session and production WebAuthn authority slices are implemented. Organization/member/invitation mutations validate the fixed role and optimistic-version boundary, protect the last owner, revalidate and lock the exact current session/organization/membership epochs inside the mutation transaction, use stable redacted errors, and revoke reduced authority transactionally. Migration 0024 provides organization-wide and per-membership session epochs; session issuance snapshots both and rotation is atomic. Authentication and registration now enforce exact RP/origin/UV bindings, durable one-time consuming claims with bounded verifier deadlines and stale-claim recovery, counter/backup-state CAS, session-bound recent authorization, and atomic step-up consumption when an existing account adds another passkey. The Console includes accessible organization administration, conflict/expiry/retry states, and automatic existing-passkey step-up without persisting ceremony or proof material. Real PostgreSQL qualification covers replay, tenancy, expiry, concurrent consumption, epoch invalidation, and atomic passkey addition. Remaining Phase 2 work is threshold-owner recovery, production-browser Playwright role/WebAuthn matrices, and production telemetry/abuse controls.

Deliverables:

1. finish organization creation, invitation, membership lifecycle, and fixed Owner/Admin/Auditor/Viewer permissions;
2. implement WebAuthn registration/authentication with exact RP ID/origin checks, sign-counter policy, credential lifecycle, and recent-auth step-up;
3. use rotating, server-side human sessions with CSRF protection, device/session inventory, revocation, organization/member epochs, and bounded recovery;
4. build Console screens for onboarding, devices, agents, policies, approvals, audit, emergency stop, and purge authorization;
5. add accessible empty/error/recovery states and secret-free telemetry.

Exit gate: browser E2E proves two organizations cannot cross-read or mutate; role downgrades and session revocation take effect transactionally; WebAuthn replay/origin/RP/counter negative tests pass.

### Phase 3 — PostgreSQL Device API and managed signers

Deliverables:

1. complete forward-only PostgreSQL migrations and transactional repositories for all authority, replay, outbox, ACK, audit, and recovery state;
2. run one migration job per deployment, enforce schema/version checks at startup, and qualify backup, PITR, and restore;
3. compose the real Device API for enrollment, challenge/receipt, refresh, ACK, audit ingest, Agent Session Grant consumption, revoke, and emergency stop;
4. replace development keys with purpose-separated KMS/HSM keys and narrowly scoped workload identities; pin key version in signed evidence;
5. add transactional outbox workers, retry/dead-letter policy, rate limits, abuse controls, metrics, and alerts.

Exit gate: real PostgreSQL contention/process-kill tests pass; tenant SQL review is clean; KMS IAM prevents cross-purpose signing; restore produces the same authoritative heads without replaying consumed grants.

### Phase 4 — macOS onboarding and distribution

Deliverables:

1. finish the native onboarding state machine: verify app, initialize local state, enroll approval/device keys, bind organization/device, connect Claude Code/Cursor, and verify a test commit;
2. make every step resumable and show actionable status without exposing bearer material or private evidence;
3. ship one universal Developer ID-signed, hardened-runtime, notarized and stapled PKG containing the app, XPC services, launchd jobs, helper, CLI, and signer;
4. publish a Homebrew formula/bootstrap that downloads and verifies the exact PKG digest/signature, plus direct GitHub Release installation and an offline verification path;
5. implement update, rollback refusal, uninstall-preserve, reinstall recovery, explicit current-user purge, and compatibility reporting.

Exit gate: clean-machine install → onboarding → Claude/Cursor signed commit → upgrade → uninstall/reinstall passes on supported Apple Silicon and Intel T2 hardware without Xcode.

### Phase 5 — end-to-end qualification, security review, and production deployment

Deliverables:

1. deploy immutable Console/API/worker images with migration, canary, rollback, TLS, secrets, observability, alerting, backup, and incident runbooks;
2. run browser-to-Cloud-to-device-to-Secure-Enclave E2E, failure injection, long-duration unattended operation, and all 16 physical gates on both lanes against one candidate;
3. commission independent review of XPC/code identity, native storage, canonical signatures, WebAuthn/recovery, tenant SQL, KMS IAM, supply chain, updater, purge, and qualification infrastructure;
4. resolve every critical/high finding and either fix or explicitly accept lower findings with owner and deadline;
5. produce one signed promotion record binding commit, PKG and nested identities, notarization, image digests, migrations, KMS versions, E2E evidence, security review, and both hardware reports.

Exit gate: the promotion verifier independently accepts the record, production smoke/restore tests pass, and no unresolved critical/high security finding remains.

### Parallel execution and integration locks

After Phase 1 freezes shared contracts, four lanes may proceed concurrently: Console identity, PostgreSQL/Device API, native onboarding, and release/operations. Migration numbers, OpenAPI changes, XPC selectors, entitlement/designated requirements, durable native formats, canonical signing preimages, and release identities remain serialized integration locks. Every lane merges behind full contract, Node, Swift, package, E2E, and secret-scan gates appropriate to its boundary.

## 12. Detailed execution waves after N3-E

### Wave 1 — protected qualification closure

Implementation status (2026-08-14): the fixed `run`/`recover` entrypoint, root-private input/inbox materializers, candidate-checkpoint-bound release trust and staging, per-step run-binding lifecycle, six-scenario driver, daemon-restart receipt recovery, Controller durable-receipt preference, seven-distinct-Grant suite, package inventory, immutable workflow preflight, installed workflow invocation, qualification Human/Device API contracts, purpose-separated signed batch manifest, macOS response verifier, root relay, and canonical suite-evidence record are implemented and locally verified. The remaining closure work is production runtime/KMS composition, packaging the fixed native relay client, binding suite evidence into the signed lane report, release-stage recovery/cleanup qualification, and exact execution on both protected Mac lanes.

Implementation:

- replace the remaining injected runner callbacks with fixed packaged commands and closed schemas;
- bind the activation document to the exact canonical signed Grant without putting proof bytes in argv, environment, stdout, logs, or evidence;
- supervise Controller, Agent Host, launchd restart, and timeout as separate processes with bounded termination;
- distinguish expected daemon-loss outcomes from Host lifecycle failures without accepting a missing fired receipt;
- add stale-run recovery that proves no active run, validates every durable identity, and deletes in least-authority-first order;
- add source/symbol/entitlement checks proving the qualification listener and receipt writer are unavailable in production configuration.

Acceptance:

- six scenarios each fire exactly once and a seventh unarmed control run has no injected outcome;
- kill at every receipt write/rename/fsync/cleanup boundary converges to a valid old or complete new state;
- replay, symlink, hard-link, ownership, mode, digest, generation, scenario, and phase substitution tests fail closed;
- one cleanup-safe command produces a canonical evidence report bound to source commit, PKG digest, Team ID, code identities, OS/hardware lane, and scenario result.

Dependencies: the notarized candidate checkpoint, protected runner entitlement, real Device API Grant/Lease route, and both Mac runners. Work on packaging tests and evidence schema can proceed in parallel; edits to the XPC protocol, durable receipt schema, and root storage layout are serialized.

Immediate remaining gates:

1. compose the qualification repository, Human API, Device API, purpose-separated KMS signer, and pinned verification keys in the hosted runtime; add readiness and rotation checks that fail closed when either Grant or manifest verification is unavailable;
2. package a fixed signed native executable around `NativeQualificationGrantBatchHTTPClient`, call it from the root relay without mutable executable selection, and prove that cookies, browser sessions, bearer credentials, proof bytes, and private keys never cross the boundary;
3. bind the suite digest and seven public step digests into the canonical hardware report and independent verifier rather than relying on workflow log output;
4. finish release-stage recovery and prove interruption behavior at every release copy/trust publication, input publication, run-binding, receipt, restart, disarm, restore, and cleanup boundary;
5. execute the exact source commit and notarized PKG on Apple Silicon and Intel T2 lanes and retain the untouched signed reports;
6. only after both reports independently validate, change the six scenarios and unarmed control from locally verified to physically qualified.

### Wave 2 — first usable Claude Code path

Implementation:

- ship `agentpass install`, `agentpass setup`, `agentpass doctor`, `agentpass launch --agent claude-code`, and repository-local Git signing configuration;
- enroll the Secure Enclave device identity, select organization/repository/worktree/branch/scope/TTL, and install a least-authority policy;
- launch the pinned Claude Code process through the signed Agent Host so the process/ancestry observation and FD handoff are created by one trusted path;
- implement status, close, expiry, revoke, offline-deny, and actionable diagnostics without exposing authority-bearing material;
- preserve existing Git configuration and provide an exact, resumable uninstall/rollback path.

Acceptance:

- a new user completes setup and two unattended verified commits using documented commands;
- changed executable, PID reuse, ancestry, repository, worktree, branch, operation, TTL, generation, and proof replay are denied;
- secrets and reusable capabilities are absent from process listings, environment, shell history, repository files, logs, crash reports, and browser storage;
- install/upgrade/uninstall tests preserve or deliberately purge state according to the documented lifecycle.

Dependencies: Wave 1, current ControlBundle apply/ACK path, Human Grant issuance, Device Lease consumption, and a pinned supported Claude Code execution contract. CLI/onboarding copy and Git integration tests may proceed in parallel with native lifecycle work.

### Wave 3 — Cursor parity and real Console onboarding

Implementation:

- add Cursor only through a pinned, production-supported headless process identity and reuse the common Agent Host/session contract;
- remove all sample operational state from Console views;
- complete the guided flow for organization creation/selection, invitation and role administration, passkey lifecycle, device enrollment, repository policy, Agent launch instructions, session/audit visibility, revoke, and emergency stop;
- show pending/fetched/applied/blocked/stale/offline/revoked states from authoritative PostgreSQL data and signed ACKs, never from optimistic browser state;
- add keyboard, screen-reader, localization, conflict, expiry, recovery, and lockout behavior.

Acceptance:

- owner/admin/auditor/viewer Playwright matrices pass over production-built Console and Cloud with real PostgreSQL TLS and virtual WebAuthn;
- Claude Code and Cursor pass the same authorization and negative-substitution suite;
- a non-engineer can enroll, launch, verify commits, inspect audit, and revoke from one guided journey;
- revoke and emergency stop remain reductions only and cannot mint or widen native authority.

Dependencies: Wave 2 common session contract and authoritative audit upload/read model. Cursor adapter work and Console presentation may run in parallel after the shared API DTOs are frozen.

### Wave 4 — recovery, abuse resistance, and managed signing

Implementation:

- add PostgreSQL-backed shared rate limits, concurrent-session ceilings, organization session epochs, bounded WebAuthn ceremonies, and enumeration-safe errors;
- implement versioned threshold owner recovery with hashed one-time material, restricted recovery sessions, passkey re-enrollment, and fresh operation-bound recent WebAuthn;
- move bundle, capability, refresh, Console identity, and qualification/release evidence signing behind purpose-separated KMS/HSM keys and IAM;
- implement rotation, retiring-key verification windows, drain, rollback refusal, audit, alerts, and disaster-recovery procedures;
- finish native hash-chain audit upload and authoritative Cloud/Console observation.

Acceptance:

- two-instance race tests prove shared throttles and one-time recovery consumption;
- no support operator or single lost owner can silently seize an organization;
- KMS outage, timeout, response loss, version rollback, and cross-purpose/key substitution fail closed or replay the exact committed result;
- backup/PITR restore and signer rotation drills preserve tenant isolation, generations, audit continuity, and revocations.

Dependencies: stable hosted schemas from Waves 2–3. Recovery and KMS adapters can be built in parallel but promotion waits for joint incident and restore drills.

### Wave 5 — signed distribution and production promotion

Implementation:

- build universal, reproducible release artifacts; generate SBOM, provenance, nested code-identity manifest, and checksums;
- sign with Developer ID, notarize, staple, and publish one immutable PKG consumed by direct download, Homebrew bootstrap, and CI qualification;
- deploy immutable Cloud/Console images, run forward-only migrations through a separate role, and add canary, rollback, monitoring, paging, backup, and incident runbooks;
- commission an independent review of native/XPC/process binding, WebAuthn/recovery, tenant SQL/RLS, KMS IAM, installer lifecycle, evidence, and log redaction;
- promote through an allow-listed tenant cohort before general availability.

Acceptance:

- both physical Mac lanes and both Agent adapters pass against the same source commit and notarized PKG;
- browser, Cloud, PostgreSQL, native, packaging, upgrade, recovery, and rollback gates are linked from one signed promotion record;
- secret scans and artifact inspection pass, and there are zero unresolved critical/high findings or P0/P1 defects;
- rollback disables new authority without invalidating already-required audit and recovery evidence.

Dependencies: Waves 1–4 and external Apple/KMS/deployment credentials. Credential-dependent execution may be scheduled later, but no production-ready claim is made before the evidence exists.

## 13. Workstream ownership and merge cadence

Use four parallel workstreams with one integration owner:

| Workstream | Owns | Must not independently change |
| --- | --- | --- |
| Native/session | Agent Host, XPC service, Secure Enclave, process binding, local durable state | OpenAPI, SQL migration numbering, release identities |
| Cloud/data | Human/Device APIs, PostgreSQL transactions/RLS, audit ingest, KMS adapters | native XPC DTOs, installer paths |
| Console/onboarding | BFF DTOs, setup journey, WebAuthn UI, device/session/activity views | authority semantics, browser-held credentials |
| Qualification/release | protected runners, evidence schemas, package/notarization, deployment gates | product protocol or storage changes without integration review |

Merge cadence:

1. freeze or version any shared contract first;
2. land implementation plus deterministic negative tests in its owning workstream;
3. run cross-boundary integration and secret scans;
4. update the operator/user documentation and compatibility notes;
5. record modeled, integration, physical, and production evidence as different evidence classes;
6. promote only a clean commit that passes every gate required by the affected boundary.

## 14. Executable backlog from the frozen-contract baseline

This backlog turns the phases above into merge-sized increments. A batch is complete only when its code, negative tests, operator documentation, and evidence classification land together. Batches that change OpenAPI, canonical signing bytes, SQL migration numbers, XPC selectors, entitlements, installer paths, or release identities require integration-owner review before parallel work resumes.

### Batch 0 — close the Phase 1 contract inventory

Scope:

1. promote organization, membership, invitation, WebAuthn credential/ceremony/recent authorization, policy, capability, ControlBundle, purge authorization/receipt, and promotion evidence into closed versioned JSON Schemas;
2. replace duplicated inline OpenAPI components with external schema references;
3. pair every promoted schema with a public, secret-free positive fixture and fail validation on missing required or unknown top-level fields;
4. add each schema to the frozen catalog with its actual authority, tenant source, actor source, idempotency, expiry, signing domain, implementation references, and compatibility fixture;
5. preserve separate schema versions and mutable resource revisions, and explicitly reject mixed-version downgrade paths.

Done when `npm run contracts:validate`, the catalog tests, the full Node suite, the Swift suite, Console build/tests/lint, package checks, and secret scans pass from one clean commit. Phase 1 may then close only after a final inventory confirms that device and agent identity read models are either already represented by existing enrollment/session schemas or receive explicit standalone schemas.

### Batch 1 — organization and human-session authority

Merge slices:

1. PostgreSQL repositories for organization creation, invitations, acceptance, membership role/status changes, and organization/member session epochs, always reserving the first SQL parameter for `organization_id`;
2. transactionally enforced Owner/Admin/Auditor/Viewer permissions, last-owner protection, invitation expiry/one-time consumption, and role-downgrade session invalidation;
3. rotating opaque server-side sessions with hashed tokens, CSRF binding, absolute and idle expiry, device/session inventory, revoke-one, revoke-all, and enumeration-safe errors;
4. Human API handlers generated from the frozen DTOs without leaking passwordless ceremony state or reusable bearer material;
5. audit records for every authority change, including denied attempts, with stable reason codes and no secrets.

Required tests:

- two-organization read/write isolation for every repository and route;
- concurrent invitation acceptance, last-owner demotion, session rotation, revoke, and epoch-change races against real PostgreSQL;
- process-kill tests at transaction commit/response-loss boundaries proving exact retry behavior;
- property tests for unknown fields, stale versions, tenant substitution, and actor substitution.

### Batch 2 — production WebAuthn and recovery

Implementation checkpoint (2026-08-14): slices 1–4 are implemented and covered by focused, full-suite, Console, and real-PostgreSQL qualification tests. Registration of a second credential fails closed without an operation-bound proof and consumes that proof in the same credential-set transaction; first-credential bootstrap is serialized under the same credential lock. Both authentication and registration claims have bounded verifier deadlines and stale-consuming recovery. Slice 5 and the recovery portions of the browser matrix remain open; the current implementation must not be represented as threshold-owner recovery capable. The required slice-5 state machine and negative evidence are fixed in [THRESHOLD_OWNER_RECOVERY_DESIGN.md](./THRESHOLD_OWNER_RECOVERY_DESIGN.md).

Merge slices:

1. registration options, attestation verification, credential metadata storage, list/rename/revoke, and authentication options/assertion verification using exact production RP ID and allow-listed HTTPS origins;
2. durable one-time ceremonies storing only challenge digests, bounded attempts, short expiry, consuming state, exact retry semantics, and cleanup;
3. sign-counter handling that distinguishes reliable counters, zero/non-incrementing authenticators, backup eligibility/state changes, and cloned-credential risk without accidental lockout;
4. operation-bound recent authorization for role changes, emergency stop, device revoke, recovery changes, and purge, consumed atomically with the protected mutation;
5. versioned threshold-owner recovery with hashed one-time material, restricted recovery sessions, passkey re-enrollment, delay/notification controls, and a fresh recent authorization before authority is restored.

Required tests:

- Playwright virtual-authenticator coverage for registration, login, step-up, credential loss, revoke, and recovery;
- negative origin, RP ID, challenge replay, counter rollback, cross-session, cross-member, cross-organization, expiry, and concurrent-consumption cases;
- recovery tests proving that neither one support operator nor one lost owner can silently take over an organization.

### Batch 3 — authoritative Device API and PostgreSQL operations

Merge slices:

1. production route composition for enrollment, possession challenge/receipt, bundle refresh, signed ACK, audit ingest, Agent Session Grant consumption, revoke, emergency stop, and qualification Grant batches;
2. transactional repositories for generations, replay ledgers, nonce rotation, exact retries, outbox/ACK state, audit chain heads, recovery journals, and bounded retention;
3. one forward-only migration job per deployment, startup schema compatibility checks, TLS-required least-privilege roles, RLS defense in depth, backup/PITR, and restore verification;
4. PostgreSQL-backed shared rate limits and concurrent-session ceilings that remain effective across API replicas;
5. metrics and alerts for signer failures, stale bundles, replay denial, tenant-binding denial, outbox lag, audit-chain gaps, migration drift, and restore health.

Required tests:

- real PostgreSQL contention and process-kill matrices for every one-shot or exact-retry transition;
- tenant SQL static review plus dynamic cross-tenant tests under both application roles and RLS;
- restore tests proving consumed grants remain consumed and authoritative generation/audit heads are unchanged.

### Batch 4 — managed signer separation

Merge slices:

1. move capability, ControlBundle, refresh hint, possession receipt, Agent Session Grant, qualification manifest, and promotion evidence signing behind distinct KMS/HSM keys and workload identities;
2. pin algorithm, purpose, key ID, and key version into the signed contract and public evidence; never accept caller-selected signing purpose;
3. implement rotation with explicit active/retiring/revoked states, bounded verification overlap, drain checks, rollback refusal, and emergency disable;
4. make response-loss retries return the exact previously committed signed bytes rather than producing a second authority object;
5. document IAM, rotation, outage, compromise, restore, and audit procedures.

Required tests:

- IAM tests proving each service can invoke only its assigned signing purpose and cannot export key material;
- cross-purpose, cross-key, old-version, algorithm, malformed-response, timeout, outage, and response-loss tests;
- rotation and restore drills preserving verification of required historical audit/evidence while denying new authority from retired keys.

### Batch 5 — Console product journey

Implement the production-built Console as a thin, secret-free control surface over authoritative Human API state. The screen order is: sign in/passkey → organization selection/create → invite and roles → device enrollment → repository policy → Claude Code/Cursor launch instructions → active sessions → audit → revoke/emergency stop → purge. Every optimistic action must reconcile to PostgreSQL state or a signed device ACK before displaying success.

Acceptance includes Owner/Admin/Auditor/Viewer Playwright matrices, keyboard and screen-reader flows, mobile-safe recovery, localization-ready copy, expired/conflict/offline states, CSP/CSRF/cookie checks, and proof that credentials, challenges, capabilities, private evidence, and reusable tokens never enter browser storage or telemetry.

### Batch 6 — native onboarding and agent adapters

Merge slices:

1. resumable `verify → initialize → enroll → bind organization/device → install policy → connect agent → test signed commit` state machine shared by the app and CLI;
2. `agentpass install`, `setup`, `doctor`, `launch`, `status`, `close`, `revoke`, and lifecycle-safe uninstall/purge commands with actionable, secret-free diagnostics;
3. pinned Claude Code adapter first, then Cursor parity, both launched by the signed Agent Host with verified process/ancestry identity and fixed-FD activation transfer;
4. preserve existing Git configuration, deny repository/worktree/branch/operation/TTL/generation substitutions, and keep all private keys inside Secure Enclave/Keychain/XPC boundaries;
5. upgrade, rollback-refusal, uninstall-preserve, reinstall-recover, and explicit purge journals that converge safely after interruption.

Acceptance is two unattended verified commits per adapter, plus negative executable/PID-reuse/ancestry/scope/replay tests and clean-machine lifecycle tests with no secrets in argv, environment, shell history, repository files, logs, crash reports, or browser storage.

### Batch 7 — signed distribution and qualification

1. create one universal hardened-runtime PKG containing the app, XPC services, launchd jobs, helper, CLI, and signer;
2. generate SBOM, provenance, nested code-identity manifest, checksums, notarization evidence, and an independently verifiable promotion record;
3. publish direct download and Homebrew bootstrap paths that both fetch and verify the exact same immutable PKG; provide offline verification;
4. deploy immutable Console/API/worker images with a separate migration role, canary, rollback, observability, paging, backups, and incident runbooks;
5. run browser-to-Cloud-to-device-to-Secure-Enclave E2E and all 16 physical gates on Apple Silicon and Intel T2 against the same commit and PKG;
6. complete independent security review, fix every critical/high finding, and attach accepted lower findings to an owner and deadline.

Promotion is allowed only when one signed record binds the commit, image and PKG digests, nested identities, Team ID, notarization ticket, migration set, signer key versions, browser/E2E evidence, security review, restore drill, and both untouched physical-Mac reports.

### Recommended merge order and parallelism

The next critical path is Batch 0 → Batch 1 session/organization core → Batch 2 WebAuthn step-up → Batch 3 authoritative Device API → Batch 6 Claude Code vertical slice. In parallel, Console presentation can follow frozen Human DTOs, managed-signer adapters can follow frozen signing domains, and packaging automation can follow frozen native identities. Cursor parity, recovery, broad UI polish, and production promotion follow the first Claude Code end-to-end path so they reuse a proven authority lifecycle instead of creating a second one.

At each merge boundary run, at minimum:

```text
npm run contracts:validate
npm run lint
npm test
npm run test:native
npm run test:native-app
npm run test:native-installer-preservation
npm test --prefix apps/web-console
npm run lint --prefix apps/web-console
```

Add real PostgreSQL, Playwright, packaging/notarization, KMS/IAM, restore, and physical-lane gates whenever the changed boundary requires them. A modeled or skipped test is never reported as production or physical evidence.
