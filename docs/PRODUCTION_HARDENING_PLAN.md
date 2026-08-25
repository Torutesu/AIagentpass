# AgentPass production hardening plan

Status: implemented hardening design for v0.18–v0.20. Security invariants in this document remain release gates.

Implementation checkpoint (2026-08-12): the lifecycle, bootstrap, legacy migration, audit-key rotation/recovery, crash-safe activation, retention/prune, deletion-evidence, installer, and signed-release foundations described below are implemented and covered by the repository test suite. Protocol v13 exposes the production prune workflow in addition to lifecycle and recovery operations. Prune rollback detection uses a fresh nonce-bound, Ed25519-signed Node receipt-head envelope and short-lived one-shot observations; retained archive identities are descriptor-relatively revalidated and held by FD lease through irreversible audit-key deletion. The remaining release gates require external credentials or hardware: publishing a Developer ID-signed and notarized artifact, configuring protected release environments, qualifying on physical Intel/Apple-silicon Secure Enclave hardware, and moving the separately administered anchor signing key to an HSM/KMS-grade boundary.

## Scope and ordering

The remaining production work is split into three independently testable tracks:

1. v0.18 — native key lifecycle: signing, audit-checkpoint, and human-approval key rotation, retirement, deletion, and recovery enrollment;
2. v0.19 — bounded checkpoint and anchor-receipt storage with cryptographically continuous archival;
3. v0.20 — reproducible universal packaging, Developer ID/notarization release automation, installer artifacts, provenance, and hardware qualification.

The Platform authenticator is an additional protected operations gate. Its
production configuration and qualification contract are maintained in
[PLATFORM_AUTH_PRODUCTION_OPERATIONS.md](PLATFORM_AUTH_PRODUCTION_OPERATIONS.md)
and [PLATFORM_AUTH_QUALIFICATION.md](PLATFORM_AUTH_QUALIFICATION.md). The
secret-free local preflight cannot substitute for real ingress mTLS, workload
identity, durable WebAuthn, provider/KMS, rotation, or two-instance evidence.

The current code-to-evidence reconciliation is maintained in
[PRODUCTION_READINESS_AUDIT_2026-08-20.md](PRODUCTION_READINESS_AUDIT_2026-08-20.md).
Promotion stop conditions are normative in [RELEASE.md](RELEASE.md), and
emergency containment/revoke/uncertain-signing procedure is in
[INCIDENT_AND_REVOKE_RUNBOOK.md](INCIDENT_AND_REVOKE_RUNBOOK.md). The design
and local implementation checkpoints below must not be read as external
qualification or production approval.

The executable operator packet is indexed in [`docs/runbooks/README.md`](runbooks/README.md).
Every external gate must have a redacted canonical record bound to the
candidate source commit, full source tree, artifact/deployment digest, run/job
IDs, command, timestamps, and result digest. `not_run`, `failed`,
`not_proven`, skipped, simulated, ad-hoc, or local-only output is a blocker;
retain it as failure evidence rather than normalizing it into success.

The tracks may be implemented in parallel after this design is accepted, but key lifecycle state is merged before checkpoint archival because archived checkpoints must retain their signing-key generation. Release automation is merged independently and must never expose signing or notarization credentials to pull-request jobs.

## Global invariants

- No private key is exportable. “Recovery” means authorizing a new hardware-bound generation, never restoring old private key bytes.
- Every authority increase or destructive key action requires a one-time, 60-second management challenge and a valid human-presence signature.
- Rotation is a two-key ceremony: the retiring key signs the transition and the replacement key proves possession over the same canonical statement.
- Generation numbers are strictly monotonic. Same-generation equivocation, state rollback, tag reuse, and public-key substitution fail closed.
- A lifecycle transition is durable before the service exposes the replacement key. A crash may leave an unactivated staged key, but may not produce two active generations.
- Any accepted key transition revokes all sessions and pending approvals.
- Audit and checkpoint verification remains possible after private-key deletion because every historical public key and transition statement remains in protected state.
- Local protected state alone cannot prove history after full root compromise. Lifecycle heads, checkpoints, receipts, release checksums, and recovery material must be pinned outside the host.
- User-writable configuration cannot select native keys, rotate trust, lower retention, or bypass XPC authorization.

## v0.18: native key lifecycle

### Roles

Three roles are managed independently:

- `git_signing`: background Secure Enclave key used only for SSHSIG Git signatures;
- `audit_checkpoint`: background Secure Enclave key used only for checkpoint signatures;
- `session_approval`: Secure Enclave key whose private-key use requires human presence.

Tags become generation-specific: `<configured-base-tag>.g<generation>`. Generation 1 may adopt the existing un-suffixed tag once, recording it as a legacy tag so an upgrade does not silently replace deployed keys.

### Protected lifecycle state

The root-owned service configuration adds:

- `key_lifecycle_directory` — private directory containing one immutable record per lifecycle sequence;
- `key_lifecycle_pin_directory` — private directory containing immutable prepare/pin records for every lifecycle head advance;
- `key_lifecycle_expected_head_hash` — legacy static external pin, optional only during migration and required to agree with the journal pin when both are present;
- `recovery_public_keys` — optional pinned offline Ed25519 SPKI keys used only for disaster re-enrollment;
- `retired_key_minimum_age_seconds` — bounded to 86,400–31,536,000, default 2,592,000;
- `key_lifecycle_archive_directory` — root-owned mode `0700`, same filesystem as state.

Each record is canonical JSON, created without overwrite, changed to mode `0400`, and followed by file/directory fsync. Replay derives:

- schema version and monotonic state sequence;
- one active generation per role;
- generation, application tag, public key, fingerprint, creation time, activation time, retirement time, and deletion time;
- append-only transition records;
- the previous and current lifecycle head hashes;
- the fingerprint of the pinned approval or recovery authority that authorized the transition.

Each transition statement binds role, old/new generation, old/new fingerprint, state sequence, reason, challenge ID, creation time, and previous lifecycle head. `git_signing` and `audit_checkpoint` transitions carry valid P-256 signatures from both old and new keys. `session_approval` transitions carry human-presence signatures from both approval generations. Recovery transitions carry the offline Ed25519 recovery signature and are marked `recovery=true`; they never assert continuity of unavailable private keys.

### External pin transaction and mutation outbox

Every lifecycle mutation uses write-ahead ordering; returning a new head and asking an operator to edit configuration is not an acceptable transaction:

1. deterministically construct the exact next lifecycle record and preview its record hash;
2. durably write the exact replay payload to the mutation outbox (public metadata and signatures only, never private keys);
3. durably append an immutable external-pin `prepare` record binding operation UUID, role/action, old/new heads, sequence, and timestamp;
4. append the immutable lifecycle record;
5. append the matching immutable pin commit;
6. append the outbox completion record;
7. only then return success and append the service audit outcome.

At startup, an outbox/pin pair with the old ledger head replays only its byte-identical mutation. A pair with the exact new head completes the pin and outbox after verifying the lifecycle record. Any third head, missing pair, hash mismatch, UUID reuse, sequence gap, or operation equivocation stops startup. This removes both lost-response ambiguity and the crash window between pin preparation and ledger mutation. A pending pin without its exact outbox payload is not cancellable or guessed safe.

The pin and outbox roots reject symbolic-link ancestors, hard links, permissive ownership/modes, path/FD inode changes, unknown entries, noncanonical records, and overwrite. Every immutable file and parent directory is synchronized before the next state-machine step.

### Audit-key activation transaction

`audit_checkpoint` activation has an additional external ordering constraint. The daemon must not
activate a replacement audit key until the anchor has accepted the exact old-key boundary and the
dual-signed key transition. The operation is:

1. verify the complete audit, checkpoint, and anchor-receipt chains;
2. require the latest checkpoint to equal the current audit `(entries, head_hash)` and require
   anchor `pending == 0`;
3. freeze audit-producing operations for the bounded activation challenge lifetime;
4. obtain the human approval signature and construct the exact canonical lifecycle activation
   record, without appending it;
5. bind the transition to that record's predicted lifecycle head, the final checkpoint and
   receipt, the previous transition/receipt heads, and both audit-key generations;
6. persist the byte-exact dual-signed transition plan in the rotation-plan journal and fsync it;
7. submit exactly those bytes to the anchor, verify the Ed25519 receipt, and append the exact
   transition/receipt pair to the protected transition store;
8. mark the plan journal complete with the verified receipt hash;
9. only then execute lifecycle outbox → pin prepare → ledger append → pin commit → outbox complete;
10. revoke sessions, unfreeze the audit path, append the activation audit event, and fail-stop the
    old daemon instance until restart loads the new audit signer.

After a crash or lost HTTP response, startup loads the sole pending plan. If the transition store
already contains its exact transition and receipt it completes the journal without resubmission;
otherwise it resends only the retained canonical bytes. A changed checkpoint boundary, lifecycle
head, operation UUID, generation, key, transition hash, receipt hash, or third state fails closed.
There is no API that reconstructs a plan from current state or discards an ambiguous pending plan.

### State machine

`active -> staged -> activated -> retired -> deleted`

- `stage`: create a new non-exportable key and persist its public metadata. It grants no authority.
- `activate`: verify the one-time management challenge and both possession proofs, append the transition, atomically switch active generation, revoke sessions, and append an audit event.
- `retire`: is implicit for the previous generation at activation. Retired keys cannot sign normal operations.
- `delete`: allowed only for a retired generation, after the minimum age, after its public metadata and transition have been durably archived, and after a fresh human-presence challenge. Deletion is idempotent; `errSecItemNotFound` is accepted only when state already says deleted.
- `abort`: delete an unactivated staged key after human authorization. It does not advance the active generation but does advance lifecycle sequence and audit history.

Crash recovery rules:

- key created, state not written: the deterministic staged tag is treated as an orphan and is never used; a repair command may delete it after authorization;
- staged state written, activation absent: old key remains active;
- transition archive written, active state replacement absent: startup completes activation only when archive and both signatures exactly match the expected next state;
- active state replaced: new generation is authoritative even if the success response was lost;
- key deletion succeeds, final state update fails: startup compares the keychain and signed deletion intent, then records deletion without regranting authority.

### Management authorization

XPC adds `beginKeyOperation` and `completeKeyOperation`. Challenges bind:

- protocol version and action;
- role and target generation/fingerprint;
- current lifecycle sequence/head;
- a random nonce and challenge ID;
- issued/expiry timestamps;
- operator reason;
- for recovery, a hash of the proposed recovery transition file.

The native client displays these exact values in the Local Authentication prompt. It must not sign server-supplied free-form text that is absent from the visible prompt. Challenges are consumed on every completion attempt, including malformed or invalid signatures, and are bounded globally and per role.

CLI surface:

```text
agentpass native key status
agentpass native key stage git-signing|audit-checkpoint|session-approval
agentpass native key activate ROLE --reason TEXT
agentpass native key abort ROLE --reason TEXT
agentpass native key delete ROLE GENERATION --reason TEXT --confirm DELETE_RETIRED_KEY
agentpass native key recovery-request > recovery-request.json
agentpass native key recover recovery-transition.json --confirm RECOVERY_REENROLLMENT
agentpass native key export-history > key-history.json
```

`stage` for the approval role is executed by the signed client because its new private key requires user presence; the service receives only its public key and proof. Other roles are created by the privileged service in its keychain access group.

### Audit checkpoint compatibility

Checkpoint schema v2 adds `key_generation` while retaining `public_key_fingerprint`. Verification selects the historical public key from lifecycle state. A v1 checkpoint log is accepted only as the generation-1 prefix. The first v2 checkpoint after audit-key rotation must bind the lifecycle transition hash and the previous checkpoint hash. Anchor enrollment remains algorithm-pinned, but an enrolled tenant gains a signed key-transition endpoint; the anchor accepts a new checkpoint key only when the transition is signed by the currently enrolled key and proves possession of the replacement key.

### Recovery model

Recovery is an explicit discontinuity, not a false continuity claim:

1. an offline recovery key is generated and its public key is installed root-owned during provisioning;
2. the compromised or replacement host exports a canonical recovery request containing host identity, last externally pinned lifecycle/checkpoint/receipt heads, proposed public keys, and a nonce;
3. an offline tool shows all values and signs the request;
4. the service verifies the pinned Ed25519 key, requires local human presence, records a recovery transition, revokes sessions, and refuses normal signing until policy and remote-control state are revalidated;
5. Git hosting and the audit anchor must enroll the new public keys out of band.

Loss of both active hardware keys and the offline recovery key is unrecoverable by design.

### v0.18 acceptance tests

- software P-256 fixtures cover successful three-role rotation and historical verification;
- old keys cannot sign after activation; new keys cannot sign before activation;
- challenge mutation, replay, expiry, wrong role, wrong generation, and approval-key substitution fail closed;
- state rollback, sequence reuse, transition equivocation, tag reuse, and keychain/state disagreement fail closed;
- every activation and recovery invalidates existing and pending sessions;
- crashes are injected after every durable step and converge to exactly one active generation;
- v0.17 state upgrades without replacing the existing keys;
- deletion refuses active, young, unarchived, or externally unpinned generations;
- recovery requires both offline signature and local human presence;
- OpenSSH verifies signatures before and after Git-key rotation;
- checkpoint and anchor chains verify across audit-key rotation.

## v0.19: checkpoint and receipt archival

### Segment model

Checkpoint and receipt logs gain separate root-owned mode-`0700` archive directories. Active files rotate only after 64 MiB and before the existing 128 MiB verification ceiling.

Checkpoint archive names bind the terminal global ordinal and checkpoint hash:

`checkpoints-<20-digit-count>-<64-hex-checkpoint-hash>.jsonl`

Receipt archive names bind the terminal receipt index and receipt hash:

`receipts-<20-digit-index>-<64-hex-receipt-hash>.jsonl`

Segments are mode `0400`, on the same filesystem as the active file, and are created by atomic rename followed by file and directory fsync. Unknown entries, duplicate terminal ordinals, gaps, filename/content disagreement, symlinks, ownership changes, and permissive modes fail closed.

### Continuity and pending anchors

- Checkpoint verification carries previous checkpoint hash, nondecreasing audit entry count, timestamp, key generation, and lifecycle transition across every segment.
- Receipt verification carries receipt hash, receipt index, timestamp monotonicity, tenant, and corresponding global checkpoint ordinal across every segment.
- Pending-anchor calculation uses global checkpoint and receipt ordinals, never array offsets from only the active files.
- Receipt rotation is forbidden while its terminal receipt does not cover the corresponding checkpoint prefix.
- Checkpoint rotation is forbidden when an unanchored checkpoint in that segment would become unavailable to the uploader.
- Rotation creates a compact signed segment descriptor containing first/last ordinals and hashes, byte length, SHA-256 digest, creation time, and lifecycle head.

### Retention

Local pruning is a separate destructive operation, disabled by default. It requires:

- an operator-configured minimum age and minimum retained segment count;
- proof that the segment descriptor and terminal checkpoint/receipt are accepted by a configured remote archive or anchor;
- a fresh human-presence challenge;
- a tombstone in the local retention ledger before unlink;
- directory fsync after unlink.

Without remote archive proof, AgentPass supports rotation but never pruning.

CLI and status add checkpoint/receipt segment counts, active bytes, rotation readiness, oldest retained ordinal, pending anchor count, and prune eligibility.

### v0.19 acceptance tests

- multiple checkpoint and receipt segments verify after restart;
- pending checkpoints upload in order across segment boundaries;
- mutation, deletion, reordering, duplicated ordinal, bad filename, and unknown archive entry fail closed;
- rotation below threshold and cross-filesystem archives are refused;
- crash injection around rename, chmod, state replacement, and fsync preserves one valid interpretation;
- pruning is impossible without remote proof and human authorization;
- bounded verification applies per segment while global counts remain monotonic.

## v0.20: signed distribution and hardware qualification

### Credential-free repository work

The repository will include:

- `build-release.sh`: clean universal build, exact architecture verification, hardened-runtime signing validation, deterministic ZIP and component package creation;
- `verify-release.sh`: offline verification of identifiers, Team ID, designated requirements, entitlements, provisioning profile, nested signatures, notarization ticket, Gatekeeper assessment, architectures, versions, checksums, and package payload;
- `generate-sbom.mjs`: CycloneDX JSON for npm and Swift source inputs;
- release manifest containing version, git commit, artifact sizes, SHA-256 hashes, signing identity metadata, minimum macOS version, and SBOM hash;
- release runbook and hardware qualification report template;
- CI tests that build and verify ad-hoc arm64 artifacts and reject malformed manifests, unsafe output paths, architecture omissions, and version drift.

The production bundle must not rely on one outer-app provisioning profile for differently identified restricted helpers. The service and approval client become separately provisioned nested app-like helper bundles. The service receives only `TEAMID.dev.agentpass.service-keys`; the approval client receives only `TEAMID.dev.agentpass.approval-keys`; the manager receives no keychain access group. The service and client profiles must each match their exact bundle identifier and entitlement set. A shared service/client keychain group is a release-blocking least-privilege violation.

Target layout:

```text
AgentPass.app/Contents/
  MacOS/agentpass-onboarding
  MacOS/agentpass-native-manager
  Library/LaunchDaemons/dev.agentpass.native-service.plist
  Library/HelperTools/AgentPassNativeService.app/Contents/{Info.plist,embedded.provisionprofile,MacOS/agentpass-native-service}
  Library/HelperTools/AgentPassNativeClient.app/Contents/{Info.plist,embedded.provisionprofile,MacOS/agentpass-native-client}
```

`BundleProgram` must resolve to the nested service executable. Signing proceeds from inner executables and helper bundles to the outer app, without using `codesign --deep` as a signing mechanism.

### Credentialed release workflow

A manually dispatched, protected GitHub environment imports a short-lived Developer ID certificate and notarization API credentials, builds from a signed tag, produces universal artifacts, submits to Apple, staples tickets, runs `spctl`, generates checksums/SBOM/manifest, signs the manifest, uploads artifacts, and publishes only after all verification jobs pass. Pull requests receive no release secrets and cannot invoke the protected environment.

Artifacts:

- `AgentPass-<version>-universal.zip`;
- `AgentPass-<version>-universal.pkg` with explicit install scripts and uninstall documentation;
- `AgentPass-<version>.cdx.json`;
- `AgentPass-<version>-manifest.json` and detached signature;
- checksums and notarization evidence.

The installer must never overwrite root-owned policy, lifecycle, audit, checkpoint, receipt, or archive data. Upgrades replace only the signed app and service registration material. Uninstall is split into application removal and an separately confirmed data/key purge.

### Hardware matrix

Required release evidence:

- Apple silicon, latest supported macOS: install, approval, Secure Enclave key creation, unattended sign, session expiry/revocation, all key rotations, audit rotation, sleep/wake, reboot, upgrade, uninstall-preserve;
- Intel Mac with T2, supported macOS: same scenarios and x86_64 slice execution;
- Apple silicon under Rosetta: x86_64 client/manager interoperability where applicable;
- negative tests for unsigned/re-signed clients, altered daemon plist, wrong Team ID, wrong keychain group, unstapled artifact, offline notarization check, and denied Service Management approval.

Hardware results record model identifier, CPU architecture, macOS build, Secure Enclave availability, artifact hashes, timestamps, and pass/fail evidence. A release is not described as production-hardened until both required hardware classes pass the exact candidate hashes.

### External gates

The following cannot be proven by repository-only CI and remain explicit release blockers until credentials/hardware are supplied:

- Developer ID certificate chain and authorized provisioning profile;
- Apple notarization acceptance and stapled ticket;
- protected release-environment configuration;
- Apple silicon and Intel/T2 qualification against final artifact hashes;
- external Git-hosting and audit-anchor key enrollment during recovery.

Repository work is complete only when scripts fail closed in the absence of those inputs and documentation does not claim that simulated/ad-hoc evidence satisfies them.

## Final audit gate

Before marking this plan complete, reviewers must map every invariant and acceptance test above to code, tests, CI output, a signed release artifact, or an explicit external-gate record. “No issue found,” a green unit-test subset, or an ad-hoc signature is not sufficient evidence. At least one independent review must inspect authorization prompts, keychain deletion queries, lifecycle crash recovery, archive boundary calculations, installer preservation rules, and secret exposure in workflows.

The final audit packet must include the completed checklists from
[`RELEASE_PROMOTION_RUNBOOK.md`](runbooks/RELEASE_PROMOTION_RUNBOOK.md),
[`INCIDENT_REVOKE_RUNBOOK.md`](runbooks/INCIDENT_REVOKE_RUNBOOK.md),
[`KMS_POSTGRES_QUALIFICATION_RUNBOOK.md`](runbooks/KMS_POSTGRES_QUALIFICATION_RUNBOOK.md),
[`MACOS_RELEASE_NOTARIZATION_RUNBOOK.md`](runbooks/MACOS_RELEASE_NOTARIZATION_RUNBOOK.md),
and [`STAGING_DRILL_SECURITY_REVIEW_RUNBOOK.md`](runbooks/STAGING_DRILL_SECURITY_REVIEW_RUNBOOK.md).
The approver must verify every stop condition from retained evidence or leave
the decision explicitly `STOP`; a plan update cannot waive an external gate.
