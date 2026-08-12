# Native macOS broker

AgentPass 0.17 implements the native security boundary described by ADR-001. It is a Swift 6 package with four components:

- `AgentPassNativeCore`: Secure Enclave P-256 key management, OpenSSH SSHSIG encoding, signed Agent request verification, protected sessions and remote control, replay prevention, policy/Git validation, and protected audit primitives;
- `agentpass-native-service`: a privileged Mach XPC service that owns the signing key, session hashes, audit key, root-owned policy and control state, audit chain, and checkpoint chain;
- `agentpass-native-client`: a bounded bridge used by the Node signing wrapper and native management commands.
- `agentpass-native-manager`: the app host and `SMAppService` register/status/unregister entry point.

The repository now assembles the required app layout, signs its nested executables, supports universal binaries and notarization, and verifies identifiers and keychain access groups. It is not a pre-signed binary distribution. Production installation still requires an Apple Developer Team ID, matching provisioning, signing credentials, notarization credentials, and hardware validation. An ad-hoc build is suitable only for structure tests and does not activate the claimed client-identity and keychain-access-group boundary.

## Security boundary

Every signing call is checked again inside the XPC service. The service:

1. restricts XPC connections to one configured UID and Apple code-signing requirement;
2. reads a root-owned, non-group/world-writable version 4 policy at startup;
3. verifies the Agent's Ed25519 signature over canonical request JSON;
4. enforces the currently persisted offline-signed control bundle, including expiry and global/per-Agent revocation;
5. validates an Agent-bound, in-memory protected session when policy requires it;
6. enforces a 60-second timestamp window and bounded nonce replay cache;
7. derives the Git root, branch, origin, tree, `HEAD`, and `MERGE_HEAD` itself;
8. applies both global and per-Agent operation/repository/branch/remote scope;
9. asks a non-exportable Secure Enclave P-256 key to produce an OpenSSH SSHSIG;
10. records every allow, deny, signer error, and control update before returning to the client.

When `control.required=true`, service startup requires both `control_state_path` and an initial validly signed bundle. Expiration is tolerated only while loading its remembered sequence; signing and new session issuance remain denied until a newer unexpired bundle is applied.

## Protected native remote control

The administration Ed25519 public key is pinned in the root-owned version 4 policy. The service accepts only bounded canonical version 1 bundles with a matching key fingerprint, a valid signature, UUIDv4 Agent IDs, at most seven days of validity, and a monotonically increasing JavaScript-safe sequence. Exact same-sequence reapplication is idempotent; rollback and same-sequence equivocation fail closed.

Every accepted higher control sequence also advances the native session generation, discarding active sessions and pending approvals. A session issued under an older control decision therefore cannot become usable again after a later unrevocation; the next operation requires a newly human-approved session. Re-fetching the exact active sequence does not revoke sessions.

Optional `control_url` and `control_refresh_seconds` fields in the root-owned service configuration enable an immediate startup fetch followed by dynamically scheduled refresh. Successful fetches use one-sided 90-100% jitter, so they never occur later than the configured 15-3600 second interval. Failures retry with 5-second exponential backoff and 75-100% jitter, capped at that same configured interval. A successful validated fetch resets the failure count. The URL must be credential-free HTTPS without a query or fragment. Redirects, non-200 responses, responses over 256 KiB, and request/resource timeouts are rejected without changing active state. Cookies and caches are disabled. Native health and `control status` expose the next attempt and consecutive failure count in addition to the last attempt, success, and error. Unchanged valid bundles do not create state writes or repeated allow events. Fetch failures are audited immediately, no more than once per five minutes when the failure changes, and hourly while unchanged.

For ControlBundle v2, configure all `control_v2_*` fields shown in `Resources/native-service.example.json`. `control_url` is the full per-device Cloud API bundle endpoint and `control_v2_device_key_tag` names a dedicated Secure Enclave P-256 key. The service signs each GET using the Cloud device-authentication protocol; the private key is non-exportable and is distinct from Git signing, audit signing, session approval, and the cloud Ed25519 bundle signer. `control status` exposes the device-authentication SPKI PEM for enrollment. Cloud response wrappers are parsed with duplicate/unknown-field rejection before bundle verification. The v2 signing path requires a recent successful authenticated refresh (at most twice the configured interval, with a 30-second floor) and therefore fails closed during a prolonged outage. The sample uses a 15-second interval, bounding online emergency-stop propagation to roughly 30 seconds. `agentpass control fetch` asks the native service to perform this authenticated refresh; it never downloads and applies a v1 bundle in the CLI.

The v2 state write is an audited transaction. A durable pending marker is written before applying a new sequence and cleared only after the protected audit append. A restart with an unfinished marker stays non-operational. Capability IDs, capability sequence evidence, exact signed requests, and signing results are persisted separately with owner-only files and file/directory fsync.

Accepted state is atomically replaced with mode `0600` and synchronized to disk and its parent directory. The file and existing ancestry are checked for ownership, permissions, regular-file type, and symlinks. Control application is serialized with signing and session changes. If the state changes but its allow audit event cannot be appended, the manager poisons itself and denies further use until the service is repaired and restarted.

An update creates `<control_state_path>.pending-audit` before touching state and removes it only after the audit append is durable. A crash at any intermediate point therefore remains fail-closed across restart. Recovery requires an operator to compare the signed state with the protected audit tail, repair the underlying failure, and remove the marker explicitly; the service never guesses that an interrupted update was safe.

## Protected native sessions

Session approval uses a third P-256 Secure Enclave key, separate from Git signing and audit signing. Its access control combines `privateKeyUsage` with `userPresence`, so using the private key requires Touch ID, Apple Watch, or the macOS login password. Apple documents these controls under [Local Authentication](https://developer.apple.com/documentation/localauthentication) and [`SecAccessControlCreateFlags.userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).

The service sends a 60-second, one-time challenge containing the Agent ID and bounded TTL. The final signed native client displays those values in the system authentication prompt and signs the exact challenge only after successful authentication. The root-owned service configuration pins the approval public key, verifies the P-256 signature, and then returns a random 32-byte token. It stores only the token hash, Agent ID, and expiration in service memory. Challenges cannot be replayed, altered, or approved by a different key.

Normal commits use the issued token without further human interaction. A service restart fails safe by losing all sessions. `agentpass native revoke-sessions` immediately removes active sessions and pending approvals and advances the in-memory generation. Session-start allow/deny and revocation outcomes enter the protected audit chain. Agent-triggered prompt spam remains an availability/social-engineering concern; challenges are globally and per-Agent bounded, and users should reject unexpected prompts.

## Protected native audit

Native signing events are JSON Lines records linked by `previous_hash` and a SHA-256 `hash` over canonical JSON. The audit and checkpoint files must be regular files owned by the service account with no group/world permissions. Their existing path ancestry must be root-owned, non-group/world-writable, and free of symbolic links. Appends use `O_NOFOLLOW`, an exclusive file lock, `fsync`, and mode `0600`.

Before accepting XPC traffic, and again on health, signing, checkpoint, and rotation operations, the service verifies the complete chains. Corruption, truncation behind a checkpoint, insecure permissions, ownership changes, key substitution, or an invalid checkpoint signature causes a fail-closed error. Each active or archived audit segment has a 128 MiB verification ceiling.

When `audit_archive_directory` is configured, every service audit append preflights its projected size. At 120 MiB it first signs a checkpoint, rotates the active segment, and only then appends, so signing and non-signing events cannot push the file through the 128 MiB verification ceiling. If archival or checkpointing is unavailable, the append fails before changing the log and reports the active, projected, rotation-threshold, and verification-limit sizes. Manual `agentpass native audit-rotate` remains available after 64 MiB. Rotation atomically renames the active file to `audit-<global-entry-count>-<terminal-head-hash>.jsonl`, changes it to mode `0400`, and fsyncs the file and directories. Verification then walks every segment in global entry order and carries the previous hash into the active log. Unknown directory entries, missing continuity, filename/content disagreement, symlinks, ownership changes, and permissive modes fail closed. The manual threshold prevents an Agent from creating an unbounded number of empty or tiny segments.

Checkpoints use a second, non-exportable Secure Enclave P-256 key. Schema v2 additionally binds the active key generation and lifecycle head. Verification resolves every historical key fingerprint from the protected lifecycle ledger, so rotating the active audit key does not make older checkpoints unverifiable. A v1 prefix remains readable for migration.

Audit-key activation is not a generic local key swap. The service freezes audit appends at an exact final checkpoint, requires zero pending anchor receipts, persists the dual-signed transition plus the exact signed lifecycle activation record, obtains and stores the anchor transition receipt, and only then commits the lifecycle outbox/pin/ledger transaction. A restart retries the same transition bytes and resumes the same lifecycle record; it never re-signs or invents a replacement challenge. Generation rollback, fingerprint reuse, and lifecycle-binding removal are rejected while verifying the complete checkpoint chain.

`audit_checkpoint_archive_directory` and `audit_anchor_receipt_archive_directory` enable independent 64 MiB checkpoint and receipt rotation. Segment filenames bind absolute first/last indexes and terminal hashes; verification carries both chains across all segments and rejects gaps, overlaps, substitutions, unknown entries, links, unsafe permissions, and cross-filesystem archives. `agentpass native audit-evidence-rotate` rotates only evidence logs that reached the threshold. Pending anchor calculation uses absolute receipt indexes across archived and active files.

The remote anchor accepts both local Ed25519 and native P-256 checkpoint tenants while pinning one algorithm and key per tenant. Native anchor configuration is root-owned; the service itself performs HTTPS submission, rejects redirects and responses over 512 KiB, verifies the returned Ed25519 receipt and both chains, and durably appends the receipt under protected ancestry. A lost response leaves the checkpoint pending, and retrying it returns the anchor's original receipt.

## Build and test

```sh
swift test --package-path native/macos
swift build -c release --package-path native/macos
npm run test:native-app
native/macos/scripts/build-app.sh --adhoc --force
```

The ad-hoc app test verifies the app layout, signing identifiers, embedded keychain access groups, daemon label/program/Mach service, manager diagnostics, strict code-signature validity, and fail-closed build options. It does not prove Apple Developer identity, Service Management registration, notarization, or Secure Enclave access.

For a production build, provide distinct service/client provisioning profiles and the final signing identity. Add `--universal` to build arm64 and x86_64 slices. Notarization is a separate release step; the bundle builder never claims an artifact was notarized:

```sh
AGENTPASS_SIGNING_IDENTITY="Developer ID Application: Example Corp (TEAMID1234)" \
AGENTPASS_TEAM_ID="TEAMID1234" \
AGENTPASS_APP_IDENTIFIER_PREFIX="TEAMID1234" \
native/macos/scripts/build-app.sh \
  --universal \
  --identity "$AGENTPASS_SIGNING_IDENTITY" \
  --team-id "$AGENTPASS_TEAM_ID" \
  --app-identifier-prefix "$AGENTPASS_APP_IDENTIFIER_PREFIX" \
  --service-profile ./AgentPassNativeService.provisionprofile \
  --client-profile ./AgentPassNativeClient.provisionprofile \
  --force
```

The build refuses missing or shared profiles, wrong Team ID/prefix/bundle ID/keychain group, development profiles, `get-task-allow`, expired profiles, symlinks, and unsafe overwrite. The service receives only `TEAMID.dev.agentpass.service-keys`; the approval client receives only `TEAMID.dev.agentpass.approval-keys`. Signing proceeds inner-to-outer without `codesign --deep` as a signing mechanism. Secure Enclave prompts and signed-XPC behavior still require a provisioned macOS integration environment and are not exercised by software-key tests.

## Bundle resources and installation inputs

Templates are under `native/macos/Resources/`:

- `dev.agentpass.native-service.plist` belongs in the signed app's `Contents/Library/LaunchDaemons` directory;
- the client and service entitlements must use the actual App Identifier Prefix;
- `native-service.example.json` must replace `TEAMID`, use the interactive user's UID, and be installed root-owned with mode `0600`.

Create `/Library/Application Support/AgentPass` as root with no group/world write permission. Create `audit-archive`, `audit-checkpoint-archive`, `audit-receipt-archive`, `audit-retention-archive`, and (when enabled) `key-lifecycle` children as root with mode `0700`. Install the approved version 4 policy there as `policy.json`, owned by root and not group/world writable. This copy—not `~/.agentpass/config.json`—is authoritative inside the service. If it contains `control.required=true`, install an initial signed bundle as `control.bundle.json`, root-owned with mode `0600`, and configure that absolute `control_state_path`. Add `control_url` and `control_refresh_seconds` to enable service-owned refresh. The configured state and audit paths must remain under protected root-owned ancestry.

Lifecycle-backed startup is opt-in. Set `key_lifecycle_directory`, `key_lifecycle_pin_directory`, `key_lifecycle_mutation_outbox_directory`, and `session_approval_key_tag`; partial configuration fails closed. The older `key_lifecycle_expected_head_hash` is accepted as a migration pin and must agree with the journal pin when both are present. Startup first resolves an exact outbox/pin/ledger transaction: an old head replays the canonical record bytes, a new head completes the pin and outbox, and every mismatch fails closed. It then requires the ledger head to equal the latest durable pin. The ledger must contain active `git_signing`, `audit_checkpoint`, and `session_approval` generations. The service loads exact existing Secure Enclave tags without auto-creating replacements, compares their public keys with the ledger, and uses every historical audit public key for checkpoint verification. `agentpass native key-lifecycle-status` replays and reports the ledger.

The Core library contains a resumable first-install ceremony which orders generation 1 as: stage approval public key, verify its self-authorization and proof-of-possession, then create and individually approval-sign the Git and audit service keys. It rejects a substituted approval key, an unrecorded exact-tag orphan, unexpected ledger records, and incomplete completion. This state machine intentionally does not make the production daemon listener available with partial authority. Signed client/service bootstrap primitives, transactional pin updates, and byte-exact online mutation replay are implemented; installer orchestration remains required before unattended production provisioning. A newly introduced outbox may join the next existing journal-pin sequence after bootstrap.

The signed helpers now expose the low-level offline ceremony without starting XPC. The client supports `bootstrap-approval-create TAG` and `bootstrap-sign TAG`; it derives exactly one `*.dev.agentpass.approval-keys` entitlement, creates/loads a user-presence generation-1 key, strictly decodes the canonical statement, displays its role/fingerprint/head, and signs it. The service supports root-only `--bootstrap prepare-approval|commit-approval|prepare-service|commit-service|status --config PATH`, accepts bounded exact JSON on stdin, and returns the new lifecycle head. These are operator primitives; the higher-level installer must preserve the returned canonical artifacts and finish the mutation-outbox/pin transaction before registration.

Protocol v11 exposes online staging, activation, and human-approved staged service-key abort:

```sh
agentpass native key-stage git_signing
agentpass native key-activate git_signing 2 --reason "scheduled rotation"
agentpass native key-stage audit_checkpoint
agentpass native key-stage session_approval
agentpass native key-activate session_approval 2 --reason "approval key rotation"
agentpass native key-abort git_signing 2 --reason "cancelled rollout"
```

Service keys are created under exact generation tags in the service keychain group. Approval keys are created by the signed client with user-presence access control and an explicitly resolved approval-group entitlement. Approval-key activation requires valid signatures from both the old and new approval keys over one canonical, expiring statement. Lifecycle-enabled production configuration requires both the external pin journal and byte-exact mutation outbox; static-pin-only and direct-ledger mutation configurations are rejected. Stage, activation, recovered activation, abort intent/completion, and deletion intent/completion persist their exact canonical ledger record before preparing the external pin. Startup replays pending outbox mutations and finishes exact Keychain deletions recorded by abort/deletion intents without reconstructing expired challenges or biometric signatures. XPC now exposes staged-key abort, offline recovery installation, and retired-key deletion ceremonies. Retired-key deletion is intentionally restricted to `audit_checkpoint`: its external transition receipt and signed retention/prune evidence can identify the exact retired generation. `git_signing` and `session_approval` deletion remain fail-closed until an equivalent externally signed lifecycle-archive proof exists.

Retired audit-key deletion is enabled only when these four root configuration fields are all present; a partial group prevents startup:

- `audit_key_deletion_evidence_bundle_path`: absolute path to the canonical, root-owned mode `0600`, single-link evidence bundle;
- `audit_key_deletion_archive_directory`: one root-owned mode `0700` directory containing all three archive files named by every authorized segment;
- `audit_retention_authorizer_public_key`: pinned P-256 SSH public-key line for prune authorization and post-prune manifests;
- `audit_key_deletion_minimum_retention_seconds`: local floor from 86400 through 31536000 seconds. A signed authorization may increase but cannot lower it.

The evidence bundle is canonical JSON (sorted keys, compact encoding, no trailing newline) with this exact schema. The three Base64 values decode to the exact canonical Core artifacts; arbitrary JSON, alternate Base64 spellings, unknown fields, and noncanonical artifact bytes are rejected.

```json
{
  "anchor_prune_receipt_base64": "BASE64_CANONICAL_ANCHOR_PRUNE_RECEIPT",
  "authorization_base64": "BASE64_CANONICAL_PRUNE_AUTHORIZATION",
  "expected_next_retained": null,
  "post_prune_manifest_base64": "BASE64_CANONICAL_POST_PRUNE_MANIFEST",
  "prior_chain_state": {
    "authorization_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "last_archive_receipt_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "last_checkpoint_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "last_checkpoint_index": 0,
    "last_event_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "last_event_index": 0,
    "last_receipt_index": 0,
    "manifest_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "receipt_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "sequence": 0
  },
  "version": 1
}
```

For a noninitial prune, `prior_chain_state` contains the exact previous verified chain tip and `expected_next_retained` is either `null` or one exact `NativeAuditRetentionSegment` JSON object. Initial state must be the all-zero state shown above; partial/nonzero substitutions fail closed.

The service never accepts authorization, receipts, manifests, archive paths, or prior state from XPC. The client-supplied deletion proof is only an assertion of signed hashes/timestamps and must exactly equal the Service-derived values. Before the listener starts, and again during both challenge creation and deletion completion, the Service rereads the protected bundle, canonically decodes every signed artifact, and descriptor-relatively reopens every authorization segment under the one configured archive directory. File hashes, inode/device/mode/owner/link count/size, transition-store tip, lifecycle ancestry, and the current clock are rechecked.

The trusted retention boundary is constructed only from local verified stores. It requires the current lifecycle head to descend from the latest externally receipted audit transition; the transition replacement must be the active audit generation; the complete audit log must equal the latest signed checkpoint; all checkpoints must have receipts with zero pending; and that latest checkpoint receipt must be the event immediately preceding the transition receipt. Its checkpoint index/hash/receipt hash and event index/hash must exactly match the transition and transition receipt. Missing, stale, replaced, recovery-only, or partially configured evidence therefore prevents startup or the operation. A valid evidence replacement after startup is accepted only if it independently satisfies the same complete verification and the pending client assertion still matches it.

To anchor native checkpoints, first export `agentpass native audit-key` from the final signed client and enroll it as a unique tenant on the separately administered anchor. Then add `audit_anchor_url`, `audit_anchor_tenant`, `audit_anchor_public_key`, and `audit_anchor_receipt_path` to the root-owned native service configuration. Production audit-key rotation additionally requires both `audit_key_transition_path` and the private `audit_key_rotation_plan_directory`. The public key is the anchor's Ed25519 SPKI PEM, not the host P-256 key. Partial configuration prevents service startup.

After the signed app and daemon are registered, select the bridge in the user-side configuration:

```json
{
  "native_broker": {
    "enabled": true,
    "mach_service": "dev.agentpass.native-service",
    "client": "/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client",
    "manager": "/Applications/AgentPass.app/Contents/MacOS/agentpass-native-manager"
  }
}
```

The Node wrapper rejects a symlinked or group/world-writable client executable. The XPC service independently checks its signing requirement, so changing this user-side path cannot grant an attacker binary access.

Generate the approval key with the final provisioned and signed client—not an ad-hoc development build—and capture its public key before starting a session-required service:

```sh
agentpass native session-approval-key > session-approval.pub
```

Verify the client signature as part of provisioning, then copy the exact public-key line into the root-owned `native-service.json` as `session_approval_public_key`. Set `session.required=true` and choose `session.ttl_seconds` between 60 and 86400 in the root policy. Omitting the approval key while sessions are required prevents service startup. Replacing the pinned key invalidates the existing client approval key and requires an explicit operator-controlled rotation procedure.

## Operations

```sh
agentpass native daemon-status
agentpass native daemon-register
agentpass native daemon-open-settings
agentpass native daemon-unregister
agentpass native status
agentpass native public-key
agentpass native audit-key
agentpass native checkpoint > checkpoint.json
agentpass native audit-rotate
agentpass native audit-evidence-rotate
agentpass native key-lifecycle-status
agentpass native anchor-push
agentpass native anchor-status
export AGENTPASS_SESSION="$(agentpass session start 900)"
agentpass native revoke-sessions
agentpass control apply ./control.bundle.json
agentpass control source https://control.example.com/agentpass/control.bundle.json
agentpass control fetch
agentpass control status
```

Copy the final signed app to a stable location before registration. `daemon-register` asks Service Management to register the plist embedded at `Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist`. If macOS reports that administrator approval is required, the manager opens Login Items settings and returns `requires_approval: true`; registration is not operational until the user approves it. `daemon-status` returns the bundle and plist paths as diagnostics. A `not_found` status means Service Management did not find this service and must not be treated as successful registration.

`native status` verifies all audit/evidence segments and signed chains, then reports archive readiness, lifecycle head, session state, control state, and refresh status. `native checkpoint` appends an audit event and signs the resulting exact head. `native audit-rotate` rotates the audit log; `native audit-evidence-rotate` rotates eligible checkpoint/receipt logs. Archived segments remain part of every verification and must not be deleted or edited. `native key-lifecycle-status` is read-only. `session start` prompts once and caps the requested TTL at the root policy value. The pre-push hook asks the service to validate both session and control state. Native `control trust` remains refused because user configuration cannot rotate the service trust root.

`native anchor-push` creates a fresh checkpoint only when no older checkpoint is pending, then submits exactly the next pending checkpoint. Re-run it until `native anchor-status` reports `pending: 0`; limiting each call to one checkpoint bounds XPC and network work. Receipt verification and persistence occur inside the privileged service. User-side `audit anchor trust` does not configure or rotate native anchor trust.

## Production audit pruning

Audit pruning is a four-stage management operation exposed by protocol 13:

- `audit-prune-prepare` reads a version-1 JSON request from stdin. It accepts only `operation_id`, `retention_seconds`, `segments`, and `expected_next_retained`; lifecycle, checkpoint, anchor, and prior prune-chain boundaries are always derived and verified inside the privileged service.
- `audit-prune-submit` posts the exact durable authorization to `POST /v1/audit-prunes/:tenant` and persists the canonical anchor receipt. It does not delete archives.
- `audit-prune-execute` requires that durable receipt, revalidates the service-owned reservation, deletes only the prepare-time inode identities, and atomically publishes the completion evidence bundle.
- `audit-prune-status` reports the pending stage, durable trust revision, reservation ID, and exportable `trust_head_hash`.

The settings `audit_prune_journal_directory`, `audit_prune_trust_directory`, and `audit_prune_evidence_bundle_path` are all-or-none. Both directories must already be root-owned mode `0700`; the evidence parent must be root-owned and not group/world writable. Pruning also requires the retention archive, lifecycle, key-transition, and complete anchor configuration. The retention-authorizer public key must equal the active non-exportable audit Secure Enclave key.

The local trust WAL uses immutable records, an fsync'd tip, and durable mutation reservations. Status and startup reads fetch only a fresh nonce-bound, anchor-signed version-2 head and never allocate a Node lease. Prepare, submit, execute, and reconciliation first verify that head, then use the active non-exportable audit Secure Enclave signer to request a separate version-4 exclusive lease bound to the expected position, purpose, operation, nonce, timestamp, process epoch, and audit-principal fingerprint. Node verifies the current post-transition key and canonical low-S signature before mutation. Missing, unauthenticated, stale, replayed, wrong-principal/purpose/operation/head, or forged leases fail closed.

Each verified head/lease becomes a five-second, one-shot local observation bound to trust revision, reservation, and chain generation. Acquire/release and submit HTTPS occur outside both Service authorization and coordinator locks. Submit consumes its same-principal lease atomically with the Node append. Execute revalidates the consumed lease immediately before every irreversible unlink; if the conservative deadline expires, deletion stops and the durable executor WAL resumes under a newly acquired lease. Node uses monotonic process time as the live expiry authority and conservatively fences an old-process-epoch lease for a full TTL after first observation on restart.

Anchor submission snapshots the exact durable reservation under the Service authorization gate, releases that gate during HTTPS I/O, then reacquires it and revalidates the unchanged lifecycle, trust revision, reservation, operation ID, and durable receipt before replying. Concurrent submit and execute calls fail closed through an in-flight marker; status remains available without waiting on the network-owned coordinator lock. Deletion and evidence publication stay in one serialized Service critical section.

Prune stage success/error metadata is returned by `audit-prune-status` (`last_stage`, `last_decision`, `last_error`, and `last_updated_at`). These stage records are deliberately not appended to the ordinary audit log while a prune reservation is frozen: such an append could rotate or checkpoint the very evidence boundary being authorized. The durable prune authorization/receipt/executor/completion WAL and published evidence bundle are the authoritative audit trail. After completion, later ordinary audit activity proceeds normally.

## Remaining production work

- Publish a Developer ID-signed, provisioned, notarized universal artifact and installer.
- Add an externally signed lifecycle-archive proof for Git/approval-key deletion, and finish transactional external-pin advancement UX.
- Test notarized universal binaries on Intel and Apple silicon hardware with Secure Enclave.
