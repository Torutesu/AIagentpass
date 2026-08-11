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

Accepted state is atomically replaced with mode `0600` and synchronized to disk and its parent directory. The file and existing ancestry are checked for ownership, permissions, regular-file type, and symlinks. Control application is serialized with signing and session changes. If the state changes but its allow audit event cannot be appended, the manager poisons itself and denies further use until the service is repaired and restarted.

An update creates `<control_state_path>.pending-audit` before touching state and removes it only after the audit append is durable. A crash at any intermediate point therefore remains fail-closed across restart. Recovery requires an operator to compare the signed state with the protected audit tail, repair the underlying failure, and remove the marker explicitly; the service never guesses that an interrupted update was safe.

## Protected native sessions

Session approval uses a third P-256 Secure Enclave key, separate from Git signing and audit signing. Its access control combines `privateKeyUsage` with `userPresence`, so using the private key requires Touch ID, Apple Watch, or the macOS login password. Apple documents these controls under [Local Authentication](https://developer.apple.com/documentation/localauthentication) and [`SecAccessControlCreateFlags.userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).

The service sends a 60-second, one-time challenge containing the Agent ID and bounded TTL. The final signed native client displays those values in the system authentication prompt and signs the exact challenge only after successful authentication. The root-owned service configuration pins the approval public key, verifies the P-256 signature, and then returns a random 32-byte token. It stores only the token hash, Agent ID, and expiration in service memory. Challenges cannot be replayed, altered, or approved by a different key.

Normal commits use the issued token without further human interaction. A service restart fails safe by losing all sessions. `agentpass native revoke-sessions` immediately removes active sessions and pending approvals and advances the in-memory generation. Session-start allow/deny and revocation outcomes enter the protected audit chain. Agent-triggered prompt spam remains an availability/social-engineering concern; challenges are globally and per-Agent bounded, and users should reject unexpected prompts.

## Protected native audit

Native signing events are JSON Lines records linked by `previous_hash` and a SHA-256 `hash` over canonical JSON. The audit and checkpoint files must be regular files owned by the service account with no group/world permissions. Their existing path ancestry must be root-owned, non-group/world-writable, and free of symbolic links. Appends use `O_NOFOLLOW`, an exclusive file lock, `fsync`, and mode `0600`.

Before accepting XPC traffic, and again on health, signing, checkpoint, and rotation operations, the service verifies the complete chains. Corruption, truncation behind a checkpoint, insecure permissions, ownership changes, key substitution, or an invalid checkpoint signature causes a fail-closed error. Each active or archived audit segment has a 128 MiB verification ceiling.

When `audit_archive_directory` is configured, `agentpass native audit-rotate` becomes available after the active log reaches 64 MiB. The service signs a checkpoint before atomically renaming the active file to `audit-<global-entry-count>-<terminal-head-hash>.jsonl`, changes it to mode `0400`, and fsyncs the file and directories. Verification then walks every segment in global entry order and carries the previous hash into the active log. Unknown directory entries, missing continuity, filename/content disagreement, symlinks, ownership changes, and permissive modes fail closed. The threshold prevents an Agent from creating an unbounded number of empty or tiny segments.

Checkpoints use a second, non-exportable Secure Enclave P-256 key. Each checkpoint binds the audit entry count and head, the previous checkpoint hash, timestamp, and key fingerprint. Copy checkpoint records and the audit public key to an independently protected system to make later local truncation detectable. Merely retaining the fingerprint on the same host does not preserve evidence after full host compromise.

The remote anchor accepts both local Ed25519 and native P-256 checkpoint tenants while pinning one algorithm and key per tenant. Native anchor configuration is root-owned; the service itself performs HTTPS submission, rejects redirects and responses over 512 KiB, verifies the returned Ed25519 receipt and both chains, and durably appends the receipt under protected ancestry. A lost response leaves the checkpoint pending, and retrying it returns the anchor's original receipt.

## Build and test

```sh
swift test --package-path native/macos
swift build -c release --package-path native/macos
npm run test:native-app
native/macos/scripts/build-app.sh --adhoc --force
```

The ad-hoc app test verifies the app layout, signing identifiers, embedded keychain access groups, daemon label/program/Mach service, manager diagnostics, strict code-signature validity, and fail-closed build options. It does not prove Apple Developer identity, Service Management registration, notarization, or Secure Enclave access.

For a production build, provide the final provisioning profile and signing identity. Add `--universal` to build arm64 and x86_64 slices and `--notary-profile` to submit and staple the result:

```sh
AGENTPASS_SIGNING_IDENTITY="Developer ID Application: Example Corp (TEAMID1234)" \
AGENTPASS_TEAM_ID="TEAMID1234" \
native/macos/scripts/build-app.sh \
  --universal \
  --profile ./AgentPass.provisionprofile \
  --notary-profile agentpass-notary \
  --force
```

The build refuses a production build without an identity, Team ID, and provisioning profile. It decodes the profile, verifies its Team ID, derives the App Identifier Prefix, and requires the exact AgentPass keychain access group before signing. It also refuses symlinked profiles, refuses ad-hoc notarization, and does not overwrite an existing app unless `--force` is explicit. Set `AGENTPASS_APP_IDENTIFIER_PREFIX` or `--app-identifier-prefix` only when an explicit cross-check against the profile is desired. Tests also verify SSHSIG output with `/usr/bin/ssh-keygen -Y verify` and cover forged requests, session/key/Agent binding, challenge mutation and replay, expiration and revocation, scope bypass, malformed signatures, audit mutation, truncation, checkpoint mutation, audit-key substitution, symlinks, and permissive files. Secure Enclave prompts and signed-XPC behavior require a provisioned macOS integration environment and are not exercised by software-key tests.

## Bundle resources and installation inputs

Templates are under `native/macos/Resources/`:

- `dev.agentpass.native-service.plist` belongs in the signed app's `Contents/Library/LaunchDaemons` directory;
- the client and service entitlements must use the actual App Identifier Prefix;
- `native-service.example.json` must replace `TEAMID`, use the interactive user's UID, and be installed root-owned with mode `0600`.

Create `/Library/Application Support/AgentPass` as root with no group/world write permission. Create its `audit-archive` child as root with mode `0700`, then set `audit_archive_directory` to that absolute path. Install the approved version 4 policy there as `policy.json`, owned by root and not group/world writable. This copy—not `~/.agentpass/config.json`—is authoritative inside the service. If it contains `control.required=true`, install an initial signed bundle as `control.bundle.json`, root-owned with mode `0600`, and configure that absolute `control_state_path`. Add `control_url` and `control_refresh_seconds` to enable service-owned refresh. The configured state and audit paths must remain under protected root-owned ancestry.

To anchor native checkpoints, first export `agentpass native audit-key` from the final signed client and enroll it as a unique tenant on the separately administered anchor. Then add `audit_anchor_url`, `audit_anchor_tenant`, `audit_anchor_public_key`, and `audit_anchor_receipt_path` to the root-owned native service configuration. The public key is the anchor's Ed25519 SPKI PEM, not the host P-256 key. All four fields are required together; partial configuration prevents service startup.

After the signed app and daemon are registered, select the bridge in the user-side configuration:

```json
{
  "native_broker": {
    "enabled": true,
    "mach_service": "dev.agentpass.native-service",
    "client": "/Applications/AgentPass.app/Contents/MacOS/agentpass-native-client",
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

`native status` verifies all audit segments and both signed chains, then reports the audit head, latest checkpoint, session state, control sequence/expiry/operational state, and automatic-refresh status. `native public-key` emits the Git signing public key. `native audit-key` emits the distinct checkpoint verification key. `native checkpoint` first adds an audit event, then signs the resulting exact audit head. `native audit-rotate` refuses logs below 64 MiB and creates a terminal checkpoint before moving the active segment. Archived segments remain part of every verification and must not be deleted or edited; copy them and checkpoints to separately protected storage under an operator retention policy. `session start` prompts once and caps the requested TTL at the root policy value. The pre-push hook asks the service to validate both the session and control state instead of consulting user-writable files. `native revoke-sessions` does not require human approval because it can only remove authority. `control source` stores an optional untrusted manual-fetch URL in user configuration; `control apply` and manual `fetch` cross XPC and are independently verified against the root policy before persistence. Native `control trust` is refused because user configuration cannot rotate the service trust root. Automatic refresh uses only the root-owned service URL.

`native anchor-push` creates a fresh checkpoint only when no older checkpoint is pending, then submits exactly the next pending checkpoint. Re-run it until `native anchor-status` reports `pending: 0`; limiting each call to one checkpoint bounds XPC and network work. Receipt verification and persistence occur inside the privileged service. User-side `audit anchor trust` does not configure or rotate native anchor trust.

## Remaining production work

- Publish a Developer ID-signed, provisioned, notarized universal artifact and installer.
- Add signing, audit, and session-approval key deletion/rotation with interactive authorization and recovery UX.
- Test notarized universal binaries on Intel and Apple silicon hardware with Secure Enclave.
