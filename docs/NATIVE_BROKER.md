# Native macOS broker

AgentPass 0.12 implements the source-level native security boundary described by ADR-001. It is a Swift 6 package with three components:

- `AgentPassNativeCore`: Secure Enclave P-256 key management, OpenSSH SSHSIG encoding, signed Agent request verification, protected sessions and remote control, replay prevention, policy/Git validation, and protected audit primitives;
- `agentpass-native-service`: a privileged Mach XPC service that owns the signing key, session hashes, audit key, root-owned policy and control state, audit chain, and checkpoint chain;
- `agentpass-native-client`: a bounded bridge used by the Node signing wrapper and native management commands.

This is not a pre-signed binary distribution. Production installation still requires an Apple Developer Team ID, app bundle, matching entitlements/provisioning, hardened-runtime signing, notarization, and registration through `SMAppService.daemon(plistName:)`. An ad-hoc build is suitable for tests, but does not activate the claimed client-identity and keychain-access-group boundary.

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

Accepted state is atomically replaced with mode `0600` and synchronized to disk and its parent directory. The file and existing ancestry are checked for ownership, permissions, regular-file type, and symlinks. Control application is serialized with signing and session changes. If the state changes but its allow audit event cannot be appended, the manager poisons itself and denies further use until the service is repaired and restarted.

An update creates `<control_state_path>.pending-audit` before touching state and removes it only after the audit append is durable. A crash at any intermediate point therefore remains fail-closed across restart. Recovery requires an operator to compare the signed state with the protected audit tail, repair the underlying failure, and remove the marker explicitly; the service never guesses that an interrupted update was safe.

## Protected native sessions

Session approval uses a third P-256 Secure Enclave key, separate from Git signing and audit signing. Its access control combines `privateKeyUsage` with `userPresence`, so using the private key requires Touch ID, Apple Watch, or the macOS login password. Apple documents these controls under [Local Authentication](https://developer.apple.com/documentation/localauthentication) and [`SecAccessControlCreateFlags.userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).

The service sends a 60-second, one-time challenge containing the Agent ID and bounded TTL. The final signed native client displays those values in the system authentication prompt and signs the exact challenge only after successful authentication. The root-owned service configuration pins the approval public key, verifies the P-256 signature, and then returns a random 32-byte token. It stores only the token hash, Agent ID, and expiration in service memory. Challenges cannot be replayed, altered, or approved by a different key.

Normal commits use the issued token without further human interaction. A service restart fails safe by losing all sessions. `agentpass native revoke-sessions` immediately removes active sessions and pending approvals and advances the in-memory generation. Session-start allow/deny and revocation outcomes enter the protected audit chain. Agent-triggered prompt spam remains an availability/social-engineering concern; challenges are globally and per-Agent bounded, and users should reject unexpected prompts.

## Protected native audit

Native signing events are JSON Lines records linked by `previous_hash` and a SHA-256 `hash` over canonical JSON. The audit and checkpoint files must be regular files owned by the service account with no group/world permissions. Their existing path ancestry must be root-owned, non-group/world-writable, and free of symbolic links. Appends use `O_NOFOLLOW`, an exclusive file lock, `fsync`, and mode `0600`.

Before accepting XPC traffic, and again on health, signing, and checkpoint operations, the service verifies the complete chains. Corruption, truncation behind a checkpoint, insecure permissions, ownership changes, key substitution, or an invalid checkpoint signature causes a fail-closed error. Each log has a 128 MiB verification ceiling; reaching it stops signing, so production operations need monitored archival/rotation before that limit.

Checkpoints use a second, non-exportable Secure Enclave P-256 key. Each checkpoint binds the audit entry count and head, the previous checkpoint hash, timestamp, and key fingerprint. Copy checkpoint records and the audit public key to an independently protected system to make later local truncation detectable. Merely retaining the fingerprint on the same host does not preserve evidence after full host compromise.

The existing remote anchor protocol accepts the local broker's Ed25519 checkpoints, not these native P-256 checkpoints. Native remote anchoring is still pending; do not send native checkpoint JSON to the current anchor endpoint.

## Build and test

```sh
swift test --package-path native/macos
swift build -c release --package-path native/macos
```

Tests verify SSHSIG output with `/usr/bin/ssh-keygen -Y verify` and cover forged requests, session/key/Agent binding, challenge mutation and replay, expiration and revocation, scope bypass, malformed signatures, audit mutation, truncation, checkpoint mutation, audit-key substitution, symlinks, and permissive files. Secure Enclave prompts and signed-XPC behavior require a provisioned macOS integration environment and are not exercised by the software-key unit tests.

## Bundle resources and installation inputs

Templates are under `native/macos/Resources/`:

- `dev.agentpass.native-service.plist` belongs in the signed app's `Contents/Library/LaunchDaemons` directory;
- `AgentPassNativeService.entitlements` must use the actual App Identifier Prefix;
- `native-service.example.json` must replace `TEAMID`, use the interactive user's UID, and be installed root-owned with mode `0600`.

Create `/Library/Application Support/AgentPass` as root with no group/world write permission. Install the approved version 4 policy there as `policy.json`, owned by root and not group/world writable. This copy—not `~/.agentpass/config.json`—is authoritative inside the service. If it contains `control.required=true`, install an initial signed bundle as `control.bundle.json`, root-owned with mode `0600`, and configure that absolute `control_state_path`. The configured state and audit paths must remain under protected root-owned ancestry.

After the signed app and daemon are registered, select the bridge in the user-side configuration:

```json
{
  "native_broker": {
    "enabled": true,
    "mach_service": "dev.agentpass.native-service",
    "client": "/Applications/AgentPass.app/Contents/MacOS/agentpass-native-client"
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
agentpass native status
agentpass native public-key
agentpass native audit-key
agentpass native checkpoint > checkpoint.json
export AGENTPASS_SESSION="$(agentpass session start 900)"
agentpass native revoke-sessions
agentpass control apply ./control.bundle.json
agentpass control source https://control.example.com/agentpass/control.bundle.json
agentpass control fetch
agentpass control status
```

`native status` verifies both chains and reports the audit head, latest checkpoint, session state, and control sequence/expiry/operational state. `native public-key` emits the Git signing public key. `native audit-key` emits the distinct checkpoint verification key. `native checkpoint` first adds an audit event, then signs the resulting exact audit head. `session start` prompts once and caps the requested TTL at the root policy value. The pre-push hook asks the service to validate both the session and control state instead of consulting user-writable files. `native revoke-sessions` does not require human approval because it can only remove authority. `control source` stores only an untrusted HTTPS distribution URL in user configuration; `control apply` and `fetch` cross XPC and are independently verified against the root policy before persistence. Native `control trust` is refused because user configuration cannot rotate the service trust root. Native HTTPS refresh is not automatic yet; run `control fetch` from an operator-managed scheduler before expiry.

## Remaining production work

- Build the signed `.app` host/registrar and automate `SMAppService` register/status/unregister.
- Add service-owned bounded HTTPS control refresh with monitored retry/backoff.
- Add a remote anchor protocol and verifier for native P-256 checkpoints.
- Add signed audit-log archival/rotation without losing checkpoint continuity.
- Add signing, audit, and session-approval key deletion/rotation with interactive authorization and recovery UX.
- Test notarized universal binaries on Intel and Apple silicon hardware with Secure Enclave.
