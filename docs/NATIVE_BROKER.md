# Native macOS broker

AgentPass 0.10 implements the source-level native security boundary described by ADR-001. It is a Swift 6 package with three components:

- `AgentPassNativeCore`: Secure Enclave P-256 key management, OpenSSH SSHSIG encoding, signed Agent request verification, replay prevention, policy/Git validation, and protected audit primitives;
- `agentpass-native-service`: a privileged Mach XPC service that owns the signing key, audit key, root-owned policy, audit chain, and checkpoint chain;
- `agentpass-native-client`: a bounded bridge used by the Node signing wrapper and native management commands.

This is not a pre-signed binary distribution. Production installation still requires an Apple Developer Team ID, app bundle, matching entitlements/provisioning, hardened-runtime signing, notarization, and registration through `SMAppService.daemon(plistName:)`. An ad-hoc build is suitable for tests, but does not activate the claimed client-identity and keychain-access-group boundary.

## Security boundary

Every signing call is checked again inside the XPC service. The service:

1. restricts XPC connections to one configured UID and Apple code-signing requirement;
2. reads a root-owned, non-group/world-writable version 4 policy at startup;
3. verifies the Agent's Ed25519 signature over canonical request JSON;
4. enforces a 60-second timestamp window and bounded nonce replay cache;
5. derives the Git root, branch, origin, tree, `HEAD`, and `MERGE_HEAD` itself;
6. applies both global and per-Agent operation/repository/branch/remote scope;
7. asks a non-exportable Secure Enclave P-256 key to produce an OpenSSH SSHSIG;
8. records every allow, deny, or signer error before returning to the client.

The service refuses policies with `session.required=true` or configured remote control. This is deliberate fail-closed behavior until native session issuance and persistent remote sequence state are implemented.

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

Tests verify SSHSIG output with `/usr/bin/ssh-keygen -Y verify` and cover forged requests, replay, scope bypass, malformed signatures, audit mutation, truncation, checkpoint mutation, audit-key substitution, symlinks, and permissive files. Secure Enclave and signed-XPC behavior require a provisioned macOS integration environment and are not exercised by the software-key unit tests.

## Bundle resources and installation inputs

Templates are under `native/macos/Resources/`:

- `dev.agentpass.native-service.plist` belongs in the signed app's `Contents/Library/LaunchDaemons` directory;
- `AgentPassNativeService.entitlements` must use the actual App Identifier Prefix;
- `native-service.example.json` must replace `TEAMID`, use the interactive user's UID, and be installed root-owned with mode `0600`.

Create `/Library/Application Support/AgentPass` as root with no group/world write permission. Install the approved version 4 policy there as `policy.json`, owned by root and not group/world writable. Set `session.required` to `false` and omit `control`. This copy—not `~/.agentpass/config.json`—is authoritative inside the service. The configured audit paths must remain under protected root-owned ancestry.

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

## Operations

```sh
agentpass native status
agentpass native public-key
agentpass native audit-key
agentpass native checkpoint > checkpoint.json
```

`native status` verifies both chains and reports the audit head and latest checkpoint. `native public-key` emits the Git signing public key. `native audit-key` emits the distinct checkpoint verification key. `native checkpoint` first adds an audit event, then signs the resulting exact audit head.

## Remaining production work

- Build the signed `.app` host/registrar and automate `SMAppService` register/status/unregister.
- Implement protected native session issuance and remote-control sequence persistence.
- Add a remote anchor protocol and verifier for native P-256 checkpoints.
- Add signed audit-log archival/rotation without losing checkpoint continuity.
- Add signing/audit key deletion and rotation with interactive authorization and recovery UX.
- Test notarized universal binaries on Intel and Apple silicon hardware with Secure Enclave.
