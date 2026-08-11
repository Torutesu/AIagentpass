# Native macOS broker

AgentPass 0.9 adds the source-level native security boundary described by ADR-001. It is a Swift 6 package with three components:

- `AgentPassNativeCore`: Secure Enclave P-256 key management, OpenSSH SSHSIG encoding, Ed25519 Agent request verification, replay prevention, policy evaluation, and Git commit validation;
- `agentpass-native-service`: a Mach XPC service that owns the Secure Enclave key and root-owned policy;
- `agentpass-native-client`: a bounded bridge used by the existing Node signing wrapper.

This is not a pre-signed binary distribution. A production installation still requires an Apple Developer Team ID, an application bundle, matching entitlements/provisioning, hardened-runtime signing, notarization, and registration through `SMAppService.daemon(plistName:)`. The service intentionally refuses mutable policy files and unsigned/unexpected XPC clients, so an ad-hoc build is useful for tests but is not the claimed high-assurance deployment.

## Security boundary

Every sign call is checked again inside the XPC service. The service:

1. restricts the XPC connection to one configured UID and Apple code-signing requirement;
2. reads a root-owned, non-group/world-writable version 4 policy at startup;
3. verifies the Agent's Ed25519 signature over canonical request JSON;
4. enforces a 60-second timestamp window and bounded nonce replay cache;
5. resolves the Git root, branch, and origin itself;
6. applies both global and per-Agent operation/repository/branch/remote scope;
7. checks the exact commit tree and `HEAD`/`MERGE_HEAD` parent set;
8. asks the non-exportable Secure Enclave P-256 key to sign an OpenSSH-compatible SSHSIG envelope.

The native implementation currently refuses policies with `session.required=true` or configured remote control. This is deliberate fail-closed behavior until protected native session issuance, persistent remote sequence state, and native audit checkpointing are implemented.

## Build and interoperability test

```sh
swift test --package-path native/macos
swift build -c release --package-path native/macos
```

Tests generate a P-256 signature and verify it with `/usr/bin/ssh-keygen -Y verify`, in addition to testing forged requests, scope bypass, replay, malformed DER, and unsupported policy features.

## Bundle resources

Templates are under `native/macos/Resources/`:

- `dev.agentpass.native-service.plist` belongs in the signed app's `Contents/Library/LaunchDaemons` directory;
- `AgentPassNativeService.entitlements` must use the actual App Identifier Prefix;
- `native-service.example.json` must replace `TEAMID`, use the actual interactive user's UID, and be installed root-owned with mode `0600`.

Copy the approved version 4 policy to `/Library/Application Support/AgentPass/policy.json`, owned by root and not group/world writable. For the current native release, set `session.required` to `false` and omit `control`. This copy—not the user's `~/.agentpass/config.json`—is authoritative inside the service.

After the signed app and daemon are registered, the user-side configuration selects the bridge:

```json
{
  "native_broker": {
    "enabled": true,
    "mach_service": "dev.agentpass.native-service",
    "client": "/Applications/AgentPass.app/Contents/MacOS/agentpass-native-client"
  }
}
```

The Node wrapper rejects a symlinked or group/world-writable client executable. The XPC service independently checks the client's signing requirement, so changing this user-side path cannot grant access to an attacker binary.

## Remaining work before production distribution

- Build the signed `.app` host/registrar and automate `SMAppService` register/status/unregister.
- Move session issuance, remote-control sequence persistence, audit logging, and audit checkpoint keys into the native service.
- Add key deletion/rotation with interactive authorization and recovery UX.
- Test notarized universal binaries on Intel and Apple silicon hardware with Secure Enclave.
