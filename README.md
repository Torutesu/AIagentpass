# AgentPass

AgentPass is an OSS policy broker for coding-agent operations. It keeps signing keys in the platform security boundary and gives an agent permission to perform a narrowly scoped operation, rather than handing the agent a secret.

> Early alpha: macOS + Git SSH signing. Review the threat model before using production keys.

## Why

Password managers are designed around human approval. Coding agents need unattended execution, but a plaintext key gives an untrusted process too much power. AgentPass starts with Git commit signing: the private key remains in macOS Secure Enclave-backed infrastructure, while AgentPass applies repository, branch, and remote policy before delegating to `ssh-keygen`.

## Quick start

```sh
npm install
npm link
agentpass init
agentpass check
agentpass doctor
```

Upgrading from AgentPass 0.5 or earlier creates the v4 audit identity and, when needed, a signed agent identity:

```sh
agentpass migrate
agentpass broker install --force
```

The v0.6 broker refuses configuration versions below 4. Migration intentionally invalidates legacy single-session storage, so issue a new Agent-bound session afterward.

Create the non-exportable Secure Enclave-backed signing key on macOS:

```sh
agentpass setup-macos              # review commands
agentpass setup-macos --execute    # run them
agentpass broker install
agentpass broker ping
```

Install a pre-push hook after explicitly allowing push operations in `config.json`. The default policy intentionally does not allow push:

```json
{ "operations": ["git.commit.sign", "git.push", "git.tag.push"] }
```

```sh
agentpass install-hook
```

The hook evaluates every ref received from Git. Branches use `branches.allow`/`branches.deny`; tags use `tags.allow`/`tags.deny`. A revoked AgentPass state or a required expired session blocks the push.

Signing is session-gated by default. Before an unattended run, issue a short-lived session token:

```sh
export AGENTPASS_SESSION="$(agentpass session start 900)"
```

Sessions are bound to the selected Agent ID. For a non-default identity, use `agentpass session start 900 --agent AGENT_ID` and export the same ID as `AGENTPASS_AGENT_ID` when invoking Git. Multiple agents can hold concurrent sessions. Tokens are never written to the audit log; only their hashes are stored locally. Set `"session.required"` to `false` only if another control supplies the authorization boundary.

Configure Git to use the wrapper:

```sh
git config --local gpg.format ssh
git config --local user.signingkey ~/.agentpass/keys/id_git_sign.pub
git config --local gpg.ssh.program "$(command -v agentpass-git-sign)"
git config --local commit.gpgsign true
```

`agentpass-git-sign` never invokes `ssh-keygen` directly. It sends the payload to the Unix socket broker. The broker independently resolves the repository root, branch, and origin; replaces the caller-provided key with the configured key; filters SSH signing arguments; evaluates policy and session state; records the payload hash; and only then signs. If the broker is unavailable, signing fails closed.

Each request is signed by an enrolled Ed25519 agent identity, timestamped, and assigned a random nonce. The broker verifies the signature and rejects unknown, expired, or replayed requests before policy evaluation.

Manage agent identities without editing `config.json` directly:

```sh
agentpass agent list
agentpass agent add cursor-nightly
agentpass agent set-default AGENT_ID
agentpass agent scope AGENT_ID \
  --operation git.commit.sign \
  --repository /absolute/path/to/repo \
  --branch 'feature/*' \
  --remote 'git@github.com:owner/repo.git'
agentpass agent rotate AGENT_ID
agentpass agent revoke AGENT_ID --confirm REVOKE
agentpass broker install --force   # trust the new configuration
```

New agents initially receive a snapshot of the global policy. Their explicit scope can only narrow effective access because every request must pass both global policy and Agent scope. Configuration mutation intentionally makes the running broker fail closed. Revoked and rotated private-key files are moved under `~/.agentpass/agents/revoked/` for operator recovery, but are no longer enrolled.

The Secure Enclave-backed key can be created using the macOS technique documented by [mizdra](https://www.mizdra.net/entry/2026/08/07/101542), for example with `sc_auth create-ctk-identity`, then referenced in `.agentpass/config.json`.

Inspect and control the local policy:

```sh
agentpass status
agentpass audit --verify
agentpass audit checkpoint > checkpoint.json
agentpass audit public-key > agentpass-audit.pub
agentpass revoke    # local broker mode
agentpass restore --confirm RESTORE
agentpass native revoke-sessions  # native mode: invalidate active authority
```

Copy `checkpoint.json` to an append-only or remote system. The public key verifies who signed a checkpoint; retaining a checkpoint record or its `checkpoint_hash` outside the host is what detects later local history replacement.

AgentPass also includes a remote anchor that verifies checkpoint signatures and returns append-only, signed receipts:

```sh
# Separately administered anchor host; publish it through an HTTPS reverse proxy.
agentpass-anchor init /var/lib/agentpass-anchor
agentpass-anchor enroll /var/lib/agentpass-anchor build-mac-01 ./agentpass-audit.pub
agentpass-anchor serve /var/lib/agentpass-anchor

# AgentPass host; pin the anchor key through an authenticated channel.
agentpass audit anchor trust \
  --url https://audit-anchor.example.com/ \
  --tenant build-mac-01 \
  --key ./anchor-public.pem
agentpass audit anchor push
agentpass audit anchor status
```

Only signed checkpoint metadata leaves the host; audit events and repository data remain local. Failed pushes are retained and safely retried. See [docs/AUDIT_ANCHOR.md](docs/AUDIT_ANCHOR.md) for deployment, protocol, and residual risks.

## Offline-signed remote revocation

Generate the control key on an offline administration host and retain `control-private.pem` there:

```sh
agentpass control keygen ./agentpass-control-key
agentpass control sign \
  --key ./agentpass-control-key/control-private.pem \
  --sequence 1 \
  --expires 2026-08-12T00:00:00Z \
  --revoke-agent AGENT_ID > control.bundle.json
```

Use `--global-revoke` instead of `--revoke-agent` for an emergency stop. Bundles have a maximum seven-day lifetime and sequence numbers must increase whenever content changes.

On each AgentPass host, pin only the public key and install the initial bundle:

```sh
agentpass control trust ./control-public.pem \
  --url https://control.example.com/agentpass/control.bundle.json \
  --refresh 60
agentpass control apply ./control.bundle.json
agentpass broker install --force
agentpass control status
```

The broker periodically fetches the static JSON bundle over HTTPS. Missing, expired, malformed, incorrectly signed, rolled-back, or same-sequence conflicting bundles fail closed. See [docs/REMOTE_CONTROL.md](docs/REMOTE_CONTROL.md) for the protocol and operational model.

In native mode, install the public key in the root-owned service policy and the initial bundle at `control_state_path`; user-side `control trust` is intentionally refused. Configure `control_url` and `control_refresh_seconds` in the root-owned native service configuration for automatic bounded refresh. `agentpass control fetch` and direct apply remain available for operator recovery. The native service—not the user configuration—verifies trust and persists the sequence.

## Security model

AgentPass protects against copying the private key out of the device and limits the allowed signing context. It does not protect against a fully compromised host process that is able to invoke an allowed signing operation. The policy boundary is therefore an authorization and audit layer, not a replacement for macOS sandboxing or endpoint security.

## Native macOS boundary

Version 0.14 includes a Swift/XPC native broker and a buildable macOS app host. It creates separate non-exportable P-256 signing, audit-checkpoint, and human-presence approval keys in Secure Enclave, emits OpenSSH-compatible SSHSIG signatures internally, authenticates the signed XPC client, and repeats Agent identity, session, remote-control, replay, scope, Git context, tree, and parent validation against root-owned policy and state inside the service. The service automatically refreshes signed control bundles from a root-configured HTTPS source with redirects disabled and a 256 KiB response ceiling. Every native signing outcome is appended to a root-owned, durable SHA-256 chain; signed checkpoints make later truncation or rewriting detectable once retained outside the host.

```sh
npm run test:native
npm run test:native-app
native/macos/scripts/build-app.sh --adhoc --force
```

Protected native sessions require human presence only when `agentpass session start` is called; policy-compliant commits remain unattended until the Agent-bound TTL expires. The service retains token hashes only in memory, so restart and `agentpass native revoke-sessions` invalidate them. Native mode verifies, atomically persists, and periodically refreshes signed control bundles under root-owned configuration and ancestry; `agentpass control apply`, `fetch`, and `status` are also routed through XPC. The build pipeline assembles the required `Contents/Library/LaunchDaemons` layout, signs every nested executable, supports universal builds and optional notarization, and exposes `SMAppService` register/status/unregister commands. No Developer ID-signed release artifact is published yet, and ad-hoc builds do not activate the production identity boundary. See [docs/NATIVE_BROKER.md](docs/NATIVE_BROKER.md) for setup and remaining gaps.

## Current scope and roadmap

- [x] repository, branch, remote, and operation policy
- [x] tamper-evident local audit chain
- [x] emergency local revocation switch
- [x] prerequisite diagnostics
- [x] short-lived session token with generation-based revocation
- [x] fixed production config location (no environment override)
- [x] configured signing-key enforcement
- [x] signed-payload hash in audit events
- [x] Unix socket signing broker with no local fallback
- [x] broker-side Git context and signing-argument validation
- [x] broker config snapshot with mutation fail-closed
- [x] macOS LaunchAgent installation
- [x] Secure Enclave setup command with dry-run default
- [x] optional pre-push policy hook
- [x] separate branch and tag push rules
- [x] GitHub Actions CI test workflow
- [x] Swift/XPC broker core with Secure Enclave SSHSIG and service-side policy validation
- [x] root-owned native hash-chain audit with separate Secure Enclave checkpoint key
- [x] human-approved protected native sessions with Agent binding and immediate revocation
- [x] signed/notarizable native app build and Service Management registrar
- [ ] published notarized universal native release artifact
- [x] protected native remote-control state and monotonic sequence enforcement
- [x] service-owned bounded native HTTPS control refresh
- [x] per-agent Ed25519 request identity with replay protection
- [x] agent enrollment, selection, revocation, and key rotation
- [x] per-agent operation/repository/branch/remote scopes
- [x] concurrent short-lived sessions bound to Agent IDs
- [x] signed and chained audit checkpoints
- [x] merge commit parent validation against `HEAD` and `MERGE_HEAD`
- [ ] FIDO2/YubiKey and TPM backends
- [ ] 1Password, Vault, and Infisical broker adapters
- [x] offline-signed remote Agent and global revocation
- [x] bounded HTTPS control refresh with sequence rollback detection
- [x] remote checkpoint anchoring with signed, chained receipts
- [ ] remote anchoring protocol for native P-256 checkpoints

See [THREAT_MODEL.md](THREAT_MODEL.md) for the exact security boundary and remaining same-user limitations.

## License

MIT
