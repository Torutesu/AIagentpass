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
agentpass revoke    # immediately deny signing
agentpass restore --confirm RESTORE
```

Copy `checkpoint.json` to an append-only or remote system. The public key verifies who signed a checkpoint; retaining a checkpoint record or its `checkpoint_hash` outside the host is what detects later local history replacement.

## Security model

AgentPass protects against copying the private key out of the device and limits the allowed signing context. It does not protect against a fully compromised host process that is able to invoke an allowed signing operation. The policy boundary is therefore an authorization and audit layer, not a replacement for macOS sandboxing or endpoint security.

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
- [ ] separate-user system broker for hostile same-user agents
- [x] per-agent Ed25519 request identity with replay protection
- [x] agent enrollment, selection, revocation, and key rotation
- [x] per-agent operation/repository/branch/remote scopes
- [x] concurrent short-lived sessions bound to Agent IDs
- [x] signed and chained audit checkpoints
- [x] merge commit parent validation against `HEAD` and `MERGE_HEAD`
- [ ] FIDO2/YubiKey and TPM backends
- [ ] 1Password, Vault, and Infisical broker adapters
- [ ] remote checkpoint anchoring and remote revocation

See [THREAT_MODEL.md](THREAT_MODEL.md) for the exact security boundary and remaining same-user limitations.

## License

MIT
