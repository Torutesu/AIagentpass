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

Create the non-exportable Secure Enclave-backed signing key on macOS:

```sh
agentpass setup-macos              # review commands
agentpass setup-macos --execute    # run them
```

Install a pre-push hook after explicitly allowing push operations in `config.json`. The default policy intentionally does not allow push:

```json
{ "operations": ["git.commit.sign", "git.push", "git.tag.push"] }
```

```sh
agentpass install-hook
```

The hook evaluates every ref received from Git. Branches use `branches.allow`/`branches.deny`; tags use `tags.allow`/`tags.deny`. A revoked AgentPass state or a required expired session blocks the push.

For unattended runs, issue a short-lived session token and enable session enforcement in `config.json`:

```sh
export AGENTPASS_SESSION="$(agentpass session start 900)"
```

Set `"session": { "required": true, "ttl_seconds": 900 }` to require that token for signing. The token is never written to the audit log; only its hash is stored locally.

Configure Git to use the wrapper:

```sh
git config --local gpg.format ssh
git config --local gpg.ssh.program "$(command -v agentpass-git-sign)"
git config --local commit.gpgsign true
```

The Secure Enclave-backed key can be created using the macOS technique documented by [mizdra](https://www.mizdra.net/entry/2026/08/07/101542), for example with `sc_auth create-ctk-identity`, then referenced in `.agentpass/config.json`.

Inspect and control the local policy:

```sh
agentpass status
agentpass audit --verify
agentpass revoke    # immediately deny signing
agentpass restore
```

## Security model

AgentPass protects against copying the private key out of the device and limits the allowed signing context. It does not protect against a fully compromised host process that is able to invoke an allowed signing operation. The policy boundary is therefore an authorization and audit layer, not a replacement for macOS sandboxing or endpoint security.

## Current scope and roadmap

- [x] repository, branch, remote, and operation policy
- [x] tamper-evident local audit chain
- [x] emergency local revocation switch
- [x] prerequisite diagnostics
- [x] short-lived session token with generation-based revocation
- [x] Secure Enclave setup command with dry-run default
- [x] optional pre-push policy hook
- [x] separate branch and tag push rules
- [x] GitHub Actions CI test workflow
- [ ] per-agent identity and session TTL
- [ ] push and tag policy enforcement
- [ ] FIDO2/YubiKey and TPM backends
- [ ] 1Password, Vault, and Infisical broker adapters
- [ ] signed audit events and remote revocation

## License

MIT
