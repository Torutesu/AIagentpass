# AgentPass

AgentPass is an OSS policy broker for coding-agent operations. It keeps signing keys in the platform security boundary and gives an agent permission to perform a narrowly scoped operation, rather than handing the agent a secret.

> Early prototype: macOS + Git SSH signing. Do not use for production keys yet.

## Why

Password managers are designed around human approval. Coding agents need unattended execution, but a plaintext key gives an untrusted process too much power. AgentPass starts with Git commit signing: the private key remains in macOS Secure Enclave-backed infrastructure, while AgentPass applies repository, branch, and remote policy before delegating to `ssh-keygen`.

## Quick start

```sh
npm install
npm link
agentpass init
agentpass check
```

Configure Git to use the wrapper:

```sh
git config --local gpg.format ssh
git config --local gpg.ssh.program "$(command -v agentpass-git-sign)"
git config --local commit.gpgsign true
```

The Secure Enclave-backed key can be created using the macOS technique documented by [mizdra](https://www.mizdra.net/entry/2026/08/07/101542), for example with `sc_auth create-ctk-identity`, then referenced in `.agentpass/config.json`.

## Security model

AgentPass protects against copying the private key out of the device and limits the allowed signing context. It does not protect against a fully compromised host process that is able to invoke an allowed signing operation. The policy boundary is therefore an authorization and audit layer, not a replacement for macOS sandboxing or endpoint security.

## Roadmap

- [ ] macOS Secure Enclave setup command
- [ ] per-agent identity and session TTL
- [ ] push and tag policy enforcement
- [ ] FIDO2/YubiKey and TPM backends
- [ ] 1Password, Vault, and Infisical broker adapters
- [ ] signed audit events and remote revocation

## License

MIT
