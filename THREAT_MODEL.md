# AgentPass threat model

## Protected assets

- The non-exportable private signing key in Secure Enclave.
- The authorization policy and revocation state.
- The integrity and attribution of signing requests.
- Audit evidence describing policy decisions and signer outcomes for authenticated signing requests.

## Broker security boundary

The Git signing wrapper is an untrusted client. It can choose a working directory, SSH arguments, payload, and session token, but the broker does not trust those values as authorization facts.

For every request, the broker:

1. resolves the real Git repository root itself and requires an exact allowlist match, preventing nested-repository substitution;
2. reads the active branch and origin itself;
3. evaluates repository, operation, branch, remote, revocation, and session policy;
4. discards the caller-provided key and inserts the configured key;
5. accepts only the SSH `-Y sign` operation in the `git` namespace and a small option allowlist;
6. hashes and audits the exact payload passed to the signer;
7. fails closed if its startup configuration changes;
8. has no local-signing fallback.

The Unix socket is mode `0600`, the configuration directory is mode `0700`, and a PID lease prevents a second broker from silently replacing the live socket. Connections and message sizes are bounded.

## Security levels

### Local broker mode

The included macOS LaunchAgent runs as the logged-in user. It protects against accidental misuse, argument injection, an untrusted Git wrapper, policy drift while the broker is running, and copying the non-exportable key material.

It does not provide a complete boundary against malware or an agent with arbitrary code execution as the same macOS user. Such a process can attempt to terminate the broker, modify user-owned files, bypass Git hooks, or invoke platform signing facilities directly if it can access the key reference.

### Hardened system broker mode

The target high-assurance deployment is a separately installed and signed system service under a dedicated OS identity. That service must own the key reference, policy, state, and audit signing key; expose only a narrow socket protocol; authenticate approved agent identities; and require human authentication for restore or policy changes.

This mode is not yet shipped. Until it is, AgentPass must not claim protection against a fully compromised same-user host.

The implementation decision and Apple signing prerequisites are recorded in [docs/ADR-001-native-security-boundary.md](docs/ADR-001-native-security-boundary.md).

## Explicit non-goals of local mode

- Preventing `git push --no-verify`; server-side branch protection is required.
- Protecting against root or kernel compromise.
- Proving audit integrity after an attacker rewrites the entire local log; remote anchoring or signed audit checkpoints are required.
- Treating an environment-variable session token as a non-transferable agent identity.
