# AgentPass threat model

## Protected assets

- The non-exportable private signing key in Secure Enclave.
- The authorization policy and revocation state.
- The integrity and attribution of signing requests.
- Audit evidence describing policy decisions and signer outcomes for authenticated signing requests.
- Signed audit checkpoints that can be pinned outside the host.
- An optional offline control trust root for remote emergency revocation.

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

An authenticated Agent ID is also an authorization principal. Its explicit operation, repository, branch, and remote scope is evaluated after the global policy, so an Agent scope cannot widen global access. Session records are keyed by token hash and bound to one Agent ID; issuing a session for one enrolled agent does not authorize another.

When remote control is configured, the broker pins an Ed25519 administration public key and refuses to start or sign without a valid, unexpired bundle. Bundles can revoke all signing or selected Agent IDs. They are limited to seven days, fetched only through HTTPS without redirects, size-bounded, and ordered by a monotonically increasing sequence. Runtime rollback and same-sequence equivocation are rejected.

Normal commits must have `HEAD` as their sole parent. Merge commits are accepted only while `MERGE_HEAD` exists and every payload parent exactly matches `HEAD` followed by the repository's merge heads. Initial commits must have no parent.

Audit records form a SHA-256 chain. A separate Ed25519 key signs explicit checkpoints containing the entry count and exact audit head. Exporting the checkpoint record or its hash to an append-only remote system makes later truncation or rewriting detectable against that external copy. The public-key fingerprint identifies the checkpoint signer but, by itself, cannot preserve history after private-key compromise.

## Security levels

### Local broker mode

The included macOS LaunchAgent runs as the logged-in user. It protects against accidental misuse, argument injection, an untrusted Git wrapper, policy drift while the broker is running, and copying the non-exportable key material.

It does not provide a complete boundary against malware or an agent with arbitrary code execution as the same macOS user. Such a process can attempt to terminate the broker, modify user-owned files, bypass Git hooks, or invoke platform signing facilities directly if it can access the key reference.

The offline control key prevents that process from authoring a new valid control decision. In local mode, however, a same-user attacker can replace the cached bundle and restart the broker, losing the in-memory highest sequence. Short bundle lifetimes and an online HTTPS source bound the rollback window; the native system service must persist the sequence outside the agent user's writable state.

### Hardened system broker mode

The target high-assurance deployment is a separately installed and signed system service under a dedicated OS identity. That service must own the key reference, policy, state, and audit signing key; expose only a narrow socket protocol; authenticate approved agent identities; and require human authentication for restore or policy changes.

This mode is not yet shipped. Until it is, AgentPass must not claim protection against a fully compromised same-user host.

The implementation decision and Apple signing prerequisites are recorded in [docs/ADR-001-native-security-boundary.md](docs/ADR-001-native-security-boundary.md).

## Explicit non-goals of local mode

- Preventing `git push --no-verify`; server-side branch protection is required.
- Protecting against root or kernel compromise.
- Proving audit integrity after an attacker rewrites the entire local log and uses the locally readable checkpoint key; pin checkpoint records or checkpoint hashes outside the host.
- Treating an environment-variable session token as a non-transferable agent identity.
