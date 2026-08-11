# Security policy

AgentPass is early-alpha, security-sensitive software. Do not use it as the only control protecting production credentials.

AgentPass keeps the signing key in platform-backed storage and applies policy inside a fail-closed Unix-socket broker. Requests carry an enrolled Ed25519 identity, timestamp, nonce, short-lived session, exact payload, and Git context. The broker independently derives repository facts, validates the commit tree and all parents, replaces the requested key with its configured key, restricts signer arguments, and records a hash-chained audit event. Audit heads can be signed with a separate Ed25519 checkpoint key and verified after export.

The included broker is a per-user macOS LaunchAgent. It does not isolate its files or key reference from malware with arbitrary code execution as that same user. Git pre-push hooks are also bypassable. Use least-privilege repository access and server-side branch protection, and read [THREAT_MODEL.md](THREAT_MODEL.md) before deploying. The signed native XPC boundary required for hostile same-user isolation is specified in [docs/ADR-001-native-security-boundary.md](docs/ADR-001-native-security-boundary.md).

Report vulnerabilities through a private GitHub security advisory. Do not include private keys, credentials, or sensitive repository data in public issues.
