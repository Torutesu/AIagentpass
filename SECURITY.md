# Security policy

AgentPass is early-alpha, security-sensitive software. Do not use it as the only control protecting production credentials.

AgentPass keeps the signing key in platform-backed storage and applies policy inside a fail-closed Unix-socket broker. Requests carry an enrolled Ed25519 identity, timestamp, nonce, short-lived session, exact payload, and Git context. The broker independently derives repository facts, validates the commit tree and all parents, replaces the requested key with its configured key, restricts signer arguments, and records a hash-chained audit event. Audit heads can be signed with a separate Ed25519 checkpoint key and verified after export.

The default broker is a per-user macOS LaunchAgent. It does not isolate its files or key reference from malware with arbitrary code execution as that same user. Git pre-push hooks are also bypassable. Use least-privilege repository access and server-side branch protection, and read [THREAT_MODEL.md](THREAT_MODEL.md) before deploying. Version 0.12 includes the Swift/XPC and Secure Enclave source for the stronger boundary, including protected human-approved sessions, protected remote-control sequence state, a root-owned native audit chain, and a separate non-exportable checkpoint key, but not a signed/notarized production bundle; see [docs/NATIVE_BROKER.md](docs/NATIVE_BROKER.md).

Optional remote control uses an offline Ed25519 administration key. Once its public key is pinned, the broker requires a currently valid signed bundle and enforces global and per-Agent revocation before local policy. Keep the administration private key off AgentPass hosts and publish bundles through authenticated HTTPS infrastructure.

Optional remote audit anchoring sends signed checkpoint metadata to a separately administered append-only service and verifies its signed receipts. The reference anchor must be exposed through a hardened HTTPS reverse proxy; it does not include TLS termination, rate limiting, replication, or an HSM-backed receipt key. See [docs/AUDIT_ANCHOR.md](docs/AUDIT_ANCHOR.md).

Report vulnerabilities through a private GitHub security advisory. Do not include private keys, credentials, or sensitive repository data in public issues.
