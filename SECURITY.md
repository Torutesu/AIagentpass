# Security policy

AgentPass is an early, security-sensitive prototype. Do not use it as the only control protecting production credentials.

AgentPass prevents export of the signing key and applies local authorization policy before signing. The production CLI uses a fixed configuration directory and rejects signing with a key other than the configured key path. A fully compromised host process that can modify `~/.agentpass`, invoke the Secure Enclave provider directly, or bypass Git hooks may still defeat local policy. Use OS sandboxing, least-privilege repository access, server-side branch protection, and a future AgentPass broker daemon in addition to AgentPass.

Once the public repository is available, report vulnerabilities through a private GitHub security advisory. Do not include private keys, credentials, or sensitive repository data in public issues.
