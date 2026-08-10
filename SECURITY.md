# Security policy

AgentPass is an early, security-sensitive prototype. Do not use it as the only control protecting production credentials.

AgentPass prevents export of the signing key and applies local authorization policy before signing. A fully compromised host process may still invoke an operation that the policy allows. Use OS sandboxing, least-privilege repository access, and branch protection in addition to AgentPass.

Once the public repository is available, report vulnerabilities through a private GitHub security advisory. Do not include private keys, credentials, or sensitive repository data in public issues.
