# ADR-001: Native macOS security boundary

Status: accepted; native core implemented in 0.9, signed distribution pending

## Decision

The Node.js LaunchAgent remains the portable local broker and development implementation. The high-assurance macOS edition will move key creation, policy storage, request verification, audit signing, and SSHSIG generation into a signed native app/XPC service.

The native target will:

- generate its P-256 signing key with `kSecAttrTokenIDSecureEnclave`;
- store it in the data protection keychain under an AgentPass keychain access group;
- use a `SecAccessControl` policy suitable for background private-key usage;
- ship as an app-like signed bundle with a provisioning profile and keychain-access-group entitlement;
- install its helper through Apple's Service Management framework;
- expose a narrow XPC interface and authenticate callers from their audit token and code-signing identity;
- construct OpenSSH SSHSIG output internally, so no exportable key handle file is required;
- require interactive human authorization for policy changes and restore, while ordinary policy-compliant signing remains unattended.

## Why a root Node daemon is not the solution

Secure Enclave keys stored in the macOS data protection keychain are governed by application keychain access groups and code-signing entitlements. A command-line tool or unrelated root daemon does not automatically gain the signed app's keychain access group. Moving the existing Node process to root would increase attack surface without establishing the required app identity.

Apple's documentation also recommends a factored privileged service with a narrow protocol instead of forking a privileged child from an untrusted application.

## Required external prerequisites

- Apple Developer Team ID.
- Developer ID Application certificate or development signing identity.
- Provisioning profile authorizing the AgentPass keychain access group.
- Stable bundle identifiers for the host app and XPC service.

Without these values, the repository can implement and test the portable broker, protocol, policy engine, and SSHSIG fixtures, but cannot produce the final code-signed keychain isolation boundary.

AgentPass 0.9 implements that testable source layer under `native/macos`: Secure Enclave key management, SSHSIG generation, XPC client gating, and service-side Agent/policy/Git validation. See [NATIVE_BROKER.md](NATIVE_BROKER.md) for the remaining packaging and protected-state work.

## Primary references

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave)
- [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [Service Management](https://developer.apple.com/documentation/servicemanagement/)
- [Elevating Privileges Safely](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html)
- [Git SSH signing implementation](https://github.com/git/git/blob/master/gpg-interface.c)
