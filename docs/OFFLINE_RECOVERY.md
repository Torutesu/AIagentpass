# Offline recovery authorization

AgentPass recovery authorities use offline Ed25519 keys to authorize a hardware-key re-enrollment request. The native service generates the request from live protected state and installs a verified result only after a local Secure Enclave user-presence signature.

## Create offline authorities

Run this once on each offline signing device:

```sh
agentpass recovery keygen /secure/offline/agentpass-recovery --signer security-1
```

The command creates `security-1.private.pem` and `security-1.public.pem` with mode `0600`. It refuses existing files, unsafe output directories, symbolic links, hard-linked private keys, keys owned by another user, and group/world permissions. Stdout contains only canonical public metadata; the private key is never printed. Store the private key offline and enroll the public key and signer ID in the root-owned recovery policy through the provisioning process.

## Sign a recovery request

First stage the exact replacement generation. Service-owned roles use `agentpass native key-stage`; approval-key staging remains client-owned. Create the final audit checkpoint and push it until `anchor-status` reports zero pending evidence. Then ask the host to emit the canonical request:

```sh
agentpass native recovery-request git_signing > recovery-request.json
```

Request generation freezes normal service and audit operations for the ten-minute request lifetime. Transfer the request to an offline device. Inspect every bound value, especially the installation ID, role, current and proposed generation/fingerprint, lifecycle and audit heads, control sequence, and expiration. Then sign:

```sh
agentpass recovery sign \
  --request recovery-request.json \
  --key /secure/offline/agentpass-recovery/security-1.private.pem \
  --signer security-1 > security-1.authorization.json
```

Requests expire within 15 minutes. Input must be canonical JSON with at most one trailing newline and must be a single-link regular file no larger than 16 KiB. Authorization output is one canonical JSON line and contains no secret key material.

## Verify the threshold offline

The policy is canonical JSON:

```json
{"authorities":[{"id":"security-1","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"},{"id":"security-2","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}],"policy_id":"production-recovery","threshold":2,"version":1}
```

Verify every authorization against the same request:

```sh
agentpass recovery verify \
  --request recovery-request.json \
  --policy recovery-policy.json \
  --authorization security-1.authorization.json \
  --authorization security-2.authorization.json
```

The host request must bind this exact policy through `recovery_policy_version`, `recovery_policy_id`, and the SHA-256 `recovery_policy_hash`. It must also contain a parseable P-256 replacement key and non-null old-key, lifecycle, audit, checkpoint, and receipt heads. Success prints a canonical result containing `valid`, the threshold, sorted accepted signer IDs, and the request hash. Duplicate IDs and duplicate public keys cannot satisfy threshold; policy substitution, unknown signers, altered requests, expired requests, noncanonical input, unsafe ACL/ancestry, symlinks, and hard links fail closed.

## Install on the affected host

For `git_signing` and `session_approval`, return the request and threshold authorizations to the host and run:

Return the request and threshold authorizations to the host and run:

```sh
agentpass native recovery-install \
  --request recovery-request.json \
  --policy recovery-policy.json \
  --authorization security-1.authorization.json \
  --authorization security-2.authorization.json
```

The CLI re-verifies the threshold before contacting the service. The service independently decodes the complete evidence bundle, checks it against its root-owned policy and pinned authority fingerprints, and re-observes the exact lifecycle, audit, checkpoint, receipt, and control state. It then displays protocol version, sequence, challenge, generations, fingerprints, request hash, lifecycle head, and expiry in the macOS authentication prompt. Service-key recovery requires the active approval key; approval-key recovery proves possession of the staged replacement approval key.

Successful installation writes the exact signed recovery record through mutation outbox, external pin, and lifecycle ledger, revokes every session, and leaves the running daemon fail-stopped. Restart the service to load the replacement key. Any changed runtime head, expired request, policy substitution, invalid local signature, or replay is rejected before activation.

## Recover the audit-checkpoint key

Audit-key recovery adds a second, anchor-specific threshold ceremony. The local lifecycle record is prepared first but is not committed. The service binds its predicted record hash to the latest fully anchored retiring-key checkpoint, the global anchor event boundary, transition history, tenant, installation, policy, request nonce, and expiration:

```sh
agentpass native recovery-prepare \
  --request recovery-request.json \
  --policy recovery-policy.json \
  --authorization security-1.authorization.json \
  --authorization security-2.authorization.json \
  > anchor-authorization.json
```

`recovery-prepare` only accepts an `audit_checkpoint` request. For other roles it directs the operator to `recovery-install`. It does not change the Keychain, lifecycle ledger, transition store, journal, or anchor.

Each offline authority inspects and signs the exact schema-v3 authorization:

```sh
agentpass recovery anchor-sign \
  --authorization anchor-authorization.json \
  --key /secure/offline/agentpass-recovery/security-1.private.pem \
  --signer security-1 \
  --output security-1.anchor-approval.json

agentpass recovery anchor-verify \
  --authorization anchor-authorization.json \
  --policy recovery-policy.json \
  --approval security-1.anchor-approval.json \
  --approval security-2.anchor-approval.json \
  > anchor-evidence.json
```

Install the canonical evidence on the affected host:

```sh
agentpass native recovery-anchor-install --evidence anchor-evidence.json
```

Before displaying macOS authentication, the service independently re-verifies the pinned converted anchor policy, sorted unique threshold approvals, exact authorization, expiration, runtime state, control sequence, lifecycle preparation, final checkpoint and receipt, global event boundary, and transition chain. The active local approval key then signs the exact lifecycle statement with user presence. Only after that proof succeeds does the replacement Secure Enclave audit key sign the anchor authorization.

The exact v3 transition is written to the root-private recovery journal before HTTP submission. A successful activation requires the anchor receipt and transition to be verified and fsync'd in the transition store, then the journal completion to be durable, before the exact previously prepared lifecycle record is committed. Ambiguous HTTP responses never authorize local activation; retries reuse the exact transition bytes. Startup reconciles store-accepted/journal-incomplete state and commits any already-authorized lifecycle record, then exits so the service restarts on the replacement signer.

The service configuration must include the complete anchor recovery set. Partial configuration fails closed:

```json
{
  "recovery_policy_path": "/Library/Application Support/AgentPass/recovery-policy.json",
  "installation_id": "build-mac-01",
  "audit_key_transition_path": "/Library/Application Support/AgentPass/audit-key-transitions.jsonl",
  "audit_key_recovery_plan_directory": "/Library/Application Support/AgentPass/audit-key-recovery-plans",
  "audit_key_recovery_approval_directory": "/Library/Application Support/AgentPass/audit-key-recovery-approvals"
}
```

Both journal directories must be service-owned mode `0700`. The plan journal's immutable records and mutable tip, and the approval journal's immutable user-presence proof (exact signature, signer fingerprint, lifecycle-statement hash, and anchor-authorization hash), are validated on every startup. Creating a request does not freeze normal operations; the service freezes signing, checkpoint creation, audit mutation, session issuance, control mutation, and key-management operations atomically only after threshold evidence verifies. Drift, replay, policy substitution, duplicate approvals, local signer substitution, stale checkpoints, pending anchor evidence, or a non-latest event boundary fails closed.
