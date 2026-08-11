# AgentPass remote control protocol

## Trust model

The administration key is Ed25519 and should be generated and retained on an offline or separately administered host. AgentPass signing hosts receive only its public key. A control bundle is public data and may be distributed as a static JSON file through a CDN, object store, or repository endpoint that provides HTTPS.

Configuring a trust root is a fail-closed transition. The broker will not start without a locally installed, cryptographically valid bundle and will not sign once it expires. In local mode, an HTTPS URL enables background refresh. In native mode, the root-owned policy and control-state path are authoritative; `agentpass control fetch` verifies transport in the CLI and sends the signed bundle to the service, but scheduling that command is currently an operator responsibility.

Replacing an existing administration public key requires the explicit `--confirm ROTATE_TRUST` acknowledgement. The previous cached bundle is archived because signatures from the old root must not be accepted under the new configuration.

## Signed statement

The signature covers canonical JSON containing:

- `version`: protocol version `1`;
- `sequence`: positive monotonically increasing integer;
- `issued_at`: UTC timestamp;
- `expires_at`: UTC timestamp no more than seven days after issuance;
- `global_revoked`: emergency stop boolean;
- `revoked_agents`: sorted unique Agent UUIDs.

The transport object also contains the administration-key fingerprint and a Base64 Ed25519 signature. Unknown fields are discarded during verification and are not trusted.

## Update rules

- Content changes require a strictly higher sequence.
- Re-fetching the exact same sequence and content is idempotent.
- Different content at an existing sequence is equivocation and is rejected.
- A sequence lower than the active or previously observed sequence is rejected.
- Missing, invalid, expired, oversized, redirected, or non-HTTPS responses never replace the last valid bundle.
- Once the last valid bundle expires, signing stops until a new valid bundle is installed.

Automatic fetch outcomes and sequence changes are written to the AgentPass audit chain. `agentpass broker ping` exposes the active sequence, last successful fetch time, and latest fetch error.

## Recovery

If a published bundle expires, create a new bundle with a higher sequence and apply it locally or restore the HTTPS endpoint. An expired cached bundle is still cryptographically inspected for its sequence, so expiration does not permit rollback.

Local LaunchAgent mode cannot preserve the highest observed sequence against an attacker who can rewrite all files as the same user and restart the process. Keep validity periods short and the HTTPS source available. Native mode atomically persists canonical signed bundles in a mode `0600` regular file under root-owned, non-group/world-writable ancestry. It retains the sequence from an expired bundle across restart, rejects rollback and equivocation, and fails signing and session issuance closed on expiry, global revocation, per-Agent revocation, or an audit failure following state application.
