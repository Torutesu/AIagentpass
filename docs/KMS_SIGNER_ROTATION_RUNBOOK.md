# Hosted KMS signer rotation runbook

This runbook applies to the three currently composed hosted Ed25519 signing
purposes:

- `agent-session-grant`
- `qualification-grant-batch-manifest`
- `device-enrollment-possession-receipt`

The signing private key remains in the remote KMS/HSM. AgentPass receives only a
pinned public key and a 64-byte signature. The provider boundary must be
constructed with an injected AWS or Google Cloud KMS client; it must never read
a private key from a file, environment variable, or local process memory.

## Payload compatibility gate

The adapters enforce the provider limits exactly:

- AWS KMS `ECC_NIST_EDWARDS25519` with `ED25519_SHA_512` accepts `MessageType:
  RAW` and at most 4,096 bytes.
- Google Cloud KMS `EC_SIGN_ED25519` signs the supplied `data` using PureEdDSA;
  Cloud HSM user-provided data is limited to 8,192 bytes.

Neither adapter prehashes, truncates, pads, or otherwise rewrites the bytes.
Prehashing would change the signature scheme and is forbidden at this boundary.
Qualification manifest v2 is digest-only: the seven full Grant envelopes remain
in the batch and are verified separately. Its signing-data constructor rejects
payloads above 4,096 bytes, and the maximum-valid-field test must remain green
for every release. Reintroducing embedded Grants or widening a field beyond
that bound is a release-blocking schema change, never an adapter fallback.

## Preconditions

Hosted startup requires `AGENTPASS_KMS_PROVIDER=aws|gcp` plus distinct
`AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE` and
`AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE`, and
`AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE` values. These are remote KMS
resource identifiers; they are intentionally separate from the logical
`AGENTPASS_CLOUD_*_KEY_ID` values and their pinned public keys. All three
resources, logical key IDs, and public-key fingerprints must be distinct. AWS
uses the standard SDK credential chain; GCP uses Application Default
Credentials.

Hosted startup verifies PostgreSQL migration 0037 before constructing any KMS
provider. The database lifecycle row is authoritative: an existing key state is
never overwritten from environment configuration, and a retired, revoked, or
emergency-disabled active binding keeps readiness closed.

1. Create a new Ed25519 KMS key/version in the same purpose-specific namespace.
2. Record the key identifier, canonical SPKI public-key fingerprint, algorithm,
   purpose, and version in the change ticket.
3. Confirm that the new key fingerprint is different from the bundle, refresh,
   other signer, and every active/retiring key for the same purpose.
4. Exercise the adapter against a non-production KMS project/account. Confirm
   request byte limits, deadline cancellation, and that the returned signature
   verifies against the recorded public key.
5. Prepare the verification ring with the new key as `active` and the old key
   as `retiring` with an explicit expiry. Do not put a retiring key in the
   signing client configuration.

## Dual-read / single-write rotation

1. Deploy the new public-key ring to verifiers first. During this phase,
   verifiers accept the old and new key IDs, but issuance still uses the old
   key. Check readiness and the public, secret-free signer metadata on every
   instance.
2. Change the KMS provider binding to the new key/version and deploy it. This
   is the single-write cutover: all new Agent Session grants or qualification
   manifests must carry only the new key ID.
3. Verify one signed object for each purpose. Confirm its canonical bytes,
   purpose, key ID, algorithm, version, and signature length (exactly 64
   bytes). Confirm no private material appears in logs or health output.
4. Keep the old key in the verification ring until every object it could have
   issued has expired, plus the agreed clock-skew and incident buffer. Monitor
   unknown-key, metadata-mismatch, provider-timeout, and invalid-signature
   counters.
5. Remove the old key from the verification ring only after the expiry window.
   Then disable or schedule destruction of the old KMS key according to the
   cloud provider's retention policy. Record the final verification result.

Never write with both keys, and never accept a public-key response that differs
from the pinned fingerprint. A provider metadata substitution is an outage,
not a reason to update the pin during the same incident.

Every signing operation follows `reserve -> provider sign once -> commit exact
signature -> reply`. A committed retry returns the stored 64-byte signature. A
pending or uncertain operation must never be blindly re-signed; reconcile it
only from provider-confirmed exact signature bytes or resolve it through the
documented operator procedure. A request digest conflict is an integrity event.

## Emergency revoke

1. Declare the affected purpose and key ID. If the scope is uncertain, revoke
   each affected purpose independently rather than sharing a key or broadening
   trust.
2. Disable the KMS key/version immediately. Remove it from the active and
   retiring verification rings, and deploy the configuration with readiness
   expected to fail closed until a replacement key is ready.
3. Stop issuance and reject objects carrying the revoked key ID at every
   verifier. Do not rely on expiration alone.
4. Preserve audit records containing only request ID, purpose, key ID,
   fingerprint, timestamps, and stable error codes. Do not copy KMS error text,
   request payloads, signatures, or secrets into incident tickets.
5. Provision a new purpose-separated key, perform the preconditions above,
   then execute the dual-read/single-write procedure. Re-issue affected
   short-lived grants only after the new signer is healthy.
6. After containment, review KMS IAM policy, client identity, adapter logs,
   deployment provenance, and all objects issued by the revoked key. Schedule
   destruction only after legal/forensic retention requirements are satisfied.

## Rollback and evidence

Rollback may restore verification of the old key only while its documented
retiring expiry has not passed and the key has not been revoked. It must never
restore old-key signing after a new-key write cutover. Attach the deployment
IDs, both public-key fingerprints, readiness snapshots, and focused adapter
test output to the rotation record.
