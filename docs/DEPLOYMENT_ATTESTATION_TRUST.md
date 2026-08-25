# Deployment-attestation trust root

The promotion workflow does not trust an attestation key or a checkout file by
itself. `ops/trust/deployment-attestation-trust.v1.json` is a canonical JSON
manifest signed by a separately provisioned Ed25519 trust-root key.

The signed manifest binds each environment/key identity to:

- the attestation public-key fingerprint and key version;
- an explicit `active` or `revoked` state; and
- a `not_before`/`not_after` validity window.

The verifier rejects non-canonical bytes, symlinks, hardlinks, group/world
writable files, unknown fields, duplicate identities, reused fingerprints,
invalid signatures, expired entries, and revoked entries. The trust-root
public key is supplied through the protected `production-release` environment
variable `AGENTPASS_DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY`; it is never generated
inside CI and no private key is stored in this repository.

The checked-in manifest intentionally contains placeholder fingerprint and
signature values until the operator performs the out-of-band trust-root
ceremony. Therefore promotion must fail closed until all of the following are
provisioned and reviewed:

1. a production-held Ed25519 trust-root key and its protected public key;
2. an attestation signing key for each enabled environment;
3. a root-signed manifest containing the real attestation fingerprint,
   validity window, and lifecycle state; and
4. a rotation/revocation record retained with the promotion evidence.

Rotation is performed by signing a new manifest with the existing root,
including both the old and replacement entries only for their intended
validity windows, then removing the old entry after its `not_after` boundary.
An attestation signed by a revoked or out-of-window key is rejected even when
its cryptographic signature is otherwise valid.
