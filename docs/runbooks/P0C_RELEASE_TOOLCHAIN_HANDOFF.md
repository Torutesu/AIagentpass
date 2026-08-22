# P0-C aggregate/promotion release toolchain handoff

The aggregate and promotion jobs do not execute the release verifier from the
candidate checkout. A protected runner administrator must provision
`/opt/agentpass/release/qualification-tool` before enabling either job.

The directory is root-owned, non-writable, and contains the exact inventory
below. The files are copied from a reviewed source tree during a controlled
provisioning operation; they are never downloaded by GitHub Actions.

```text
verify-installed-toolchain.mjs
verify-external-qualification-signature.mjs
external-qualification-trust.mjs
verify-hardware-qualification-set.mjs
validate-hardware-qualification.mjs
generate-hardware-qualification-template.mjs
run-p0c-qualification.mjs
sign-hardware-qualification.mjs
p0c/verify-runner-attestation.mjs
n3e/controller-identity-contract.mjs
n3e/qualification-suite-evidence.mjs
lib/release-candidate-identity.mjs
```

Generate the canonical inventory from the staged directory:

```sh
node scripts/release/qualification/create-release-toolchain-manifest.mjs \
  /opt/agentpass/release/qualification-tool > manifest.json
```

The administrator then signs `manifest.json` with the release-toolchain trust
key and installs `manifest.sig` and `manifest.pub` as root-owned files. The
manifest digest and public-key fingerprint are stored as the protected
repository variables `AGENTPASS_P0C_RELEASE_TOOL_MANIFEST_SHA256` and
`AGENTPASS_P0C_RELEASE_TOOL_MANIFEST_FINGERPRINT`.

The workflow verifies ownership, the detached signature, the manifest digest,
and the closed file inventory before invoking any qualification verifier. A
missing or mismatched installation fails closed. This handoff itself is an
external protected-runner operation and is not proven by local tests.

## External evidence signer handoff

The promotion workflow also requires detached Ed25519 signatures for the
aggregate external qualification envelope and the child-evidence envelope.
The protected repository variables are:

```text
AGENTPASS_EXTERNAL_QUALIFICATION_SIGNATURE_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_PUBLIC_KEY_FINGERPRINT
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_SIGNATURE_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_BASE64
AGENTPASS_EXTERNAL_QUALIFICATION_CHILD_PUBLIC_KEY_FINGERPRINT
```

The aggregate signature covers canonical `{ evidence, binding }`. The child
signature covers canonical `{ evidence, binding, child_evidence }`. The
workflow verifies both signatures before digest recomputation and retains the
signature, public key, fingerprint verification, and digest results in the
promotion evidence index. Missing variables, a mismatched fingerprint, a
non-Ed25519 key, or a substituted payload stops promotion.

The public key and signatures must be produced by the approved external
qualification authority and retained with its provider/run/job records. A
locally generated key can satisfy unit tests but is not production evidence.

The trust manifest itself is supplied as the protected variable
`AGENTPASS_EXTERNAL_QUALIFICATION_TRUST_MANIFEST_JSON` and must be signed by
the same root represented by the installed toolchain's `manifest.pub`. It maps
the aggregate and child signer fingerprints to an authority ID and validity
window. The promotion workflow retains this manifest and rejects a changed or
expired manifest before verifying evidence signatures.
