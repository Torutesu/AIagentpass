# AgentPass release evidence

AgentPass release candidates use a detached Ed25519 signature over a strict,
canonical release-manifest v2. The verifier does not trust a public key merely
because it is shipped beside an artifact: an independently distributed
`SHA256:<base64url-SPKI-digest>` fingerprint is mandatory.

## Evidence model

The signed manifest binds all of the following:

- the release version and optional `v<version>` source tag;
- the exact Git commit and tree;
- every release artifact's basename, role, media type, byte length, and SHA-256;
- the exact bytes and entry count of `SHA256SUMS`;
- the SPDX 2.3 document digest, namespace, `documentDescribes`, source commit,
  source tree, committed Swift input inventory, and compiler/SDK metadata;
- for an `accepted_stapled` claim, the notary submission IDs and the exact
  notarytool and stapler evidence bytes.

The manifest, signature, public key, artifacts, checksum file, notarization
evidence, and hardware reports are opened with `O_NOFOLLOW`. Data is read and
hashed from that same descriptor, `nlink == 1` is required, and `fstat` identity
must remain unchanged before and after the read. This prevents path validation
from being separated from the bytes that are actually verified.

## Build the production installer

```sh
native/macos/scripts/build-app.sh --universal --output-dir "$PWD/dist" \
  --identity 'Developer ID Application: …' --team-id APPLETEAM1 \
  --app-identifier-prefix APPLETEAM1 \
  --service-profile /protected/service.provisionprofile \
  --client-profile /protected/client.provisionprofile
native/macos/scripts/build-installer.sh \
  --app "$PWD/dist/AgentPass.app" \
  --output "$PWD/dist/AgentPass-v0.18.0-macos-universal.pkg" \
  --identity 'Developer ID Installer: …'
AGENTPASS_NOTARY_KEY_ID=… \
AGENTPASS_NOTARY_ISSUER_ID=… \
AGENTPASS_NOTARY_PRIVATE_KEY_PATH=/protected/AuthKey.p8 \
scripts/release/notarize-installer.sh \
  dist/AgentPass-v0.18.0-macos-universal.pkg \
  dist/notarytool-result.json dist/stapler-result.txt
node scripts/release/generate-sbom.mjs dist/AgentPass-v0.18.0.spdx.json
node scripts/release/generate-manifest.mjs \
  dist/AgentPass-v0.18.0.release-manifest.json \
  dist/SHA256SUMS \
  --notarization-status=accepted_stapled \
  --notary-submission=SUBMISSION-UUID \
  --notarytool-evidence=dist/notarytool-result.json \
  --stapler-evidence=dist/stapler-result.txt \
  dist/AgentPass-v0.18.0-macos-universal.pkg \
  dist/AgentPass-v0.18.0.spdx.json \
  dist/release-manifest.public.pem
node scripts/release/sign-manifest.mjs \
  dist/AgentPass-v0.18.0.release-manifest.json \
  /protected/release-manifest.private.pem \
  dist/AgentPass-v0.18.0.release-manifest.sig
node scripts/release/verify-release.mjs \
  dist/AgentPass-v0.18.0.release-manifest.json \
  dist/AgentPass-v0.18.0.release-manifest.sig \
  dist/release-manifest.public.pem \
  'SHA256:PINNED_RELEASE_KEY_FINGERPRINT'
```

The private key must be an Ed25519 PKCS#8 file owned by the invoking user with
no group or other permission bits. Existing signature, manifest, or checksum
outputs are never overwritten.

`verify-release.mjs` proves signature, schema, digest, source, checksum, SBOM,
and evidence consistency. It deliberately reports `apple_ticket_verified:
false`: generic offline verification does not contact Apple and does not replace
`stapler validate`, Gatekeeper assessment, or the macOS-specific verifier.

`build-installer.sh` requires a Developer ID Installer identity and emits one
non-relocatable component package whose payload is exactly
`/Applications/AgentPass.app`. The launch daemon plist and helper are embedded
inside that app, so they are replaced as one signed bundle. Registration and
administrator approval remain explicit `SMAppService` operations; an upgrade
does not silently rewrite that approval state.

The package has no payload entry below
`/Library/Application Support/AgentPass`. Its signed preinstall and postinstall
scripts recursively validate that protected tree without following links. They
require root ownership, reject group/world-writable objects, cross-filesystem
substitution, hard-linked files, symlinks, devices, sockets, and FIFOs. Thus the
lifecycle ledger, audit/evidence chains, lifecycle pin, mutation outbox, and
audit-key rotation journals survive upgrades byte-for-byte as installer-external
state. A fresh install creates only the root-owned mode-`0700` state directory;
it does not invent configuration or lifecycle records. An unsafe existing tree
causes installation to fail closed instead of being repaired or replaced.

For a production macOS artifact, run the macOS verifier with an independently
distributed release-key fingerprint and Apple Team ID:

```sh
scripts/release/verify-macos-release.sh \
  dist/AgentPass-v0.18.0.release-manifest.json \
  dist/AgentPass-v0.18.0.release-manifest.sig \
  dist/release-manifest.public.pem \
  'SHA256:PINNED_RELEASE_KEY_FINGERPRINT' \
  'APPLETEAM1'
```

The verifier first snapshots the manifest, detached signature, public key, and
every file named by the manifest into a newly-created mode-`0700` directory.
Each source is opened with `O_NOFOLLOW`, must be a single-link regular file, and
must retain the same file identity throughout its descriptor-based copy. All
subsequent signature, digest, package expansion, code-signing, ticket, and
Gatekeeper checks use only those mode-`0400` staged bytes inside a mode-`0500`
directory. Changing an original
release path after staging therefore cannot change the bytes later executed or
assessed.

The macOS verifier checks the outer app, native onboarding executable, manager
executable, service helper, and approval client independently. Each must have the expected identifier, pinned
TeamIdentifier, hardened runtime, secure timestamp, and a Developer ID
designated requirement bound to that Team ID. The service and client signed
entitlements must each contain exactly their own expected keychain access group.
The onboarding executable, manager, and outer app must have no keychain group. Every component rejects
`get-task-allow` and disabled library validation. The helper provisioning
profiles are separately CMS-verified, and their identifiers and sole keychain
groups must agree with the signed code. The verifier also requires a trusted
Developer ID Installer signature, exact `/Applications` destination, an
app-only payload, all three preservation scripts, a valid stapled package
ticket, and a successful Gatekeeper install assessment. Every check operates on
the staged, manifest-bound package—not on an unrelated source path.

## Bind notarization evidence

An `accepted_stapled` manifest cannot be generated from a status string alone.
It requires one accepted `notarytool ... --output-format json` result and one
successful `stapler validate` transcript:

```sh
node scripts/release/generate-manifest.mjs MANIFEST SHA256SUMS \
  --notarization-status=accepted_stapled \
  --notary-submission=01234567-89ab-cdef-0123-456789abcdef \
  --notarytool-evidence=notarytool-result.json \
  --stapler-evidence=stapler-result.txt \
  ARTIFACT AgentPass-v0.18.0.spdx.json
```

The notarytool result must have status `Accepted` and an ID listed by
`--notary-submission`. The stapler transcript must record successful validation.
Both files are included in `SHA256SUMS` and in the signed manifest. These records
bind the release producer's claim; final macOS verification must still validate
the stapled ticket on the artifact itself.

## SPDX policy

The release SBOM format is SPDX JSON 2.3. Its described element is
`SPDXRef-AgentPass`. The generator inventories committed npm metadata and
committed Swift package/source inputs directly from the named Git commit, hashes
those inputs, and records Node.js, Swift compiler, Xcode, and macOS SDK metadata.
Release tooling must not label this document as CycloneDX.

## Hardware qualification gate

An unqualified template can be schema-checked without credentials:

```sh
node scripts/release/validate-hardware-qualification.mjs RESULT.json
```

A report with `qualified: true` is rejected unless all required physical tests
and gates passed, every passing result binds an existing evidence file by size
and SHA-256, and the exact candidate PKG is bound by the signed release manifest.
The report also binds source, dependency lock, Team ID, every code identity,
notarization, Cloud image, database migrations, signer-key versions, browser
versions, and a detached Ed25519 operator signature under an independently
pinned operator-key fingerprint:

```sh
node scripts/release/validate-hardware-qualification.mjs \
  RESULT.json \
  AgentPass-v0.18.0-macos-universal.pkg \
  AgentPass-0.18.0.release-manifest.json \
  AgentPass-0.18.0.release-manifest.sig \
  RELEASE.public.pem \
  'SHA256:PINNED_RELEASE_KEY_FINGERPRINT' \
  RESULT.sig OPERATOR.public.pem \
  'SHA256:PINNED_OPERATOR_KEY_FINGERPRINT' \
  QUALIFICATION-EVIDENCE-DIRECTORY
```

Both detached signatures are over exact canonical bytes and are encoded as one
base64 line. Evidence names are basenames only; symlinks, hard links, missing
files, size changes, and digest substitutions fail closed. Apple Silicon and Intel T2 reports must be signed by approved
operators and must name the same candidate artifact SHA-256 before promotion.
Intel hardware without T2 cannot qualify. Operator-key enrollment, revocation,
and the aggregate two-report verifier remain protected-release gates; a
fingerprint supplied by an untrusted artifact is not a trust root. A single
qualified report therefore does not authorize publication by itself.

## Workflow and promotion rule

`.github/workflows/release-candidate.yml` is manual-dispatch only. Its first
Linux job verifies an annotated SSH-signed tag and package version without any
production secret. Only the protected `production-signing` macOS job receives
application signing, installer signing, manifest signing, and App Store Connect
notary credentials. There is no `pull_request`, `pull_request_target`, tag-push,
or untrusted-ref path into that job.

The signing job uploads a private workflow artifact only after notarytool
returns `Accepted`, stapling succeeds, `stapler validate` succeeds, Gatekeeper
accepts the installer, and the post-staple package bytes are included in the
signed manifest. A separate `production-release` job receives no signing or
notary secrets. It downloads those exact bytes, repeats manifest, package,
ticket, Gatekeeper, code-signing, entitlement, profile, and source checks, then
creates a draft GitHub Release. It uploads an explicit manifest-bound file list
and makes the draft public only after every upload succeeds. Existing releases
are never overwritten.

Production promotion remains fail closed until all of these are available and
independently checked:

1. Developer ID signatures and exact provisioning-profile identity;
2. Apple notarization acceptance and a stapled ticket;
3. signed Apple Silicon and Intel T2 qualification reports for the same digest;
4. signed-manifest verification using the pinned release key;
5. macOS-specific designated-requirement, entitlement, Gatekeeper, and ticket
   verification.
