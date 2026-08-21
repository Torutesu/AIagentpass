# macOS release and notarization

## Build boundary

Build from the frozen annotated tag/source commit in the protected
`Release candidate` workflow. Pull requests and untrusted refs must never
receive Developer ID or notarization credentials. The output is one universal
PKG; direct download and Homebrew must install that same digest.

The repository entry points are `native/macos/scripts/build-app.sh`,
`native/macos/scripts/build-installer.sh`, `scripts/release/generate-sbom.mjs`,
`scripts/release/generate-manifest.mjs`, and the protected
`scripts/release/notarize-installer.sh`. Do not invent a second packaging path.

The static distribution contract is fail closed: production app inputs must
name a `Developer ID Application:` identity, the installer must name a
`Developer ID Installer:` identity, every native executable must contain
exactly `arm64` and `x86_64`, and the final PKG digest is printed as
`artifact_sha256` before and after stapling. `AGENTPASS_EXPECTED_ARTIFACT_SHA256`
may bind notarization to an already recorded pre-notary digest. The
notarization helpers create `<artifact>.notarization.lock`; any failure leaves
`<artifact>.notarization-failed`, and either marker blocks reuse. Build a new
artifact after any failed notarization, stapling, Gatekeeper, or evidence write
operation. Existing evidence files are never overwritten.

## Sign, notarize, staple, and verify

1. Build and sign nested service/client/helper code, then the outer app and
   Developer ID Installer PKG. Verify exact identifiers, Team ID, hardened
   runtime, entitlements, provisioning profiles, universal slices, ownership,
   permissions, and absence of symlinks.
2. Submit the PKG through the protected notarization environment. The
   notarizer first verifies a trusted Developer ID Installer signature bound
   to `AGENTPASS_TEAM_ID`, then requires `AGENTPASS_NOTARY_KEY_ID`,
   `AGENTPASS_NOTARY_ISSUER_ID`, and
   `AGENTPASS_NOTARY_PRIVATE_KEY_PATH`; never print or copy their values.
   Retain only the redacted `Accepted` JSON and successful stapler output:

   ```sh
   AGENTPASS_TEAM_ID=APPLETEAM1 \
   scripts/release/notarize-installer.sh \
     /secure/candidate/AgentPass-macos-universal.pkg \
     /secure/evidence/notarytool-result.json \
     /secure/evidence/stapler-result.txt
   ```

3. After stapling, compute the PKG digest and generate/sign the manifest. The
   manifest must contain the package, SBOM, source commit/tree, nested code
   identities, notary submission, notarytool evidence, and stapler evidence.
4. Run the offline verifier against the staged manifest and exact artifacts:

   ```sh
   bash scripts/release/verify-macos-release.sh \
     /secure/candidate/release-manifest.json \
     /secure/candidate/release-manifest.sig \
     /secure/candidate/release-manifest.public.pem \
     <pinned-release-key-fingerprint> <team-id>
   ```

   Require `stapler validate`, Gatekeeper install assessment, nested
   `codesign --verify`, designated requirements, entitlements, profiles,
   universal arm64/x86_64 slices, and the exact post-staple package bytes.

## Evidence boundary

The focused tests and `/bin/bash -n` checks are static contract checks only.
They do not possess or validate a real Apple Developer ID certificate,
provisioning profile, App Store Connect notary credentials, Apple
notarization ticket, stapled ticket, or Gatekeeper decision. A passing local or
Linux run therefore remains `implemented`/`locally-qualified`, not
`externally-qualified`; missing external proof is `not_proven` and blocks
promotion. The real boundary is the protected macOS signing runner:
`codesign`/`pkgutil` must report the expected Developer ID chain and Team ID,
`notarytool` must return `Accepted`, `stapler validate` must succeed, and
`spctl --assess --type install` must accept the exact post-staple
`artifact_sha256`. Simulated, ad-hoc, failed, or digest-mismatched evidence
does not cross this boundary.

## Physical qualification

Run the protected P0-C qualification on the exact manifest-bound PKG on
Apple-silicon/Secure Enclave and Intel/T2 hardware. Cover clean install,
approval, enrollment, unattended signing, expiry/revoke, rotation, reboot,
sleep/wake, upgrade, uninstall-preserve, purge, network loss, crash/restart,
wrong identity/entitlement, unstapled package, and Gatekeeper negatives.

Each signed report records hardware model, CPU architecture, macOS build,
Secure Enclave availability, operator key fingerprint, candidate/manifest/PKG
digests, scenario results, timestamps, and evidence file digests. A local ad-hoc
build, simulator, one architecture, or unstapled package cannot pass.

## Release evidence checklist

- [ ] Annotated tag, source SHA/tree, package/SBOM/manifest digests, and CI run
  are bound and immutable.
- [ ] Developer ID Application/Installer identity, Team ID, profiles,
  entitlements, designated requirements, and hardened runtime pass.
- [ ] Notarytool result is `Accepted`; stapler output proves successful
  validation; Gatekeeper accepts the staged PKG; post-staple digest is in the
  manifest.
- [ ] Archive/PKG secret scan is clean and no release credential appears in
  logs, artifacts, images, or evidence.
- [ ] Apple-silicon and Intel/T2 reports pass the same package digest and are
  signed by the approved operators.
- [ ] Failed notarization, ticket, signature, or hardware evidence remains
  retained and blocks promotion.
