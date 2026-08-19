# macOS distribution artifact and onboarding gate

The production install unit is the exact Developer ID Installer-signed PKG.
`native/macos/scripts/build-installer.sh` refuses unsigned input, verifies the
package, and emits `<package>.inventory.json` beside the PKG. The inventory is
canonical JSON: it contains the PKG byte count and SHA-256 plus a sorted,
symlink-free inventory of every file in the assembled `AgentPass.app`.

The inventory and PKG must be copied together. Do not rebuild, re-sign, or
rename either file after evidence is produced. A changed byte, missing file,
symlink, hard link, duplicate inventory entry, or changed inventory JSON is a
hard failure.

## Protected release evidence

After the credentialed macOS job has run `pkgutil --check-signature`,
`xcrun notarytool`, `xcrun stapler validate`, and the install Gatekeeper
assessment, create the closed evidence document and the three small canonical
JSON projections in one evidence directory. The evidence must bind all four
records to the PKG SHA-256 and bind the inventory descriptor to the exact
inventory file:

```sh
node native/macos/scripts/verify-distribution-evidence.mjs \
  distribution-evidence.json \
  AgentPass-1.0.0-macos-universal.pkg.inventory.json \
  release-root \
  evidence
```

The verifier requires a trusted `Developer ID Installer` identity and a
10-character Team ID, an `Accepted` notary result with a UUID, validated
stapling, and an accepted Gatekeeper assessment. It re-hashes the candidate,
re-hashes every inventory entry, and re-reads every evidence projection.
Absent, non-canonical, unknown, stale, or digest-mismatched evidence exits
non-zero. The output `status: "verified"` means the supplied evidence is
internally bound; it is not a claim that this checkout performed Apple’s
external checks.

## First-run onboarding

The onboarding executable must be launched only from the installed,
signature-verified `AgentPass.app`. The distribution gate runs before the
browser/CLI handoff:

1. Verify the PKG and inventory together.
2. Verify the Developer ID/notarization evidence together with the same PKG
   digest.
3. Install the exact PKG, then launch the app from `/Applications`.
4. Complete organization/device enrollment through the browser handoff.
5. Run the installed manager’s status/self-test before authorizing an agent.

Homebrew or a copied app bundle is an evaluation path, not production
distribution. Production onboarding must not continue when any artifact or
evidence check is unknown or fails.

## Physical hardware qualification evidence

The separate `macOS hardware qualification evidence` workflow must run once on
an Apple Silicon runner and once on an Intel runner for the exact release
commit. It emits one canonical JSON report per architecture. The report binds
the signed artifact byte digest to the observed machine architecture and to
three fixed physical probes: launchd Host/Child identity, an NSXPC authorization
round trip, and crash/restart recovery. Each probe must emit a single JSON
object with `status: "passed"`; a missing probe, a non-zero exit, malformed
output, an architecture mismatch, or an unverified signature aborts the run.

Verify a retained report independently with:

```sh
node native/macos/Qualification/hardware-qualification.mjs --verify REPORT.json
```

The verifier checks canonical JSON, the exact artifact byte count and SHA-256,
and requires all three checks to be passing. There is no `skipped`, `unknown`,
or dry-run success state in this contract; absence of either architecture's
report keeps release status `not_proven`.

The protected runners must be physical macOS machines, not VMs or Rosetta,
with the release artifact already installed or otherwise available at the
supplied absolute path. The three runner-local probe executables must exercise
the real signed launchd service and Host/Child NSXPC path, intentionally crash
the supervised process, observe launchd restart it, and report only bounded,
redacted JSON. Configure their absolute paths as the protected repository
variables `AGENTPASS_LAUNCHD_HOST_CHILD_PROBE`, `AGENTPASS_NSXPC_PROBE`, and
`AGENTPASS_CRASH_RESTART_PROBE`. The workflow does not manufacture probes or
claim hardware evidence when those prerequisites are absent.
