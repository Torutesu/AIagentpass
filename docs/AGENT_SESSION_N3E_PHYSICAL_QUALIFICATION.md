# Agent session N3-E physical qualification

Status: operator contract and runbook only. No Developer ID-signed, notarized,
launchd/XPC N3-E qualification has been executed or passed in this worktree.

This document is the handoff for the eventual physical qualification of the
process-bound Agent session path. It deliberately separates three kinds of
evidence:

| Evidence | What it proves | What it does not prove |
| --- | --- | --- |
| Deterministic native tests | Session state, restart recovery, retry ambiguity, binding, clock, audit, and leakage invariants | A real signed daemon, XPC transport, launchd, Secure Enclave, or physical Agent process |
| Source/CLI contract tests | The physical harness inventory, candidate binding, bounded evidence projection, and fail-closed entrypoints remain present | That any physical scenario was run |
| Physical qualification report | The exact notarized candidate passed the fixed scenarios on an approved Mac hardware lane | Security review, production deployment, or a different candidate |

The report may be called `qualified` only after the physical runner has run the
exact candidate and the independent validators have accepted both required
hardware lanes. A source test, a POSIX durability model, a mock Cloud server,
an ad-hoc build, or a report template is not physical qualification evidence.

## Contract under test

The qualification has one fixed inventory. Drivers and scenarios are not
selected interactively on the runner.

- 16 gates: package/Gatekeeper, clean install and launchd/XPC, Secure Enclave
  enrollment, Cloud possession, Claude Code unattended signing, Cursor
  unattended signing, audit observation, policy reduction, offline expiry,
  revoke/emergency stop, crash/reboot recovery, sleep/network/clock recovery,
  upgrade, uninstall/reinstall, current-user purge, and negative identity/
  entitlement cases.
- 20 tests: the exact names are frozen in
  `scripts/release/run-p0c-qualification.mjs` and
  `scripts/release/validate-hardware-qualification.mjs`.
- Two physical classes: `apple_silicon` and `intel_t2`. Both are required for
  aggregate promotion.
- The installed runner must contain exactly 16 root-owned, protected driver
  files and exactly 16 root-owned, protected scenario files. The driver
  configuration binds each gate to its scenario basename and SHA-256 digest.
- Evidence is verified by the lane validator and then by
  `scripts/release/verify-hardware-qualification-set.mjs`. The aggregate
  verifier requires distinct Apple-silicon and Intel-T2 reports with the same
  source, artifact, Team ID, release-manifest, Cloud image, migration, and
  signer-version bindings.

The repository currently contains the fixed driver declarations and the
initial checked-in physical scenario implementations. The provisioning
contract intentionally refuses an installed scenario directory that does not
contain all 16 production entrypoints. Complete the physical scenario
implementation and provision it on the protected runner before scheduling a
qualification. Do not fill missing entries with a fixture, test file, shell
stub, or a copied development executable.

## Prerequisites

An operator must have all of the following before starting:

1. A successful Release Candidate workflow run from the canonical repository,
   on protected `main`, producing the exact
   `notarized-release-candidate` artifact.
2. The candidate's signed release manifest, manifest signature, pinned public
   key fingerprint, notarization evidence, universal PKG, and release
   attestation. The PKG must be the product artifact named and hashed by the
   signed manifest.
3. Two clean, dedicated macOS runners: one Apple silicon/Secure Enclave lane
   and one Intel/T2 lane. They must have the intended Node.js version,
   `codesign`, `spctl`, `pkgutil`, `xcrun stapler`, `installer`, `launchctl`,
   and the supported Claude Code/Cursor test clients.
4. A root-owned, mode-protected `/opt/agentpass/p0c` installation on each
   runner. Its `gates/` and `scenarios/` directories must have the exact
   16-entry inventories and digest-pinned `driver-config.json` plus
   `scenario-config.json`.
5. A separately approved operator key for each hardware lane. The private
   key is injected only into the ephemeral runner workspace, with mode `0600`;
   it must never be committed, uploaded, printed, or placed in a report.
6. A release-manifest verification fingerprint, expected Developer ID Team
   ID, lane operator IDs/fingerprints/public keys, browser version inventory,
   and the protected GitHub environment variables/secrets documented by
   `.github/workflows/p0c-hardware-qualification.yml`.

The physical path is intentionally not runnable from a normal developer
laptop. The production command rejects non-macOS execution, injected metadata,
injected command runners, unprotected driver files, changed driver identity,
partial protocols, and missing gates.

## Prepare a runner (operator-controlled, once per image)

Run these steps as an administrator on each dedicated Mac. Keep the source and
scenario directories outside the user's home directory and do not use a
symlink for a production input.

### 1. Build the machine scenario configuration

The five executable paths, test repository, Cloud probe URL, and checkpoint
directory must be real protected paths on the target Mac. The command hashes
the executables into a canonical `scenario-config.json`.

```sh
sudo mkdir -m 0700 /var/empty/agentpass-p0c
sudo mkdir -m 0700 /var/empty/agentpass-p0c/checkpoints
sudo mkdir -m 0700 /var/empty/agentpass-p0c/test-repository

sudo node scripts/release/p0c/generate-scenario-config.mjs \
  --native-client /Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client \
  --native-manager /Applications/AgentPass.app/Contents/MacOS/agentpass-native-manager \
  --native-service /Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service \
  --claude-code /usr/local/bin/claude \
  --cursor /Applications/Cursor.app/Contents/MacOS/Cursor \
  --test-repository /var/empty/agentpass-p0c/test-repository \
  --cloud-probe-url https://qualification-api.example.invalid/v1/probe \
  --checkpoint-directory /var/empty/agentpass-p0c/checkpoints \
  --output /var/empty/agentpass-p0c/scenario-config.json
```

Replace the example Cloud URL with the approved qualification endpoint. It
must be HTTPS and must not contain a credential in the URL. The example domain
above is deliberately non-routable; it is not a usable qualification target.

### 2. Provision the root-owned runner

The scenario source directory supplied to this command must contain exactly
the 16 production scenario basenames. The command refuses a partial or
unexpected inventory and publishes the runner atomically.

```sh
sudo node scripts/release/p0c/provision-runner.mjs \
  --source-root "$PWD/scripts/release/p0c" \
  --scenarios /var/empty/agentpass-p0c/physical-scenarios \
  --machine-config /var/empty/agentpass-p0c/scenario-config.json
```

After provisioning, verify the fixed inventory without printing file contents:

```sh
sudo find /opt/agentpass/p0c/gates -maxdepth 1 -type f -perm -111 -print | sort
sudo find /opt/agentpass/p0c/scenarios -maxdepth 1 -type f -perm -111 -print | sort
sudo stat -f '%Su %Sp %N' /opt/agentpass/p0c/driver-config.json /opt/agentpass/p0c/scenario-config.json
```

The expected result is 16 basenames in each directory, root ownership, no
group/world write permission, and no symlink. A mismatch is a hard stop.

## Execute the physical qualification

The supported entrypoint is the manually dispatched GitHub Actions workflow.
It first checks that the candidate run is a successful same-repository Release
Candidate run on `main`, verifies the signed candidate before executing any
gate, and then runs the two hardware lanes independently.

From a trusted operator workstation:

```sh
gh workflow run p0c-hardware-qualification.yml \
  --repo Torutesu/AIagentpass \
  --ref main \
  -f release_run_id=RELEASE_CANDIDATE_RUN_ID \
  -f release_artifact_name=notarized-release-candidate
```

Replace `RELEASE_CANDIDATE_RUN_ID` with the completed Release Candidate run
ID. Do not pass a branch, fork artifact, manually downloaded PKG, or a local
build. Monitor the run and stop on any failed or skipped gate:

```sh
gh run list --repo Torutesu/AIagentpass --workflow p0c-hardware-qualification.yml --limit 5
gh run view QUALIFICATION_RUN_ID --repo Torutesu/AIagentpass --log-failed
```

Each lane performs, in order:

1. exact candidate file cataloging and signed release verification;
2. report-template generation bound to the signed manifest and PKG digest;
3. root-owned driver execution with sanitized environment and bounded output;
4. package, launchd/XPC, Secure Enclave, Cloud, Agent, lifecycle, recovery,
   and negative-identity scenarios;
5. canonical report creation, Ed25519 operator signing, and independent lane
   validation; and
6. upload of only the report, detached signature, operator public key, and
   hashed evidence files.

The private operator key is removed in an `always()` cleanup step. If cleanup
fails, quarantine the runner and rotate the lane key before any retry.

## Verify retained evidence

Download the lane artifacts and the exact candidate artifact only through the
GitHub Actions artifact interface. Do not download or retain an operator
private key. The final verification command takes 16 positional arguments;
the two lane reports must be from the same candidate and must be independently
validated.

```sh
node scripts/release/verify-hardware-qualification-set.mjs \
  RELEASE_MANIFEST RELEASE_MANIFEST_SIG RELEASE_MANIFEST_PUBLIC_KEY RELEASE_MANIFEST_FINGERPRINT \
  PRODUCT_PKG \
  APPLE_REPORT APPLE_REPORT_SIG APPLE_OPERATOR_PUBLIC_KEY APPLE_OPERATOR_FINGERPRINT APPLE_EVIDENCE_DIR \
  INTEL_T2_REPORT INTEL_T2_REPORT_SIG INTEL_T2_OPERATOR_PUBLIC_KEY INTEL_T2_OPERATOR_FINGERPRINT INTEL_T2_EVIDENCE_DIR \
  APPROVED_OPERATOR_POLICY.json
```

The verifier must emit a JSON summary with `ok: true`, `qualified: true`,
`production: true`, and both hardware classes. A missing report, a skipped
test, a changed evidence file, a report/artifact mismatch, an unapproved
operator, a source/Team ID mismatch, or a missing second hardware class must
produce a non-zero exit status. Treat any other result as unqualified.

For a single lane, the independent validator is also available:

```sh
node scripts/release/validate-hardware-qualification.mjs \
  REPORT.json PRODUCT_PKG RELEASE_MANIFEST RELEASE_MANIFEST_SIG RELEASE_MANIFEST_PUBLIC_KEY \
  RELEASE_MANIFEST_FINGERPRINT REPORT.sig OPERATOR_PUBLIC_KEY OPERATOR_FINGERPRINT EVIDENCE_DIR
```

Do not edit a report or evidence file to make validation pass. Restart from a
fresh candidate and fresh runner workspace if any input changes.

## Evidence handling and prohibited shortcuts

Physical evidence may contain only bounded, non-secret metadata and hashes.
The qualification runner records command status, timing, output byte counts,
and stdout/stderr SHA-256 digests; it does not put command output, credentials,
private keys, session proofs, Cloud tokens, or repository contents in the
evidence JSON. Never add a raw log or terminal capture to the retained
evidence directory without a security review and schema change.

The following do not count and must not be used to unblock promotion:

- `swift test`, `npm test`, source/contract tests, or static inspection alone;
- `native/macos/scripts/qualification/g42-posix-kill-restart.mjs`, because it
  is a deterministic POSIX durability model with a local fixture;
- any `production: false` invocation, injected metadata provider, fake command
  runner, mock/fake/stub scenario, ad-hoc signature, self-signed artifact, or
  development XPC service;
- a report template with `qualified: false`, a report that was edited after
  generation, or a report from only one hardware class; and
- a copied driver/scenario whose digest is not the one in the protected
  runner's canonical configuration.

If a command prints a secret, stop the run, revoke/rotate the affected
credential, preserve only the minimum incident metadata, and do not upload the
workspace. The report should be marked unqualified and the runner reprovisioned.

## Current N3-E exit status

The deterministic Agent session core and source/CLI contract are implemented
and locally testable. The following physical exit evidence remains open:

- Developer ID Application/Installer signing and notarization of the exact
  candidate;
- clean install, launchd registration, real XPC encode/decode, process kill,
  daemon restart, and lost-reply qualification on supported macOS hosts;
- Secure Enclave non-exportability and possession checks on Apple silicon and
  Intel/T2 hardware;
- real Claude Code and Cursor process/ancestry/worktree binding, unattended
  signed commits, audit observation, revocation, upgrade, and uninstall;
- independent review of retained evidence and secret/log leakage; and
- successful aggregate verification of both physical reports for the same
  candidate.

Until those artifacts exist and the aggregate verifier emits the passing
summary, N3-E is not complete and N4 signing must remain disabled.

## Local contract check

This command checks the source and CLI contracts only. A passing result is not
a physical qualification result:

```sh
node --test test/n3e-physical-qualification-contract.test.mjs
```
