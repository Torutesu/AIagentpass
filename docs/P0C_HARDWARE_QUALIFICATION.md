# P0-C physical Mac qualification runner

`scripts/release/run-p0c-qualification.mjs` is the execution contract for the physical Mac release gate. It creates an unsigned canonical hardware-qualification v2 report and private evidence files. It does not sign the report, notarize a package, or replace the release verifier.

## Production-only command

The CLI refuses every non-darwin host before it reads the requested files. It has no local, simulator, POSIX-model, or ad-hoc “qualification” mode:

```text
node scripts/release/run-p0c-qualification.mjs \
  --template /absolute/path/production-report-template.json \
  --output /absolute/path/qualification.json \
  --artifact /absolute/path/AgentPass-v0.18.0-macos-universal.pkg \
  --gate-drivers /absolute/path/p0c-gates \
  --evidence-dir /absolute/path/p0c-evidence \
  --operator operator@example.com
```

The template, artifact, gate-driver directory, evidence directory, and output path must all be explicit absolute paths. The output file must not exist. The evidence directory must already exist, be mode `0700`, and be empty. The runner never creates a guessed path or overwrites an existing result.

## Template contract

The input is the exact canonical `hardware-qualification-v2` production report template. Its top-level keys must match `scripts/release/hardware-qualification.template.json` exactly. The template must already contain the release bindings copied from the candidate release:

- source commit, dependency-lock digest, release-manifest digest, product name and product SHA-256;
- Team ID, nested code identities, accepted notarization metadata;
- Cloud image digest, migration-manifest digest, signer key versions and browser versions;
- operator public-key fingerprint and `qualified: false`.

The runner computes the product SHA-256 again and refuses any basename or digest mismatch. It replaces only physical metadata, timestamps, operator, tests, gates, and the final qualified value. The operator signature is intentionally separate and is applied after the runner by the release qualification process.

## Fixed physical metadata

On darwin the runner invokes only these absolute commands, directly and without a shell:

| Field | Command |
| --- | --- |
| architecture | `/usr/bin/uname -m` |
| model identifier | `/usr/sbin/sysctl -n hw.model` |
| macOS version | `/usr/bin/sw_vers -productVersion` |
| macOS build | `/usr/bin/sw_vers -buildVersion` |
| Secure Enclave probe | `/usr/sbin/ioreg -rd1 -c AppleSEPManager` |

The command environment is replaced with the fixed non-secret environment `HOME=/var/empty`, `LANG=C`, `LC_ALL=C`, and `PATH=/usr/bin:/bin:/usr/sbin:/sbin`. stdin is closed, `shell:false` is used, and cwd is `/`. Metadata output is parsed in memory and never persisted.

## Gate-driver contract

The driver directory must contain exactly these 16 single-link, regular, non-group/world-writable executable basenames. In production, the directory and every driver must be owned by root. The runner snapshots each driver identity and fails its gate if the file changes before or during execution:

```text
gatekeeper-notarization
clean-install-launchd-xpc
secure-enclave-enrollment
cloud-possession-verification
claude-code-unattended-sign
cursor-code-unattended-sign
audit-upload-observation
policy-reduction-refresh-ack
offline-expiry
revoke-emergency-stop
crash-restart-recovery
sleep-wake-network-clock
upgrade-preserves-state
uninstall-reinstall-recovery
current-user-purge
negative-identity-and-entitlement-cases
```

Each driver is started directly with no arguments. The runner supplies only four non-secret immutable release bindings (`AGENTPASS_P0C_ARTIFACT_PATH`, `AGENTPASS_P0C_ARTIFACT_SHA256`, `AGENTPASS_P0C_SOURCE_COMMIT`, and `AGENTPASS_P0C_TEAM_ID`). It must exit `0` and print one bounded JSON object to stdout:

```json
{
  "schema_version": 1,
  "gate": "gatekeeper-notarization",
  "status": "passed",
  "tests": [
    { "name": "exact-pkg-install", "status": "passed" }
  ]
}
```

The `gate` value must match the fixed basename. Every test must be reported exactly once across the 16 drivers, and the complete fixed test set is:

```text
exact-pkg-install, launchd-xpc-approval, secure-enclave-key-creation,
secure-enclave-nonexportability, cloud-possession-proof,
claude-code-unattended-sign, cursor-code-unattended-sign,
unrelated-process-denied, audit-console-observation, policy-reduction-denied,
offline-expiry-denied, revoke-denied, emergency-stop-denied,
service-crash-recovery, os-reboot-recovery, sleep-wake-recovery,
network-clock-failure, upgrade-preserves-state, uninstall-reinstall-recovery,
current-user-purge
```

### Checked-in driver runtime

The repository contains the 16 thin entrypoints under `scripts/release/p0c/drivers`. They have a fixed, test-enforced one-to-one assignment of all 20 tests and cannot accept arguments, print their own passing result, or execute a path chosen by the workflow. Each entrypoint delegates to `scripts/release/p0c/lib/driver-runtime.mjs`.

The runtime recomputes the exact candidate PKG digest and binds every scenario result to the candidate SHA-256, source commit, and Developer ID Team ID supplied by the qualification runner. It then executes only the root-owned, digest-pinned scenario executable assigned in canonical `/opt/agentpass/p0c/driver-config.json`. The config, scenario directory, and executable must be protected single-link files; scenario replacement before or during execution fails closed. Child stdin is closed, no shell is used, the environment is reduced to fixed system paths plus non-secret release bindings, and stdout/stderr are bounded. Raw scenario stderr is never copied into the runner protocol.

A scenario must perform the physical operation and return this internal protocol:

```json
{
  "schema_version": 1,
  "gate": "gatekeeper-notarization",
  "status": "passed",
  "tests": [{ "name": "exact-pkg-install", "status": "passed" }],
  "bindings": {
    "artifact_sha256": "<64 lowercase hex>",
    "source_commit": "<40 lowercase hex>",
    "team_id": "ABCDEFGHIJ"
  }
}
```

Static configuration, an operator assertion, a prior run, or a result bound to another candidate cannot pass. The checked-in entrypoints and runtime are the trust adapter. The destructive scenario executables are separately provisioned machine procedures and remain physical qualification work until each procedure is implemented, reviewed, and executed on both hardware lanes.

The first three physical procedures are now checked in under `scripts/release/p0c/scenarios`:

- `gatekeeper-notarization` performs Gatekeeper assessment, PKG signature and stapler validation, installs the exact bound PKG as root, and revalidates the installed app signature and Team ID;
- `clean-install-launchd-xpc` verifies root-owned installed components, all relevant code signatures, the system launchd service, and real native-client XPC `ping`/`control-status` calls;
- `secure-enclave-enrollment` calls the production service's non-creating `--device-auth qualify` probe, proves the fixed P-256 Secure Enclave key is non-exportable and sign-capable, verifies a fresh release-bound possession signature, and requires ControlBundle v2 to expose the same public key.

These procedures cannot pass on injected Linux execution, a non-root runner, a substituted executable, a different device key, an exportable-key claim, or a static operator assertion. The remaining 13 procedures are still open and therefore production provisioning continues to require an externally reviewed exact 16-scenario directory; missing scenario names fail closed.

The candidate checkpoint revalidates pinned executable identity before and after each implemented operation. Pinned commands execute from an exclusive root-private immutable copy created from the already verified bytes, so replacing the original pathname after the snapshot cannot change the child image; the copy is reverified and removed after child completion.

The exact PKG scenario now creates `/candidate-checkpoint.json` exclusively inside the configured protected checkpoint directory after installation. The checkpoint binds the artifact digest, source commit, Team ID, all six release-attested CodeDirectory hashes, observed designated requirements, content-tree digests, and filesystem identities. It is never overwritten. Every implemented post-install scenario verifies the checkpoint and installed code objects before and after its physical operation; symlink, hard-link, same-content inode replacement, writable ancestry, digest change, and mixed nested identities fail closed.

The negative-identity lane has a strict release-bound four-role manifest for the approved client, same-identity client missing its required entitlement, wrong-Team-ID client, and ad-hoc client. The native service now accepts only the exact configured peer requirement that combines the fixed client identifier, Developer ID Application certificate marker, Team ID, and approval-key entitlement. This is supporting implementation evidence only: the negative gate remains open until all four signed probes are built and the real launchd/XPC service physically proves the allow/deny matrix.

### One-time runner provisioning

Provisioning is deliberately separate from the GitHub Actions job. First create the fixed parent once as root. Materialize a dedicated, reviewed copy of `scripts/release/p0c` and the 16 scenario executables in root-owned, non-group/world-writable source directories; do not point the root provisioner at the CI user's mutable working checkout. The scenario filenames must exactly match the gate list. Then run:

```text
node scripts/release/p0c/generate-scenario-config.mjs \
  --native-client /Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client \
  --native-manager /Applications/AgentPass.app/Contents/MacOS/agentpass-native-manager \
  --native-service /Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service \
  --claude-code /absolute/root-owned/path/to/claude \
  --cursor /absolute/root-owned/path/to/cursor-agent \
  --test-repository /absolute/path/to/isolated-qualification-repository \
  --cloud-probe-url https://qualification.example.invalid/v1/probe \
  --checkpoint-directory /absolute/root-owned/path/p0c-checkpoints \
  --output /absolute/path/scenario-config.json

sudo /usr/bin/install -d -o root -g wheel -m 0755 /opt/agentpass
sudo /absolute/path/to/node /absolute/root-owned/path/reviewed-p0c-source/provision-runner.mjs \
  --source-root /absolute/root-owned/path/reviewed-p0c-source \
  --scenarios /absolute/root-owned/path/p0c-scenarios \
  --machine-config /absolute/root-owned/path/scenario-config.json
```

The config generator snapshots the SHA-256 of the exact native client, native manager, native service, Claude Code, and Cursor Agent executables and refuses unsafe inputs or output replacement. The provisioner is production-locked to root on macOS and `/opt/agentpass/p0c`. It verifies an exact 16-driver and 16-scenario inventory, refuses symlinks, hard links, writable or changed source files, copies both runtimes and the machine config through a private sibling staging directory, applies root ownership and fixed modes, generates the canonical digest-pinned driver config, verifies every installed digest, and atomically renames the completed tree into place. It refuses an existing destination; upgrades require a separately reviewed replacement/rollback procedure and cannot silently alter a qualification runner.

No operator private key, Developer ID credential, candidate artifact, or Cloud secret is written into the provisioned tree. Scenario executables must also remain secret-free and obtain only the non-secret candidate bindings passed by the driver runtime.

stdout and stderr are bounded to 256 KiB per stream. The runner records only byte counts, SHA-256 digests, truncation, exit code/signal, timeout/output-limit state, and duration. Raw child output is never written to the report, evidence directory, or error output. A timeout sends `SIGTERM`, then `SIGKILL` after the bounded grace period. An output limit does the same.

## Evidence and qualification rule

Every gate and test receives a separate JSON evidence file. Evidence files are created with `O_NOFOLLOW|O_EXCL`, mode `0600`, and must remain regular single-link files. Each report entry binds the evidence basename, exact byte count, and SHA-256. The evidence payload contains metadata and output hashes only.

`qualified` is true only when all of the following hold:

1. The production CLI is executing on darwin.
2. Physical metadata was collected from the fixed commands; Secure Enclave is available and the hardware is not `intel_without_t2`.
3. All 16 gate drivers physically ran, returned the passing protocol, and exited successfully.
4. All 20 required tests were reported exactly once and passed.
5. The exact candidate artifact matches the production template and the template binds an accepted notarized release.

Injected metadata and command runners are exposed only for deterministic unit tests. An injected run is always emitted as `qualified:false`, even if every injected gate says “passed”. This is deliberate: ad-hoc, simulator, Linux, fake-provider, and modeled durability evidence can support development but can never be called physical production qualification.

The resulting report is unsigned. The release process must separately verify the signed release manifest, exact notarized package, report evidence, and detached operator signature using `scripts/release/validate-hardware-qualification.mjs`. A report that has not gone through that verifier is not a production release claim.

## Protected GitHub execution

`.github/workflows/p0c-hardware-qualification.yml` accepts only the fixed `notarized-release-candidate` artifact from a successful same-repository `Release candidate` workflow run on protected `main`. It has two independent self-hosted lanes:

- `agentpass-p0c-apple-silicon` with environment `p0c-hardware-apple-silicon`;
- `agentpass-p0c-intel-t2` with environment `p0c-hardware-intel-t2`.

Each environment supplies only its own operator private key. Developer ID, installer, provisioning-profile, release-manifest, and notarization secrets are never exposed to these runners. Repository/environment variables pin the release fingerprint, Team ID, operator IDs/fingerprints/public keys, canonical browser-version inventory, and the external approved-operator policy. Gate drivers are provisioned outside the checkout at `/opt/agentpass/p0c/gates` and must satisfy the root-ownership contract above.

The final aggregate job is hosted and secret-free. It re-verifies both reports and the signed candidate, requires the two hardware classes to be distinct, applies the external operator policy, and emits `p0c-hardware-qualification-summary`. It does not publish a release.

Required protected configuration:

- repository variables: `AGENTPASS_CLOUD_IMAGE_DIGEST`, `AGENTPASS_RELEASE_MANIFEST_KEY_FINGERPRINT`, `AGENTPASS_RELEASE_TEAM_ID`, `AGENTPASS_RELEASE_ALLOWED_SIGNERS`, `AGENTPASS_P0C_BROWSER_VERSIONS_JSON`, `AGENTPASS_P0C_APPROVED_OPERATOR_POLICY_JSON`, both lane operator IDs, fingerprints, and base64 public keys;
- `production-signing` secret: `AGENTPASS_SIGNER_KEY_VERSIONS_JSON`, in addition to the documented signing/notarization credentials;
- Apple Silicon environment secret: `AGENTPASS_P0C_APPLE_SILICON_OPERATOR_PRIVATE_KEY_BASE64`;
- Intel T2 environment secret: `AGENTPASS_P0C_INTEL_T2_OPERATOR_PRIVATE_KEY_BASE64`;
- `production-release` environment protection: required reviewers and restricted protected-main deployment.

The three manual workflows run in this order:

1. Run `Release candidate` with an existing signed release tag. Record its workflow run ID.
2. Run `P0-C hardware qualification` from protected `main` with that release run ID and the fixed artifact name `notarized-release-candidate`. Record the successful qualification run ID.
3. Run `Promote qualified release` with both IDs. It validates the API provenance, canonical dispatch binding, signed reports, retained aggregate summary, notarized PKG, and annotated tag before creating the public release.

The promotion workflow also publishes both signed reports, operator public keys, the approved policy, aggregate summary, per-lane evidence archives, and `P0C-SHA256SUMS`. A failed upload leaves only a draft release; it is never switched to public state.
