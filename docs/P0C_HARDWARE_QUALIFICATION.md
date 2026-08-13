# P0-C physical Mac qualification runner

`scripts/release/run-p0c-qualification.mjs` is the execution contract for the physical Mac release gate. It creates an unsigned canonical hardware-qualification v2 report and private evidence files. It does not sign the report, notarize a package, or replace the release verifier.

## Production-only command

The CLI refuses every non-darwin host before it reads the requested files. It has no local, simulator, POSIX-model, or ad-hoc “qualification” mode:

```text
node scripts/release/run-p0c-qualification.mjs \
  --template /absolute/path/production-report-template.json \
  --output /absolute/path/qualification.json \
  --artifact /absolute/path/AgentPass-0.18.0-macos-universal.pkg \
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

The driver directory must contain exactly these 16 single-link, regular, non-group/world-writable executable basenames:

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

Each driver is started directly with no arguments. It must exit `0` and print one bounded JSON object to stdout:

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
