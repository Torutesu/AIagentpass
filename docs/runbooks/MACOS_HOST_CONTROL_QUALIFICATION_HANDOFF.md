# Physical macOS Host-control qualification handoff

This runbook is the operator handoff for the physical macOS qualification of
the installed AgentPass Host and its separate control client. It is an
execution and evidence guide, not a substitute for the protected workflow or
the independent report verifier.

The qualification target is one exact, signed and notarized PKG on one native
physical Mac. The same release candidate must be qualified independently on
the Apple-silicon and Intel/T2 lanes before it can be promoted. A local build,
ad-hoc signature, VM, Rosetta process, synthetic NSXPC test, or report template
does not satisfy this handoff.

## Stop conditions and evidence states

Stop immediately when any input is missing, changed, unsigned, unverifiable,
or not bound to the candidate. Do not edit a report to turn a failed or
incomplete observation into `passed`.

Use these states precisely:

| State | Meaning |
| --- | --- |
| `implemented` | The source and contract exist. |
| `locally-qualified` | Deterministic local/static checks passed. |
| `source-bound-ci` | Protected CI checked the exact source and artifact bindings. |
| `externally-qualified` | An approved physical Mac produced a signed, independently verified report. |
| `not_proven` | The physical observation or its trusted evidence is absent. This blocks promotion. |

The current checkout contains the contract and harness changes, but this
handoff does not claim that a Developer ID package has been installed or that
the real launchd/NSXPC sequence has passed. Until the protected run produces
and independently verifies the report, the items in the final section remain
`not_proven`.

## Required inputs

Prepare the following on the protected lane, keeping private keys and tokens
out of the runner evidence directory:

1. The exact notarized universal PKG named by the signed release manifest.
2. The release manifest, detached signature, public key, pinned public-key
   fingerprint, release attestation, and the expected 10-character Apple Team
   ID.
3. The full 40-character lowercase `source_commit` and `source_tree` recorded
   by that manifest. Never substitute the current checkout SHA or a branch
   name.
4. A root-owned, non-group/world-writable, ACL-free probe staging directory
   and three separately reviewed protected probe executables.
5. A native physical Mac: Apple silicon for the arm64 lane or Intel/T2 for the
   x86_64 lane. The runner must reject VMs, Rosetta, and translated execution.
6. The lane's protected runner attestation and approved operator key. Retain
   only the detached signature, public key, and evidence digests; never retain
   the operator private key in the report or artifact archive.

The signed product identity is a `Developer ID Installer: ... (TEAMID)`
identity. The installed app, Host, native client, and protected probes must
also be checked against their expected `Developer ID Application: ...
(TEAMID)` identities. The exact certificate names are supplied by the release
owner; do not replace them with an ad-hoc or “Apple Development” identity.

## Protected probe executable contract

The macOS qualification workflow does not execute qualification code from the
candidate checkout. The protected runner must install the fixed toolchain at
`/opt/agentpass/macos/qualification-tool` with a root-owned, non-writable
`manifest.json`, `run-hardware-qualification.sh`,
`hardware-qualification.mjs`, `hardware-qualification.schema.json`,
`nsxpc-host-control-probe.mjs`, and `verify-installed-toolchain.mjs`. The
manifest must list every file with its SHA-256, include the entrypoint and
verifier names, and its complete digest must be stored as the
environment-scoped `AGENTPASS_MACOS_QUALIFICATION_TOOL_MANIFEST_FINGERPRINT`
and `AGENTPASS_MACOS_QUALIFICATION_TOOL_MANIFEST_SHA256` values. The manifest
must also have a detached Ed25519 `manifest.sig` and root-owned `manifest.pub`.
Qualification stops before any probe when the fixed inventory or digest does
not match. Provisioning this directory is a protected-runner operation; it is
not performed by the candidate workflow.

The qualification runner receives these repository variables. Each value must
be an absolute path to the reviewed executable installed on the protected
runner:

```text
AGENTPASS_LAUNCHD_HOST_CHILD_PROBE
AGENTPASS_NSXPC_PROBE
AGENTPASS_CRASH_RESTART_PROBE
AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR
```

The corresponding exact SHA-256 variables are mandatory:

```text
AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256
AGENTPASS_NSXPC_PROBE_SHA256
AGENTPASS_CRASH_RESTART_PROBE_SHA256
```

Record the expected Developer ID Application identity for each probe in the
matching `*_SIGNING_IDENTITY` variable. This is mandatory for v2 qualification;
the workflow and shell entrypoint reject an empty value. An absent, ad-hoc,
Apple Development, or wrong-Team-ID identity is a stop. The signed runner
attestation `runner_id` must also match the actual GitHub `runner.name` passed
to the lane.

Every probe and every ancestor directory must be:

- a regular file or directory, never a symlink;
- owned by `root`;
- non-group/world-writable;
- free of ACL entries; and
- immutable for the duration of the run.

The runner snapshots the executable before execution and after execution. A
changed inode, digest, owner, mode, link count, or protected ancestry fails
closed. The probe staging directory must already exist and must satisfy the
same ownership, mode, link, and ACL constraints.

Before dispatch, the operator should record (without copying secrets):

```sh
stat -f '%Su %Lp %N' /absolute/path/to/launchd-probe
stat -f '%Su %Lp %N' /absolute/path/to/nsxpc-probe
stat -f '%Su %Lp %N' /absolute/path/to/crash-restart-probe
shasum -a 256 /absolute/path/to/launchd-probe
shasum -a 256 /absolute/path/to/nsxpc-probe
shasum -a 256 /absolute/path/to/crash-restart-probe
codesign --verify --strict --verbose=2 /absolute/path/to/nsxpc-probe
codesign -dv --verbose=4 /absolute/path/to/nsxpc-probe 2>&1 | grep -E 'Identifier=|TeamIdentifier=|Authority='
```

Repeat the signature check for all three probes. Compare the observed SHA and
identity with the protected variables. Do not paste raw certificate output or
probe stdout into a ticket; retain the bounded hashes and the redacted
identity fields in the evidence record.

## Install and establish the real launchd boundary

The installed application must come from the exact manifest-bound PKG. Verify
the release candidate before installation with the documented release
verifier, then install that same byte sequence:

```sh
bash scripts/release/verify-macos-release.sh \
  /secure/candidate/release-manifest.json \
  /secure/candidate/release-manifest.sig \
  /secure/candidate/release-manifest.public.pem \
  SHA256:<pinned-release-key-fingerprint> <TEAMID>

sudo installer -pkg /secure/candidate/AgentPass-macos-universal.pkg -target /
```

Confirm that `/Applications/AgentPass.app` and its nested native executables
are the signed candidate and that their Team ID matches the manifest. Launch
the app from `/Applications`; do not run a copied bundle from a checkout.
Complete the required enrollment/onboarding flow, then register and inspect
the native service through the installed CLI:

```sh
agentpass native daemon-register
agentpass native daemon-status
agentpass setup status
```

If macOS asks for Login Items or Service Management approval, approve it in
the intended user session and repeat `daemon-status`. A successful installer
step alone is not proof that launchd has registered the service. The operator
must capture the redacted status showing the service enabled, then have the
launchd probe observe the real `dev.agentpass.native-service` job and the
Host/Child services:

```text
dev.agentpass.agent-host
dev.agentpass.agent-host-control
dev.agentpass.child-git
```

The launchd probe must report the Host and Child process identities, positive
PIDs, and identity match from the installed signed processes. Merely finding a
plist in the PKG or passing a static bundle test is insufficient.

## Host-control scenario: close from a separate process

The NSXPC probe must establish an authenticated Host connection and an
independent control-client process. The expected process identities are:

| Role | Bundle identifier | Required observation |
| --- | --- | --- |
| Host | `dev.agentpass.agent-host` | Signed installed Host, positive PID and start time. |
| Control client | `dev.agentpass.native-client` | Different signed process and positive PID/start time. |

The probe must first prove that the authorized client connects and that a
wrong identity is denied. It then creates or obtains one qualification session
and records the session UUID and one operation UUID. From the separate control
client process, invoke the installed CLI route:

```sh
agentpass close \
  --session-id <session-uuid> \
  --operation-id <operation-uuid> \
  --reason completed
```

The invocation must reach the dedicated
`dev.agentpass.agent-host-control` Mach service, not the Host management
endpoint and not a file descriptor or inherited bearer capability. The close
receipt must contain `status: "closed"`, the same `session_id`, the same
`operation_id`, and a positive `closed_at_ms`. Record the caller PID and target
Host PID and prove that they are distinct processes.

The operation UUID is part of the idempotency contract. If the first response
is lost, the operator must not generate a new UUID or blindly issue a second
close. Reconnect to the control service and retry with the exact same
`--operation-id`; the resulting receipt must converge to the already-closed
terminal state without a second close effect.

## Post-close signing denial

After the control client receives or reconciles the close receipt, ask the
original Host process to perform the signing operation for the closed session.
This must be a real post-close request over the installed Host/Child path, not
a local state assertion. The expected result is a rejected request with:

```json
{
  "session_id": "<same-session-uuid>",
  "attempted_after_close": true,
  "status": "rejected",
  "reason": "endpoint_closed"
}
```

The `attempted_by_pid` must be the original Host PID. A rejection from the
wrong process, a generic transport failure, or a pre-close denial does not
prove post-close revocation. The probe must also retain enough bounded
metadata to show that the Host and control client were separately signed
processes and that the close used the control Mach service.

## Response-loss retry acceptance criteria

The NSXPC probe must deliberately lose the first close response after the
service has accepted the operation, then:

1. observe the connection loss without treating the operation as unknown;
2. reconnect to the dedicated control Mach service;
3. retry with the exact original `session_id` and `operation_id`;
4. receive a `closed` receipt bound to those same IDs; and
5. prove `no_second_close_effect: true`, `terminal_state: "closed"`, and
   `converged: true`.

Do not accept a test that only retries with a new operation ID, assumes a
timeout means failure, or reports success from a mock registry. The report
must contain only the contract's bounded fields and hashes; no raw XPC
messages, credentials, audit tokens, or secret material may be retained.

## Evidence package and independent verification

For each architecture, retain the canonical report, detached operator
signature, operator public key, and redacted evidence directory. The report
must bind all of these to:

- the exact `source_commit` and `source_tree`;
- the signed release manifest and its digest;
- the exact PKG byte count and SHA-256;
- the Developer ID Installer identity and Team ID;
- the native physical machine and architecture;
- each protected probe path, observed SHA, expected SHA, and signing identity;
- the launchd, NSXPC, and crash/restart check results.

Verify a single report on macOS with:

```sh
node native/macos/Qualification/hardware-qualification.mjs --verify \
  /secure/evidence/agentpass-macos-arm64-qualification.json
```

The verifier must return `status: "verified"`. This proves that the evidence
is internally canonical, digest-bound, and complete; it does not by itself
prove that the evidence is genuine unless the report came from the protected
runner and the operator signature is independently trusted. The aggregate
release gate must independently verify both the Apple-silicon and Intel/T2
reports and require the same candidate digest, source binding, Team ID, and
approved operator policy.

## What remains `not_proven` until this handoff completes

Do not describe any of the following as production-qualified based only on
source tests, Swift builds, Node contract tests, a plist, or a local report:

- Developer ID Application/Installer chain validation for the exact candidate
  on the physical runner;
- notarization acceptance, stapled ticket validation, and Gatekeeper install
  assessment for the exact post-staple PKG;
- actual installation and Service Management/launchd registration of the
  candidate from `/Applications`;
- a real signed Host connection through `dev.agentpass.agent-host`;
- a real signed control-client close through
  `dev.agentpass.agent-host-control`;
- post-close signing denial from the original Host process;
- response-loss reconnect and same-operation retry convergence;
- crash/restart observation and state recovery on both hardware classes;
- independent operator signature verification and aggregate promotion evidence.

Until all required protected reports and the aggregate verifier pass,
qualification status is `not_proven` and release promotion must remain
blocked.
