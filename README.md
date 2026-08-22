# AgentPass

The current production execution order and exit gates are in [docs/V1_EXECUTION_PLAN.md](docs/V1_EXECUTION_PLAN.md). The implementation-level security and product design is documented in [docs/DETAILED_DESIGN.md](docs/DETAILED_DESIGN.md); the concise component contract is in [docs/AGENT_PLATFORM_ARCHITECTURE.md](docs/AGENT_PLATFORM_ARCHITECTURE.md). The active process-bound implementation sequence is in [docs/PROCESS_BOUND_AGENT_IMPLEMENTATION_PLAN.md](docs/PROCESS_BOUND_AGENT_IMPLEMENTATION_PLAN.md), and the signed-macOS qualification status/runbook is in [docs/AGENT_SESSION_N3E_PHYSICAL_QUALIFICATION.md](docs/AGENT_SESSION_N3E_PHYSICAL_QUALIFICATION.md). The current operator packet is indexed in [docs/runbooks/README.md](docs/runbooks/README.md).

AgentPass is an OSS policy broker for coding-agent operations. It keeps signing keys in the platform security boundary and gives an agent permission to perform a narrowly scoped operation, rather than handing the agent a secret.

> Early alpha: macOS + Git SSH signing. Review the threat model before using production keys.

## Start here

AgentPass is for people who want Claude Code, Cursor, or another coding agent
to make policy-approved Git commits while they are away from the keyboard.
The agent receives a short-lived, repository-scoped capability; it never
receives the private signing key. Git still performs the commit, and the
`agentpass-git-sign` helper asks the local broker to sign only after the
repository, branch, remote, operation, session, and revocation state pass
their checks.

The boundary is:

- **The key stays on the Mac.** The native production path uses
  non-exportable Secure Enclave-backed keys and a signed native service.
- **The agent gets permission, not key material.** Permissions are short-lived,
  Agent-bound, and limited by policy.
- **The Console is for human control.** Organization/device enrollment,
  WebAuthn approval, audit inspection, scope reduction, and revocation happen
  through the Console or its CLI-guided browser flow.
- **A green local test is not a production qualification.** Real PostgreSQL,
  KMS, WebAuthn, protected runners, and physical macOS evidence are separate
  release gates.

If you are evaluating the repository, use the local setup below. If you are
operating a release, use [Protected qualification for release operators](#protected-qualification-for-release-operators)
and do not treat the evaluation path as production approval.

## Why

Password managers are designed around human approval. Coding agents need unattended execution, but a plaintext key gives an untrusted process too much power. AgentPass starts with Git commit signing: the private key remains in macOS Secure Enclave-backed infrastructure, while AgentPass applies repository, branch, and remote policy before delegating to `ssh-keygen`.

## Quick start

```sh
npm install
npm link
agentpass init
agentpass check
agentpass doctor
```

### Production macOS installation

The production channel is a Developer ID-signed and notarized PKG. AgentPass verifies the signed release manifest, pinned release key, Apple Team ID, stapled notarization ticket, Gatekeeper assessment, package payload, and nested code signatures before installation. Verification is a dry run unless `--execute` is explicit:

The values below are release-metadata placeholders, not values to invent. Get
the manifest, public key, pinned fingerprint, and Team ID from the same release
packet. Never put a private key, credential, enrollment invitation, or bearer
token into this document, a repository, a URL, or an environment variable.

```sh
agentpass install \
  --manifest "$PWD/AgentPass-v0.18.0.release-manifest.json" \
  --signature "$PWD/AgentPass-v0.18.0.release-manifest.sig" \
  --public-key "$PWD/release-manifest.public.pem" \
  --fingerprint 'SHA256:PINNED_RELEASE_KEY_FINGERPRINT' \
  --team-id 'APPLETEAM1'

sudo agentpass install \
  --manifest "$PWD/AgentPass-v0.18.0.release-manifest.json" \
  --signature "$PWD/AgentPass-v0.18.0.release-manifest.sig" \
  --public-key "$PWD/release-manifest.public.pem" \
  --fingerprint 'SHA256:PINNED_RELEASE_KEY_FINGERPRINT' \
  --team-id 'APPLETEAM1' \
  --execute
```

Service registration remains a separate, visible macOS approval step. Package installation never overwrites protected AgentPass state.

Opening `/Applications/AgentPass.app` now shows a native, read-only onboarding window. It displays the validated setup state, progress, the next canonical CLI command, and blocked-state remediation. The app can refresh status or copy the command, but it cannot execute setup, enroll a key, register a service, or mutate security state. Those operations remain explicit CLI steps until the privileged UI action protocol is implemented and qualified.

After the PKG is installed and the local policy has been initialized, preview the native bridge and Claude Code/Cursor project integration, then apply it as the interactive user:

```sh
agentpass setup --client claude-code --project "$PWD" --team-id 'APPLETEAM1'
agentpass setup --client claude-code --project "$PWD" --team-id 'APPLETEAM1' --execute
agentpass setup status
# Repeat one durable step at a time. Preview is read-only.
agentpass setup continue
agentpass setup continue --execute
# Recommended browser-assisted command.
agentpass setup continue --execute --browser --console-url https://console.example --enrollment-url https://api.example/v1
# Current explicit recovery path: copy once, then pipe the invitation through stdin.
pbpaste | agentpass setup continue --execute \
  --enrollment-url 'https://api.example/v1' \
  --enrollment-stdin
agentpass doctor --client claude-code --project "$PWD" --team-id 'APPLETEAM1'
```

For the manual Console bridge, prepare the public preflight DTO first and
copy it directly into Console; it is not the one-time enrollment invitation:

```sh
agentpass setup prepare --json | pbcopy
```

Console then issues the short-lived v2 invitation after the organization
approves the device name and WebAuthn operation. Do not save either the DTO or
the invitation in a repository, URL, environment variable, or shell history.

`setup status` reads the crash-resumable setup journal and reports the next durable action; the macOS onboarding window renders this same fail-closed status contract. `setup continue --execute` advances exactly one verified journal state. It registers the Service Management daemon and then uses the signed, root-only native bootstrap primitives to stage and activate the generation-1 approval, Git-signing, and audit keys. At device enrollment, the recommended browser path accepts the short-lived credential through a one-consume in-memory handoff; the recovery path accepts it only through bounded stdin. A fixed Secure Enclave P-256 key signs the exact v2 enrollment body digest, credential digest, challenge nonce, and candidate-binding digest. The credential is never written to config, logs, results, or journal evidence.

The browser-assisted command above is the recommended non-engineer path. `--console-url` and `--enrollment-url` are independently pinned: the first is the exact HTTPS Console origin that opens in the browser, and the second is the exact Cloud API `/v1` origin used for enrollment. Neither URL is inferred from the other. The URL fragment contains only a short-lived loopback correlation URL. The handoff nonce remains ephemeral in process memory and Console memory, and the invitation remains memory-only on both sides. No nonce or invitation is placed in a URL, browser storage, argv, environment variable, log, or setup journal.

For a non-engineer, the intended flow is: install the signed PKG, run the browser-assisted command with the two organization-approved URLs, sign in to Console, choose the device name, approve the WebAuthn prompt, and wait for the CLI to finish. If local browser delivery fails, copy the displayed invitation once and use the explicit `pbpaste`/stdin recovery fallback; do not save it in a file, shell history, argv, or an environment variable. If the browser does not open, the handoff expires, or the Console origin is rejected, verify the separately pinned URLs and start a fresh command. Never reuse an expired fragment, nonce, or invitation.

The setup journal is intentionally resumable and fail-closed. The normal
sequence is:

```sh
agentpass setup status
agentpass setup continue --execute
# At the device-enrollment step, use the browser command shown above.
agentpass setup continue --execute --browser \
  --console-url 'https://console.example' \
  --enrollment-url 'https://api.example/v1'
agentpass setup status
agentpass doctor --client claude-code --project "$PWD" --team-id 'APPLETEAM1'
```

Run `setup continue --execute` once per displayed durable step. Run it as the
signed-in interactive user, not with `sudo`; it may ask for macOS System
Settings approval. If a step fails, inspect `setup status` and resume from the
reported state instead of deleting the journal or repeating enrollment.

### Audit Exports in Console

The Console now includes a Japanese **監査エクスポート** screen. Owner and
Admin can create an immutable export; Owner, Admin, and Auditor can retrieve,
verify, and download one. Each action uses operation- and export-bound passkey
reauthentication. Downloads are bounded canonical JSON attachments, and the
browser revokes the temporary Blob URL immediately after use. Export payloads
are not written to browser storage, URLs, analytics, or logs.

Choose `production` or `staging`, select the `admin`, `device`, or
`cloud_agent` chain, then create a new export or enter an existing export ID.
The verification view independently reports payload digest, cumulative root,
audit-anchor signature, and historical public-key checks. If creation returns
an uncertain response, keep the generated export ID and use **再認証して取得**;
do not create another export merely because the response was lost.

Production installs also enforce release freshness before invoking the macOS
installer: a newer signed release may upgrade, an exact same release may be
repaired, and older or same-version/different-artifact packages are rejected.
Rollback is not an implicit installer option and requires a separately audited
authorization flow.

`enrollment.json` may be the exact canonical response returned by `POST /v1/organizations/{organization_id}/device-enrollments`, or its nested `enrollment` object. Setup accepts only the complete v2 document: it binds the protocol version, tenant, enrollment/device IDs, release candidate, Secure Enclave P-256 key fingerprint, challenge, expiry, endpoint, and public possession-receipt verification key. Do not paste its one-time credential into argv, an environment variable, URL, repository, or shell history. Enrollment issuance requires an Owner/Admin session plus operation-bound recent WebAuthn authorization.

Native bootstrap requires the root-owned `/Library/Application Support/AgentPass/native-service.json` and policy from the release configuration. Device enrollment atomically provisions the pinned ControlBundle v2 trust into that root-owned configuration, restarts the service, and requires an authenticated first refresh before its journal state advances. The final editor check is read-only and setup completes only after `git verify-commit` accepts the current full commit hash. A hosted Control Plane and physical-Mac release qualification remain separate work.

To remove AgentPass while preserving both the root-owned audit/lifecycle state and non-exportable keys, first preview and remove current-user integrations, then perform the separately elevated system phase:

```sh
agentpass uninstall --project "$PWD"
agentpass uninstall --project "$PWD" --execute
sudo agentpass uninstall --system --team-id 'APPLETEAM1' --execute
```

The user phase removes only byte-matched AgentPass MCP members and the legacy user LaunchAgent. Its final user-writable file move uses the signed `RENAME_EXCL` helper, so a concurrent writer is never overwritten or unlinked. The system phase requires the pinned Apple Team ID, unregisters the signed SMAppService daemon, removes `/Applications/AgentPass.app` through a crash-resumable identity journal, and forgets the PKG receipt. Neither phase deletes `~/.agentpass`, `/Library/Application Support/AgentPass`, Keychain identities, Secure Enclave keys, or audit history.

Upgrading from AgentPass 0.5 or earlier creates the v4 audit identity and, when needed, a signed agent identity:

```sh
agentpass migrate
agentpass broker install --force
```

The v0.6 broker refuses configuration versions below 4. Migration intentionally invalidates legacy single-session storage, so issue a new Agent-bound session afterward.

Create the non-exportable Secure Enclave-backed signing key on macOS:

```sh
agentpass setup-macos              # review commands
agentpass setup-macos --execute    # run them
agentpass broker install
agentpass broker ping
```

Install a pre-push hook after explicitly allowing push operations in `config.json`. The default policy intentionally does not allow push:

```json
{ "operations": ["git.commit.sign", "git.push", "git.tag.push"] }
```

```sh
agentpass install-hook
```

The hook evaluates every ref received from Git. Branches use `branches.allow`/`branches.deny`; tags use `tags.allow`/`tags.deny`. A revoked AgentPass state or a required expired session blocks the push.

Signing is session-gated by default. Before an unattended run, issue a short-lived session token:

```sh
export AGENTPASS_SESSION="$(agentpass session start 900)"
```

Sessions are bound to the selected Agent ID. For a non-default identity, use `agentpass session start 900 --agent AGENT_ID` and export the same ID as `AGENTPASS_AGENT_ID` when invoking Git. Multiple agents can hold concurrent sessions. Tokens are never written to the audit log; only their hashes are stored locally. Set `"session.required"` to `false` only if another control supplies the authorization boundary.

Configure Git to use the wrapper:

```sh
git config --local gpg.format ssh
git config --local user.signingkey ~/.agentpass/keys/id_git_sign.pub
git config --local gpg.ssh.program "$(command -v agentpass-git-sign)"
git config --local commit.gpgsign true
```

`agentpass-git-sign` never invokes `ssh-keygen` directly. It sends the payload to the Unix socket broker. The broker independently resolves the repository root, branch, and origin; replaces the caller-provided key with the configured key; filters SSH signing arguments; evaluates policy and session state; records the payload hash; and only then signs. If the broker is unavailable, signing fails closed.

## Claude Code and Cursor

AgentPass includes a local MCP server for status, policy checks, setup guidance, and a bounded redacted audit tail. It deliberately does not expose a general-purpose signing tool: commits continue through Git and `agentpass-git-sign`.

### Configure a project

The supported user-facing integration is project-scoped MCP configuration. The
preview commands do not write files; add `--install` only after reviewing the
JSON. Existing unrelated MCP servers are preserved.

```sh
# Claude Code
agentpass integrate claude-code --project "$PWD"
agentpass integrate claude-code --install --project "$PWD"

# Cursor
agentpass integrate cursor --project "$PWD"
agentpass integrate cursor --install --project "$PWD"
```

The equivalent native onboarding command also verifies the pinned macOS
application and prepares the setup journal:

```sh
agentpass setup --client claude-code --project "$PWD" --team-id 'APPLETEAM1'
agentpass setup --client claude-code --project "$PWD" --team-id 'APPLETEAM1' --execute
```

Use `--client cursor` for Cursor. Start Claude Code or Cursor from its normal
launcher after the integration is installed. The AgentPass MCP surface is
limited to status, policy checks, setup guidance, and a redacted audit tail;
the agent does not receive a signing tool or a private key. When it runs
`git commit`, Git invokes `agentpass-git-sign` and the broker enforces the
current policy.

Before an unattended run, create a short-lived session for the selected Agent
identity. The command exports only the returned token to the child process;
the token itself must never be copied into documentation or committed files:

```sh
export AGENTPASS_SESSION="$(agentpass session start 900 --agent AGENT_ID)"
export AGENTPASS_AGENT_ID='AGENT_ID'
```

Then configure Git once in the repository:

```sh
git config --local gpg.format ssh
git config --local user.signingkey ~/.agentpass/keys/id_git_sign.pub
git config --local gpg.ssh.program "$(command -v agentpass-git-sign)"
git config --local commit.gpgsign true
```

The adapter launch plans are intentionally closed: they accept only an
absolute project directory and a bounded TTL, and reject key/session/path
substitutions. The lifecycle command is available only after the signed native
handoff exists and otherwise fails closed:

```sh
agentpass launch --agent claude-code --project "$PWD" --ttl 600
agentpass launch --agent cursor --project "$PWD" --ttl 600
```

On a non-qualified Linux or unsigned macOS checkout, a lifecycle failure is
expected and remains `not_proven`; it is not permission to bypass the native
boundary. The adapter contract can be inspected without secrets with:

```sh
node adapters/claude-code/bin/agentpass-claude-code.mjs plan "$PWD"
node adapters/cursor/bin/agentpass-cursor.mjs plan "$PWD"
```

### Closing an unattended Agent session

The signed native Host control path can close a running Agent Host session
without giving the agent a key or a reusable bearer token:

```sh
agentpass close \
  --session-id 'SESSION_UUID' \
  --reason client_shutdown
```

The command uses the dedicated `dev.agentpass.agent-host-control` Mach service
and the signed Native Client principal. If the response is lost, retry with
the same operation ID printed in the timeout message:

```sh
agentpass close \
  --session-id 'SESSION_UUID' \
  --operation-id 'OPERATION_UUID' \
  --reason client_shutdown
```

This route is implemented and covered by focused contract tests. A physical
Developer ID-signed install, launchd registration, real cross-process NSXPC
call, and production macOS qualification are separate release gates and are
not implied by local tests.

### Starting a bounded Agent lifecycle

After Console/setup has created the one-time local handoff, the adapter accepts
only the project directory and a short TTL. The authority is inherited through
the private FD3 handoff; never put it in argv, an environment variable, a URL,
or a file:

```sh
agentpass launch --agent claude-code --project "$PWD" --ttl 600
agentpass launch --agent cursor --project "$PWD" --ttl 600
```

The adapter invokes only the fixed, signed Native Host. On Linux, an unsigned
build, a missing handoff, an untrusted Host, or a missing physical macOS
installation, the command fails closed. A successful local contract test does
not by itself prove a Developer ID-signed launchd/XPC execution.

Preview a project-scoped integration, then install it explicitly:

```sh
agentpass integrate claude-code
agentpass integrate claude-code --install

agentpass integrate cursor
agentpass integrate cursor --install
```

Preview removal of only the exact AgentPass-owned MCP entry, then apply it. Other MCP servers and settings are preserved, and native keys/audit state are not touched:

```sh
agentpass integrate claude-code --remove --project "$PWD"
agentpass integrate claude-code --remove --execute --project "$PWD"
```

Claude Code uses `.mcp.json`; Cursor uses `.cursor/mcp.json`. AgentPass preserves unrelated MCP servers in either file and refuses invalid or unsafe existing configuration. Once connected, the available MCP tools are `agentpass_status`, `agentpass_check`, `agentpass_setup`, and `agentpass_audit_tail`.

Each request is signed by an enrolled Ed25519 agent identity, timestamped, and assigned a random nonce. The broker verifies the signature and rejects unknown, expired, or replayed requests before policy evaluation.

Manage agent identities without editing `config.json` directly:

```sh
agentpass agent list
agentpass agent add cursor-nightly
agentpass agent set-default AGENT_ID
agentpass agent scope AGENT_ID \
  --operation git.commit.sign \
  --repository /absolute/path/to/repo \
  --branch 'feature/*' \
  --remote 'git@github.com:owner/repo.git'
agentpass agent rotate AGENT_ID
agentpass agent revoke AGENT_ID --confirm REVOKE
agentpass broker install --force   # trust the new configuration
```

New agents initially receive a snapshot of the global policy. Their explicit scope can only narrow effective access because every request must pass both global policy and Agent scope. Configuration mutation intentionally makes the running broker fail closed. Revoked and rotated private-key files are moved under `~/.agentpass/agents/revoked/` for operator recovery, but are no longer enrolled.

The Secure Enclave-backed key can be created using the macOS technique documented by [mizdra](https://www.mizdra.net/entry/2026/08/07/101542), for example with `sc_auth create-ctk-identity`, then referenced in `.agentpass/config.json`.

Inspect and control the local policy:

```sh
agentpass status
agentpass audit --verify
agentpass audit checkpoint > checkpoint.json
agentpass audit public-key > agentpass-audit.pub
agentpass revoke    # local and native mode: one safe emergency-stop entry point
agentpass restore --confirm RESTORE
# Native mode is dispatched through the protected broker automatically.
```

Copy `checkpoint.json` to an append-only or remote system. The public key verifies who signed a checkpoint; retaining a checkpoint record or its `checkpoint_hash` outside the host is what detects later local history replacement.

AgentPass also includes a remote anchor that verifies local Ed25519 and native Secure Enclave P-256 checkpoint signatures and returns append-only, signed receipts:

```sh
# Separately administered anchor host; publish it through an HTTPS reverse proxy.
agentpass-anchor init /var/lib/agentpass-anchor
agentpass-anchor enroll /var/lib/agentpass-anchor build-mac-01 ./agentpass-audit.pub
agentpass-anchor serve /var/lib/agentpass-anchor

# AgentPass host; pin the anchor key through an authenticated channel.
agentpass audit anchor trust \
  --url https://audit-anchor.example.com/ \
  --tenant build-mac-01 \
  --key ./anchor-public.pem
agentpass audit anchor push
agentpass audit anchor status
```

Only signed checkpoint metadata leaves the host; audit events and repository data remain local. Failed pushes are retained and safely retried. See [docs/AUDIT_ANCHOR.md](docs/AUDIT_ANCHOR.md) for deployment, protocol, and residual risks.

## Offline-signed remote revocation

Generate the control key on an offline administration host and retain `control-private.pem` there:

```sh
agentpass control keygen ./agentpass-control-key
agentpass control sign \
  --key ./agentpass-control-key/control-private.pem \
  --sequence 1 \
  --expires 2026-08-12T00:00:00Z \
  --revoke-agent AGENT_ID > control.bundle.json
```

Use `--global-revoke` instead of `--revoke-agent` for an emergency stop. Bundles have a maximum seven-day lifetime and sequence numbers must increase whenever content changes.

On each AgentPass host, pin only the public key and install the initial bundle:

```sh
agentpass control trust ./control-public.pem \
  --url https://control.example.com/agentpass/control.bundle.json \
  --refresh 60
agentpass control apply ./control.bundle.json
agentpass broker install --force
agentpass control status
```

The broker periodically fetches the static JSON bundle over HTTPS. Missing, expired, malformed, incorrectly signed, rolled-back, or same-sequence conflicting bundles fail closed. See [docs/REMOTE_CONTROL.md](docs/REMOTE_CONTROL.md) for the protocol and operational model.

In native mode, install the public key in the root-owned service policy and the initial bundle at `control_state_path`; user-side `control trust` is intentionally refused. Configure `control_url` and `control_refresh_seconds` in the root-owned native service configuration for automatic bounded refresh. `agentpass control fetch` and direct apply remain available for operator recovery. The native service—not the user configuration—verifies trust and persists the sequence.

## Security model

AgentPass protects against copying the private key out of the device and limits the allowed signing context. It does not protect against a fully compromised host process that is able to invoke an allowed signing operation. The policy boundary is therefore an authorization and audit layer, not a replacement for macOS sandboxing or endpoint security.

## Native macOS boundary

Version 0.18 includes a Swift/XPC native broker and a buildable macOS app host. It creates separate non-exportable P-256 signing, audit-checkpoint, human-presence approval, and Cloud device-authentication keys in Secure Enclave, emits OpenSSH-compatible SSHSIG signatures internally, authenticates the signed XPC client, and repeats Agent identity, capability, session, ControlBundle v2, replay, scope, Git context, tree, and parent validation against root-owned policy and state inside the service. The service automatically refreshes device-authenticated signed bundles with bounded jitter/backoff, can submit P-256 audit checkpoints to a root-configured HTTPS anchor, and rotates full audit logs into protected hash-linked segments without resetting their global chain. It verifies Ed25519 bundles/receipts and persists their chains under protected ancestry before acknowledging success.

```sh
npm run test:native
npm run test:native-app
native/macos/scripts/build-app.sh --adhoc --force
```

Protected native sessions require human presence only when `agentpass session start` is called; policy-compliant commits remain unattended until the Agent-bound TTL expires. The service retains token hashes only in memory, so restart and `agentpass native revoke-sessions` invalidate them. Native mode verifies, atomically persists, and periodically refreshes signed control bundles under root-owned configuration and ancestry; `agentpass control apply`, `fetch`, and `status` are also routed through XPC. The build pipeline assembles the required `Contents/Library/LaunchDaemons` layout, signs every nested executable, supports universal builds and optional notarization, and exposes `SMAppService` register/status/unregister commands. No Developer ID-signed release artifact is published yet, and ad-hoc builds do not activate the production identity boundary. See [docs/NATIVE_BROKER.md](docs/NATIVE_BROKER.md) for setup and remaining gaps.

## Protected qualification for release operators

This section is an operator map, not a way to qualify a release from a laptop.
The protected workflows run against the exact candidate source commit, source
tree, release artifact digest, CI run/attempt, and job IDs. They must use
protected self-hosted runners, real service identities, and independently
retained evidence. Never replace an unavailable lane with a fixture, local
test, `not_run`, or `not_proven` record.

1. Freeze the candidate. Record the exact source commit/tree, release artifact
   SHA-256, canonical CI run ID, run attempt, and job tuple. A rerun changes
   the attempt and requires new evidence.
2. Dispatch [external-qualification-runners.yml](.github/workflows/external-qualification-runners.yml)
   from the protected environment. Before PostgreSQL commands, the runner
   must run `npm run postgres:require-live-env`; then it may run
   `npm run qualification:postgres-c3:external`. The preflight requires
   distinct non-loopback TLS `verify-full` endpoints, a protected CA file,
   disposable targets, and candidate/run/artifact bindings.
3. Run the provider and browser lanes through their external wrappers:

   ```sh
   npm run qualification:kms:external
   npm run qualification:webauthn:external
   npm run qualification:external -- evidence.json binding.json > verified-evidence.json
   ```

   These commands require protected environment variables for runner identity,
   source/tree/artifact/run/attempt/job bindings, deployment or environment
   digest, adapter path plus adapter SHA-256, and pinned trust maps. Values and
   credentials belong in the protected environment, never in this repository.
4. Run both physical macOS lanes through
   [macos-hardware-qualification.yml](.github/workflows/macos-hardware-qualification.yml)
   and retain separate Apple Silicon and Intel/T2 evidence. `npm run
   test:native` and `npm run test:native-xpc-contract` are local contracts;
   they do not prove Secure Enclave, launchd, Developer ID, or notarization.
5. Assemble the signed, candidate-bound evidence packet and run the final gate:

   ```sh
   npm run release:readiness -- \
     /secure/evidence/production-readiness-gate.json
   ```

   The evidence path is passed after `--`; a valid packet prints the safe
   production-ready summary and exits `0`. An invalid, incomplete, stale, or
   otherwise unproven packet prints a redacted `status: "not_proven"` result to
   stderr and exits nonzero.

   Promotion also requires the signed evidence index, operations readiness,
   staging readiness/rollback, independent security review, and exact
   workflow run/artifact binding. Follow [docs/runbooks/RELEASE_PROMOTION_RUNBOOK.md](docs/runbooks/RELEASE_PROMOTION_RUNBOOK.md)
   for the complete handoff.

### What `not_proven` means

`not_proven` is a deliberate safety state, not a successful test result and
not a statement that the implementation is broken. It means the evidence
needed for the requested claim is missing, unavailable, locally generated,
stale, substituted, or not independently bound to the exact candidate. The
`npm run release:readiness -- <evidence-path>` exits nonzero and emits a
redacted `{"status":"not_proven","reason":"<reason>"}` object on stderr;
promotion must stop. Green adapter tests can prove
the adapter contract locally, but only a protected external run can prove a
real KMS call; a macOS contract test can prove source-level invariants, but
only the physical signed/notarized lane can prove the release boundary. Keep
the state as `not_proven`, fix the environment or collect the missing evidence,
and rerun the complete lane.

## Current scope and roadmap

- [x] repository, branch, remote, and operation policy
- [x] tamper-evident local audit chain
- [x] emergency local revocation switch
- [x] prerequisite diagnostics
- [x] short-lived session token with generation-based revocation
- [x] fixed production config location (no environment override)
- [x] configured signing-key enforcement
- [x] signed-payload hash in audit events
- [x] Unix socket signing broker with no local fallback
- [x] broker-side Git context and signing-argument validation
- [x] broker config snapshot with mutation fail-closed
- [x] macOS LaunchAgent installation
- [x] Secure Enclave setup command with dry-run default
- [x] optional pre-push policy hook
- [x] separate branch and tag push rules
- [x] GitHub Actions CI test workflow
- [x] Swift/XPC broker core with Secure Enclave SSHSIG and service-side policy validation
- [x] root-owned native hash-chain audit with separate Secure Enclave checkpoint key
- [x] human-approved protected native sessions with Agent binding and immediate revocation
- [x] signed/notarizable native app build and Service Management registrar
- [ ] published notarized universal native release artifact
- [x] protected native remote-control state and monotonic sequence enforcement
- [x] service-owned bounded native HTTPS control refresh
- [x] bounded native refresh jitter, exponential retry, and retry telemetry
- [x] per-agent Ed25519 request identity with replay protection
- [x] agent enrollment, selection, revocation, and key rotation
- [x] per-agent operation/repository/branch/remote scopes
- [x] concurrent short-lived sessions bound to Agent IDs
- [x] signed and chained audit checkpoints
- [x] merge commit parent validation against `HEAD` and `MERGE_HEAD`
- [ ] FIDO2/YubiKey and TPM backends
- [ ] 1Password, Vault, and Infisical broker adapters
- [x] offline-signed remote Agent and global revocation
- [x] bounded HTTPS control refresh with sequence rollback detection
- [x] remote checkpoint anchoring with signed, chained receipts
- [x] service-owned remote anchoring for native P-256 checkpoints
- [x] protected native audit rotation with checkpoint and hash-chain continuity

See [THREAT_MODEL.md](THREAT_MODEL.md) for the exact security boundary and remaining same-user limitations.

The authoritative product gates and production definition of done are maintained in [docs/V1_EXECUTION_PLAN.md](docs/V1_EXECUTION_PLAN.md). The current source checkpoint, ticket dependencies, parallel lanes, acceptance evidence, and effort bands are maintained in [docs/IMPLEMENTATION_PLAN_2026-08-16.md](docs/IMPLEMENTATION_PLAN_2026-08-16.md). [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) retains the earlier milestone breakdown.

For the current production-readiness decision, use the
[2026-08-20 audit snapshot](docs/PRODUCTION_READINESS_AUDIT_2026-08-20.md).
It separates implementation and focused-test evidence from protected external
qualification. The [incident and revoke runbook](docs/INCIDENT_AND_REVOKE_RUNBOOK.md)
is the operational procedure for emergency stop, device/agent/session revoke,
uncertain signing, and exact-candidate rollback.

Promotion remains `STOP` until the external gates in the audit and [release
promotion runbook](docs/runbooks/RELEASE_PROMOTION_RUNBOOK.md) are evidenced.
Local/static tests, `not_run` reports, ad-hoc signatures, and documentation
claims never substitute for protected qualification.

## License

MIT
