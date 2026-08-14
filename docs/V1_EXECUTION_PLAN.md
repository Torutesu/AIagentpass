# AgentPass v1 execution plan

Status: active

Baseline: `codex/agent-platform` after `d7a1dcd`

Updated: 2026-08-15

This is the authoritative forward plan for the first production release. The
older milestone documents remain useful design history; when priorities differ,
this document controls execution order.

## 1. v1 outcome

A user installs one signed and notarized macOS package, completes a browser-led
device enrollment, and lets Claude Code or Cursor create policy-bound signed Git
commits without repeated human prompts. The device private key stays
non-exportable in Secure Enclave. An Owner or Admin can inspect and immediately
revoke authority in the Console, and every decision is auditable.

The supported delivery shape is headless-first:

- a Developer ID-signed and notarized PKG is the security boundary;
- direct download and Homebrew install the same immutable PKG and verify the
  same release manifest;
- the Web Console owns human identity, organization, policy, enrollment,
  revocation, and audit workflows;
- the CLI and native broker own local preflight, Secure Enclave key creation,
  enrollment proof, editor wiring, status, and repair;
- a standalone menu-bar application is optional and is not a v1 dependency.

## 2. Current checkpoint

Implemented foundations include the frozen Core/OpenAPI/JSON Schema catalog,
forward-only PostgreSQL migrations, tenant-qualified repositories, organization
roles, short-lived Human sessions, WebAuthn recent authorization, Device API,
signed control bundles and ACKs, audit ingestion, emergency revocation,
threshold-owner recovery, resumable setup, v2 device-possession enrollment, and
durable hosted-signer lifecycle/idempotency composition.

The current integration slice closes five concrete gaps:

1. bound native Swift tests in CI with process-group teardown and stable,
   secret-free timeout diagnostics;
2. make Console enrollment issue and validate the canonical v2 invitation;
3. make headless setup accept only the exact v2 invitation, pin a
   credential-free HTTPS `/v1` endpoint, verify the possession receipt before
   installing control trust, and recover an ambiguous completion without
   replaying the enrollment POST.
4. derive a deterministic candidate identity from the exact product PKG digest,
   bind it into release manifest v4, and retain a root-owned, user-readable,
   immutable public installation receipt after signed release verification;
5. import the exact public setup preflight in Console and carry an issued
   invitation over a short-lived, origin-pinned, nonce-bound IPv4 loopback
   channel without browser persistence.

This checkpoint is not a production release. Real managed-key evidence,
physical-Mac qualification, signed/notarized distribution, deployed staging,
restore drills, and independent security review remain external gates.

## 3. Dependency graph

```text
D  Contract-correct enrollment + bounded CI
|\
| +--> E  One-command browser/headless onboarding ----+
|                                                   |
+----> F  Production KMS/HSM signer + PostgreSQL ----+--> H  Agent E2E
                                                     |
G  Signed/notarized PKG + physical Mac --------------+
                                                     |
                                                     +--> I  Staging and production
```

Protocol/schema, PostgreSQL migrations, native durable state, entitlements,
release identity, and evidence schemas each have one integration owner and are
changed serially. UI, signer providers, packaging tests, and documentation may
proceed in parallel after their shared contract is frozen.

## 4. Merge-sized work packages

### D — contract-correct enrollment and reliable CI

State: in progress.

Deliverables:

- accept one canonical invitation shape from Cloud to Console to CLI;
- bind `version`, proof version, tenant, enrollment/device IDs, release
  candidate, device-key fingerprint, challenge, expiry, endpoint, and public
  possession-receipt verification key;
- keep invitation credentials out of argv, environment, URL, browser durable
  storage, setup journal, config, logs, and diagnostics;
- expose `pending` and `enrolled` truth in Console without claiming that the
  browser verified the native possession receipt;
- terminate a hung Swift test process tree on deadline and preserve the real
  success/failure exit code.

Required evidence:

- unit negatives for unknown/missing fields, tenant/candidate/key/endpoint
  substitution, expiry, private-key input, malformed/oversized responses,
  definitive HTTP rejection, response loss, and POST non-replay;
- Console unit/lint/build, root contract/lint/test, native Swift tests, and P0-B
  live Cloud/Console/PostgreSQL/browser qualification;
- a new GitHub Actions run where every job reaches a terminal state.

Exit condition: the exact invitation emitted by Cloud is accepted through the
Console and CLI, a substituted invitation fails before authority changes, and
CI cannot hang indefinitely in native tests.

### E — one-command onboarding journey

Depends on D.

E1, local preflight:

- add `agentpass setup prepare --json` to verify the installed package and
  native identities, create or reuse the non-exportable P-256 enrollment key,
  and emit only public `candidate_id` and `device_key_fingerprint` handoff data;
- make candidate discovery authoritative from the installed signed release
  manifest; never ask a non-engineer to derive or type it;
- record resumable public state in the setup journal without credentials.

E2, browser handoff:

- open Console with a short-lived, non-secret correlation identifier only;
- have Console select the active compatible release candidate and consume the
  public key fingerprint from a local loopback handoff or copy/paste fallback;
- require operation-bound WebAuthn authorization before invitation issuance;
- return the one-time invitation directly to the waiting CLI over a
  same-device, origin-pinned, nonce-bound channel. Do not place it in a query
  string, browser persistence, analytics, or shell history.

E3, completion and repair:

- resume setup after interruption at every durable state;
- verify the Cloud possession receipt, install control trust atomically,
  restart and probe the native service, connect Claude Code/Cursor, create a
  disposable signed test commit, and verify it with Git;
- add `setup status`, `doctor`, and exact remediation commands for expired
  invitation, wrong release, stale control, missing approval, and editor drift.

Exit condition: on a clean supported Mac, a non-engineer can complete setup
without manually locating a candidate ID, fingerprint, API path, or JSON blob;
an interruption at each state resumes without duplicate keys or enrollments.

### F — production signer authority

Depends on the frozen D contracts; can run beside E.

F1, provider completeness:

- provision purpose-separated managed keys for control bundles, capabilities,
  Human assertions, enrollment possession receipts, audit checkpoints, and
  release/evidence signing;
- pin provider, region, key resource, algorithm, and key version per purpose;
- forbid local/file fallback in hosted mode and fail readiness when any
  required purpose is unavailable.

F2, durable operation:

- finish PostgreSQL lifecycle, rotation, expiry, revocation, and idempotency for
  every signer purpose;
- reconcile ambiguous provider outcomes without blind re-signing;
- qualify two-instance contention, key rotation overlap, stale version,
  throttling, timeout, provider outage, response loss, and graceful drain.

F3, evidence:

- retain provider-native proof that private material is non-exportable and that
  runtime identities can use only the exact purpose key;
- verify Cloud images contain no signing key, fallback key, or broad provider
  credential;
- document rotation, compromise, disablement, and restore procedures.

Exit condition: all hosted signing uses managed non-exportable keys, exact
retries return one committed result, and a provider or database ambiguity
cannot create an untracked second signature.

### G — signed distribution and physical-Mac qualification

Can prepare beside E/F; final qualification consumes their immutable release
candidate.

G1, package pipeline:

- produce one universal or architecture-paired PKG with pinned nested code
  identities, entitlements, ownership, permissions, launchd definitions, CLI,
  adapters, and digest manifest;
- sign with Developer ID Installer/Application identities, notarize, staple,
  and independently verify Gatekeeper and every nested CodeDirectory;
- publish direct-download checksums and a Homebrew cask/bootstrap that installs
  that exact PKG rather than a second product build.

G2, lifecycle matrix:

- clean install, upgrade, rollback, uninstall-preserve, reinstall, and explicit
  purge on Apple silicon/Secure Enclave and Intel/T2 where supported;
- prove unrelated Git/editor configuration is byte-preserved and ordinary
  uninstall cannot delete protected identity or audit state;
- test power loss/process kill at every durable installer and setup boundary.

G3, protected evidence:

- bind source commit, artifact digest, Team ID, notarization ticket, hardware,
  OS, boot identity, native identities, and teardown proof in signed reports;
- reject edited, mixed-candidate, stale, skipped, or simulator-only reports.

Exit condition: both physical lanes accept the same immutable candidate and all
install/lifecycle evidence verifies independently.

### H — Claude Code and Cursor unattended E2E

Depends on E, F, and the G candidate.

Deliverables:

- finish adapters using process-bound Agent sessions and scoped capabilities;
- bind repository, worktree, branch, remote, operation, device, agent process,
  policy sequence, budget, and expiry into the signing decision;
- make one signature transaction atomic across authorization consumption,
  Secure Enclave signing, audit durability, and reply-loss recovery;
- invalidate immediately on process exit, TTL, budget exhaustion, policy
  change, device/agent revocation, emergency stop, or control staleness;
- provide editor-specific install, status, repair, and removal commands.

Required scenarios:

- two unattended commits per adapter verify with `git verify-commit`;
- 100 concurrent requests cannot exceed the configured signing budget;
- revocation during signing, daemon restart, network loss, Cloud response loss,
  audit fsync failure, reply loss, repository substitution, and malicious
  sibling process all fail or converge to one auditable result;
- no reusable secret appears in argv, environment, stdin, repository files,
  browser stores, retained traces, logs, crash reports, or support bundles.

Exit condition: Claude Code and Cursor can work unattended within policy, and
Console revocation prevents the next operation within the documented bound.

### I — staging, security review, and production

Depends on E–H.

I1, deployment:

- reproducible infrastructure for Console, Cloud API, workers, PostgreSQL,
  managed signers, secrets/config references, TLS, DNS, rate limits, alerts,
  dashboards, and immutable image promotion;
- startup/readiness gates for schema, signer purpose/version, database TLS and
  permissions, control freshness, and worker health;
- canary, rollback, forward-only migration, and graceful-drain procedures.

I2, operations:

- encrypted backups and point-in-time recovery with measured RPO/RTO;
- restore, signer rotation, provider outage, database outage, emergency stop,
  owner recovery, dead-letter adjudication, and audit export drills;
- fixed-cardinality telemetry and secret-scanned logs/support artifacts.

I3, independent review:

- threat-model review of local privilege boundaries, browser handoff,
  WebAuthn, tenant isolation, replay/idempotency, managed signers, update and
  package supply chain, audit integrity, and recovery;
- remediate all critical/high findings and retest medium findings that affect
  authority or secret handling;
- publish security policy, supported versions, disclosure path, operator
  runbooks, and signed release provenance.

Exit condition: the exact production candidate passes staging E2E, restore and
incident drills, independent review with zero unresolved critical/high issues,
and a final go/no-go checklist signed by release and security owners.

## 5. Execution order and parallel lanes

1. Finish D and obtain a terminal green CI run.
2. Freeze the public preflight/handoff contract for E; implement E1 and the
   Console side of E2 in parallel.
3. Start F1 managed-key provisioning and F2 PostgreSQL qualification while E2
   and E3 are built.
4. Build G1 packaging behind disabled production release promotion; use the
   immutable E/F candidate for G2–G3.
5. Run H first with Claude Code, then reuse the frozen adapter contract for
   Cursor. Do not generalize to more agents before both pass.
6. Deploy the exact candidate to staging for I1–I2, complete I3, then promote
   without rebuilding.

## 6. Definition of done

AgentPass v1 is complete only when all of the following are true:

- one non-engineer onboarding journey succeeds on a clean physical Mac;
- Claude Code and Cursor each produce independently verified unattended signed
  commits under bounded policy;
- browser, Cloud, native broker, and PostgreSQL agree on organization, device,
  agent, policy, session, capability, audit, and revocation state;
- every hosted signing purpose uses a managed non-exportable key with no local
  fallback;
- the distributed PKG is Developer ID-signed, notarized, stapled, and bound to
  the tested source and evidence;
- multi-instance, replay, substitution, response-loss, restart, revocation, and
  restore qualifications pass;
- production deployment and rollback are rehearsed;
- independent review has no unresolved critical or high finding.

Local mocks, skipped tests, simulator runs, an unsigned package, or a green unit
suite alone never satisfy these completion conditions.

## 7. Detailed implementation queue

This queue is ordered by production dependency, not by UI visibility. A package
may start in parallel only after every contract named in its entry is frozen.

### Q1 — finish the one-command onboarding seam

State: next.

Inputs already implemented:

- release manifest v4 candidate identity derived from the exact PKG SHA-256;
- root-owned public installed-release receipt and installed app Team ID/path
  reinspection;
- `setup prepare --json` with an exact four-field public DTO;
- Console guided preflight import and a one-consume loopback transport
  primitive.

Remaining implementation:

1. Add a CLI browser-connect mode to `setup continue` that creates the loopback
   listener, opens an allow-listed HTTPS Console origin with only the opaque
   loopback URL in the fragment, and waits under a fixed deadline.
2. Feed the received invitation directly from memory into the existing
   enrollment state handler. Never print it, persist it, put it in argv or an
   environment variable, or copy it through a temporary file.
3. Bind the configured Cloud API `/v1` origin independently from the Console
   origin; neither origin may be inferred from the other.
4. Add browser Private Network Access preflight handling only for the exact
   approved HTTPS origin, with no wildcard CORS and no reflection of rejected
   origins.
5. Resume after browser closure, listener expiry, Cloud timeout, lost enrollment
   response, native restart, and CLI interruption without reusing an invitation
   or repeating a definitive enrollment POST.
6. Finish `setup status` and `doctor` remediation for missing/invalid receipt,
   wrong Team ID, unsupported candidate, expired handoff, unavailable native
   key, stale control, and editor drift.

Required evidence:

- unit attacks for fragment/query/Origin/Host/nonce/candidate/fingerprint and
  ACK substitution, duplicate JSON keys, request smuggling bounds, concurrent
  consume, replay, expiry, abort, and listener teardown;
- Playwright coverage from launch fragment removal through WebAuthn issuance,
  successful POST/ACK, and manual stdin fallback after local delivery failure;
- a clean physical-Mac run where no candidate ID, fingerprint, endpoint, or
  invitation JSON is manually entered.

Exit condition: one command opens Console and returns to a verified, resumable
native setup state with no reusable authority in process listings, shell
history, browser history/storage, logs, crash reports, or durable setup state.

### Q2 — production data and signing authority

State: ready to start in parallel after Q1 API contracts freeze.

Work breakdown:

1. PostgreSQL: run every forward-only migration in staging; enforce
   organization-qualified primary/foreign keys, transaction isolation,
   idempotency uniqueness, row-count bounds, statement deadlines, TLS, backup,
   restore, and least-privilege runtime roles.
2. Managed keys: allocate separate provider keys for control, capability, Human
   assertion, enrollment receipt, audit checkpoint, and release/evidence
   signing. Pin provider, region, key resource, algorithm, and version.
3. Provider adapters: make AWS KMS/Cloud KMS-class adapters implement one closed
   interface, reject local/file fallback in hosted mode, and expose only public
   key metadata through readiness.
4. Durable signer operations: reserve idempotency in PostgreSQL before provider
   calls, reconcile timeout/response-loss outcomes, and prohibit blind
   re-signing when provider outcome is ambiguous.
5. Rotation and revocation: support overlap windows, stale-version rejection,
   emergency disablement, process drain, and independently verifiable audit
   records.

Exit condition: two Cloud instances under contention produce one committed
result per idempotency key, and every production signing purpose is backed by a
managed non-exportable key with no fallback path in image or configuration.

### Q3 — immutable macOS distribution

State: pipeline scaffolding exists; real credentials and physical runners are
external gates.

Work breakdown:

1. Build one immutable universal PKG and verify all nested identities,
   entitlements, ownership, permissions, launchd definitions, CLI, adapters,
   receipt root, and protected-state exclusions.
2. Sign Application and Installer artifacts with pinned Developer ID identities,
   notarize, staple, verify Gatekeeper offline, and attach provenance to manifest
   v4 without rebuilding the product.
3. Publish direct-download SHA-256 and a Homebrew cask/bootstrap that installs
   that exact PKG digest.
4. Qualify clean install, upgrade, rollback, uninstall-preserve, reinstall, and
   explicit purge on Apple silicon/Secure Enclave and Intel/T2 lanes.
5. Sign lane evidence and aggregate only reports that bind the same source,
   package digest, candidate ID, Team ID, notarization ticket, hardware, OS, and
   teardown proof.

Exit condition: both physical lanes accept one immutable candidate and the
download, Homebrew, evidence, and installed receipt all resolve to its exact PKG
digest.

### Q4 — Claude Code and Cursor production E2E

State: depends on Q1–Q3.

Work breakdown:

1. Finalize process-bound adapter launch and editor install/repair/remove
   commands for Claude Code, then Cursor against the same frozen contract.
2. Bind repository, worktree, branch, remote, operation, device, agent process,
   policy sequence, budget, expiry, and request id into each signing decision.
3. Make authorization consumption, Secure Enclave signing, audit durability,
   and reply-loss recovery converge to one result.
4. Exercise malicious sibling process, repository substitution, 100-request
   contention, budget exhaustion, revocation during signing, daemon restart,
   network loss, Cloud response loss, and audit fsync failure.

Exit condition: each supported agent makes two unattended commits that pass
`git verify-commit`, while revocation blocks the next operation within the
documented bound and every failure remains auditable.

### Q5 — staging, security review, and production promotion

State: final gate.

Work breakdown:

1. Reproducibly deploy Console, API, workers, PostgreSQL, managed signers, TLS,
   DNS, rate limits, fixed-cardinality telemetry, alerts, and immutable images.
2. Rehearse canary, drain, rollback, forward-only migration, encrypted backup,
   point-in-time restore, signer rotation, provider/database outage, emergency
   stop, owner recovery, and dead-letter adjudication.
3. Independently review local privilege boundaries, loopback handoff, WebAuthn,
   tenant isolation, replay/idempotency, managed keys, package/update supply
   chain, audit integrity, and recovery.
4. Close all critical/high findings, retest security-relevant medium findings,
   publish supported-version and disclosure policies, then promote the exact
   staging candidate without rebuilding.

Exit condition: production go/no-go evidence is complete, restore RPO/RTO is
measured, rollback is rehearsed, and no unresolved critical/high security issue
remains.
