# AgentPass production implementation plan — 2026-08-16

Status: active

Planning baseline: `codex/agent-platform` at `6601c31`

This document converts the v1 architecture into the remaining implementation
and qualification gates. [`V1_EXECUTION_PLAN.md`](./V1_EXECUTION_PLAN.md)
remains the authoritative product definition and release gate. This plan owns
the day-to-day merge order from the current source checkpoint.

## 1. Current source checkpoint

The repository currently has 182 catalog entries, 49 JSON Schemas, 62 OpenAPI
operations, and 71 forward-only PostgreSQL migrations. The implemented source
boundary includes:

- organization-qualified Human identity, roles, sessions, WebAuthn credentials,
  recent authorization, invitations, recovery, and audit foundations;
- PostgreSQL-backed platform signing challenges, sessions, lifecycle fencing,
  provider-operation reconciliation, exact-byte idempotency, and least-privilege
  role qualification;
- a strict Console BFF, organization workspace, passkey management, session
  management, device/control status, emergency actions, and recovery surfaces;
- purpose-separated hosted signer configuration and provider adapters with
  hosted file/private-key fallback rejection, exact eight-purpose readiness,
  immutable version/fingerprint checks, and active-key enforcement;
- resumable headless onboarding, v2 device enrollment, native broker/XPC,
  release-manifest verification, installer and hardware-qualification scaffolding.

The PostgreSQL 16 and 17 authority lanes and the full PostgreSQL integration
lane pass at this checkpoint. This is not production completion. The current
branch still needs a terminal green cross-version CI run, complete browser
journeys, protected real-provider evidence, physical Mac evidence, a
signed/notarized artifact, staging drills, and independent security review.

### 1.1 Live execution checkpoint

The latest completed diagnostic runs and the source at `6601c31` establish the
following current state:

- PostgreSQL 16 authority qualification, PostgreSQL 17 authority
  qualification, and the full PostgreSQL integration lane were green in the
  latest observed completed diagnostic run;
- organization invitation acceptance now returns the frozen
  `{request_id, invitation, member}` contract, converges under concurrent
  PostgreSQL acceptance, and has response-loss browser coverage;
- Human Session bootstrap is serialized in the live browser harness and retries
  only bounded transient `502` responses; authentication, authorization, and
  mutation failures are never retried;
- one injected, single-flight Console session authority now owns bootstrap,
  generation invalidation, rotation adoption, and conditional clearing for the
  shell, organization client, security client, and both panels. A stale
  bootstrap cannot overwrite or clear a newer session generation;
- registration ceremony storage failures preserve their typed dependency
  classification through service and HTTP mapping and return a stable,
  secret-free `503` response rather than a user-correctable `422`;
- the Human OpenAPI contract now freezes strict registration options/verify
  bodies, exact success DTOs, the implemented `201`, CSRF shape, recent-auth
  preconditions, and the complete error surface;
- P0-B now waits for the Console-owned `/api/auth/session/resume` rotation after
  navigation and adopts the returned session selector/CSRF before fixture-owned
  WebAuthn registration. This closes the race that first appeared as
  `owner_reg_session_revoked_rotated` and then as
  `owner_registration_options_409`; protected qualification of this exact fix
  remains pending;
- the PostgreSQL application role includes only the required WebAuthn transport
  validation function grant, and the role/constraint contract remains aligned;
- invitation reissue is source-complete through PostgreSQL, Cloud HTTP,
  OpenAPI, and Console BFF at `ca19091`; the Console interaction and protected
  role/browser matrix remain open;
- the last observed root lane lint defect is fixed. The prior browser lane also
  exposed one CLI handoff failure; it must be reproduced on the current head
  before any production code is changed. All six lanes must reach terminal
  success on the same source SHA. A local test, partial run, replaced run, or
  cancelled diagnostic run is not N1 evidence.

The next implementation batches are intentionally narrow and ordered:

| Batch | Merge-sized work | Tests and evidence | Completion condition |
| --- | --- | --- | --- |
| Q1 | Source-complete at `6601c31`: shared Console session authority, typed registration dependency errors, exact registration OpenAPI, and P0-B rotation adoption. | Concurrent bootstrap unit tests, session-rotation/revocation negatives, focused Human API tests, contract validation, live trusted-TLS PostgreSQL/Cloud/Console/Chromium run, artifact secret scan. | P0-B completes every Owner/Admin/Auditor/Viewer scenario and emits a verified source-bound report for `6601c31` or its minimal diagnostic successor. |
| Q2 | Rerun all six CI jobs without cancellation or replacement commits. Remove any newly exposed timing, lifecycle, native, or artifact-hygiene defect at its owning boundary. | Root/Console/native, browser, P0-B, PostgreSQL integration, PostgreSQL 16 and PostgreSQL 17 on one SHA. | One terminal all-green run is retained; N1 becomes `qualified`. |
| H1 | Complete organization administration: invitation resend/revoke, role change/removal with `If-Match`, last-owner protection, authoritative response-loss reconciliation, and stable Japanese remediation. | Real PostgreSQL contention/replay/cross-tenant tests plus Owner/Admin/Auditor/Viewer Playwright matrix. | Every organization mutation converges to committed state without blind replay or fixture fallback. |
| H2 | Complete passkey and Human Session lifecycle: add/rename/revoke, final-auth-path guard, current/other/all-other session revoke, epoch invalidation, explicit reauthentication. | Virtual WebAuthn, stale/replayed recent-auth, expiry, self-revoke, clone/sign-count, keyboard and secret-scan tests. | A non-engineer can recover from every expected conflict or expiry state without CLI/operator credentials. |
| D1 | Freeze onboarding preflight, invitation, loopback handoff, possession receipt, and control ACK contracts across Core/OpenAPI/Console/CLI/native. | Generated-validator sync, unknown-field/duplicate-key/canonical-vector tests and threat-model review. | One versioned contract has no caller-controlled authority fields and no downgrade path. |
| D2 | Implement browser-led loopback delivery, bounded stdin recovery, and durable resume states through `control_acknowledged`. | Interruption at every durable state, expiry/timeout/response-loss, duplicate enrollment and browser-storage scans. | Clean-machine onboarding converges with no manual identifiers and no reusable secret in argv/env/URL/storage. |
| S1 | Finish all eight managed-signer purpose paths and provider-operation reconciliation. | Two-instance contention, timeout/outage/lookup, malformed response, lost commit response, rotation/disable/drain tests. | Source paths are complete and hosted readiness rejects every missing/shared/local/file signer configuration. |
| S2 | Run protected AWS/GCP KMS qualification with purpose-separated workload identities and immutable key versions. | Cross-purpose IAM denial, non-exportability, fingerprint/version binding, rotation and no-fallback evidence. | Signed source-bound provider reports pass independent verification. |
| M1 | Close the native sign-once transaction and Claude Code lifecycle, then add Cursor through the same frozen broker protocol. | Two unattended verified commits, policy/process/repository substitution, kill/restart/expiry/unknown-outcome and secret scans. | Neither adapter can select keys, widen policy, or retry ambiguous signing. |
| R1 | Build one immutable hardened-runtime PKG, sign/notarize/staple it, and make direct download and Homebrew consume that digest. | Gatekeeper, CodeDirectory, entitlement, SBOM/provenance, upgrade/uninstall/reinstall/rollback tests on Apple silicon and Intel/T2. | Both physical reports identify the same notarized artifact digest. |
| O1 | Deploy the immutable candidate to staging and execute migration, restore, outage, rotation/compromise, emergency-stop, tenant-isolation, and rollback drills. | Measured SLO/RPO/RTO, alert routing, DAST/SAST/IaC/container review, independent security assessment. | No critical/high finding remains and an independently verified signed promotion record supports explicit production go/no-go. |

Parallel execution starts only after Q2: H1/H2 and S1 may proceed in parallel;
D1 waits for Human Session/recent-auth and possession-receipt metadata to freeze;
M1 may prepare internal native tests but cannot freeze its public adapter until
D1; R1 requires M1; O1 requires the exact qualified R1 artifact. Migrations,
public contracts, signing domains, XPC selectors, entitlements, and promotion
authority each retain a single integration owner.

## 2. Non-negotiable product boundaries

1. The Web Console is the human control plane. It never receives a private key
   or reusable device/Agent signing authority.
2. The signed native broker is the Mac security boundary. CLI and editor
   adapters are unprivileged clients of the same closed broker protocol.
3. PostgreSQL is authoritative for hosted identity, lifecycle, idempotency,
   revocation, and audit state. Process memory and browser state are caches only.
4. Production signing keys are purpose-separated, non-exportable managed keys.
   Hosted mode has no file, environment, or local-key fallback.
5. A successful HTTP response is not sufficient evidence of authority change.
   Console state must reflect committed PostgreSQL state or a verified signed
   device acknowledgement.
6. Mocked, skipped, simulator, ad-hoc-signed, and local-only evidence never
   satisfies a protected, physical, or production release gate.

## 3. Dependency and merge graph

```text
N1 qualification closure
 ├──> N2 Human/organization Console ──> N3 device onboarding ──┐
 └──> N5 managed signer/cloud authority ──────────────────────┼──> N4 macOS + agents
                                                             │
N6 infrastructure preparation ────────────────────────────────┘

N2 + N3 + N4 + N5 qualified candidate ──> N6 staging/review/promotion
```

N2 and N5 may run concurrently after N1. N6 infrastructure modules and
runbooks may be prepared concurrently, but production credentials, migration
authority, and promotion remain serialized. Protocol/schema, migrations,
signing domains, XPC selectors, entitlements, code identities, and evidence
schemas each have one integration owner.

### 3.1 Current phase order

The next changes are intentionally small enough to diagnose and revert
independently. Do not combine a CI-diagnostic repair with a new product surface.

1. **Q1.3 protected P0-B qualification**
   - run the exact `6601c31` source through trusted-TLS PostgreSQL, production
     Cloud/Console builds, and Chromium;
   - verify that bootstrap adopts the application-owned rotated session before
     registration, all role scenarios complete, and retained artifacts are
     secret-free and source-bound;
   - if the run advances and fails, change only the boundary identified by its
     fixed safe marker, add one focused regression, and rerun P0-B.
2. **Q2 browser and one-SHA qualification**
   - reproduce the prior CLI handoff browser failure on the current head; fix it
     only if reproducible, without weakening secret scanners or response DTOs;
   - stop diagnostic commits and run all six jobs on one exact head: root test,
     browser E2E, P0-B, PostgreSQL integration, PostgreSQL 16, PostgreSQL 17;
   - accept the baseline only when every job is terminal green and every
     retained report identifies the same source SHA.
3. **N2 Human/organization completion**
   - close invitation resend/revoke, role/removal CAS, last-owner protection,
     passkey lifecycle, session revocation, response-loss reconciliation, and
     non-engineer remediation copy;
   - qualify the real Owner/Admin/Auditor/Viewer browser matrix.
4. **N3 + N5 parallel contract consumers**
   - freeze and implement browser-led device onboarding and Device API/receipt/
     ACK convergence in one lane;
   - finish all eight managed-signer purposes and provider reconciliation in a
     separate lane; merge only after contract and authority reviews.
5. **N4 agent/native closure**
   - complete the sign-once XPC transaction and Claude Code lifecycle first;
     add Cursor only against the same frozen broker contract;
   - qualify process substitution, kill/restart, policy change, expiry,
     revocation, and ambiguous outcome handling on physical Macs.
6. **N6 release and production**
   - build one Developer ID-signed/notarized/stapled PKG and distribute that
     exact digest by direct download, Homebrew bootstrap, and MDM;
   - deploy the immutable candidate to staging, run migration/restore/outage/
     rotation/emergency drills, complete independent security review, and
     require an explicit signed production promotion decision.

Every queue item exits with code, negative tests, operational evidence, and
updated user/operator documentation. A local mock, simulator, skipped job, or
unsigned artifact can demonstrate development progress but cannot close the
corresponding production gate.

## 4. N1 — terminal qualification closure

Objective: establish one trustworthy source baseline before expanding product
surface.

Implementation work:

1. Make PostgreSQL 16 and 17 apply migrations 0001–0071 from an empty database.
2. Qualify app, migrator, backup, hosted-platform, and provider-operation roles;
   prove denied DDL, table access, arbitrary function execution, role switching,
   and tenant substitution.
3. Run the platform challenge/session/authorization and provider reconciliation
   matrices under contention, timeout, response loss, lost commit response,
   rotation, revocation, and malformed provider output.
4. Run root tests, Console unit/lint/build, browser E2E, P0-B live-process E2E,
   contract validation, secret scans, and release evidence validation.
5. Remove every accidental skip caused by missing CI wiring. Intentional tests
   requiring external hardware or credentials must state that requirement and
   cannot report qualification success.

Exit evidence:

- one GitHub Actions run for the exact head reaches a terminal successful state;
- PostgreSQL 16 and 17 produce the same authority behavior;
- retained reports bind source SHA, migration head, image/tool versions, and
  individual command digests;
- no test logs or artifacts contain credentials, assertions, private material,
  raw provider diagnostics, or tenant PII.

## 5. N2 — Human identity and organization Console

Objective: make every day-to-day human operation understandable and complete
without exposing Cloud operator credentials or relying on fixture data.

### N2.1 Organization workspace

- list, create, select, and switch organizations with opaque pagination;
- invite members, display invitation expiry/status, resend/revoke safely, and
  accept invitations without tenant enumeration;
- list members and change/remove roles with `If-Match`, idempotency, recent
  WebAuthn authorization, last-owner protection, and authoritative refresh;
- fail closed on an unknown role, stale organization version, expired session,
  or BFF shape mismatch.

### N2.2 Authentication and session safety

- complete passkey sign-in, add, rename, and revoke flows;
- prevent removal of the final usable recovery/authentication path;
- list the current and other sessions, revoke one/all-other sessions, and make
  self-revocation immediately clear all tenant state;
- provide explicit reauthentication and preserve only safe navigation intent;
- bind destructive operations to a resource- and operation-specific one-use
  recent-auth proof.

### N2.3 Operations surfaces

- device inventory, enrollment state, control generation/expiry/ACK, wake,
  revoke, and emergency stop;
- Agent Session and scoped-capability inspection, narrowing, expiry, and revoke;
- bounded audit search/export, managed-signer health, recovery, dead-letter,
  and uncertain-operation adjudication;
- stable Japanese and English error identifiers with actionable remediation.

### N2.4 Browser hardening and usability

- strict DTO decoders, no-store responses, CSP/HSTS, secure cookies, Origin and
  CSRF checks, safe redirects, cursor bounds, and conflict reconciliation;
- Owner/Admin/Auditor/Viewer Playwright matrix using real PostgreSQL and virtual
  WebAuthn through production-built Cloud and Console processes;
- keyboard-only journeys, focus restoration, dialogs/live regions, 200% zoom,
  reduced motion, responsive layouts, and screen-reader names;
- scan bundles, DOM, URL/history, storage, caches, console, network metadata,
  screenshots, traces, and errors for forbidden material.

Exit gate: a non-engineer can sign in, create/select an organization, manage
members and passkeys, inspect/revoke sessions and devices, and understand the
result without a CLI. All role, replay, stale-state, cross-tenant, expiry, and
response-loss negatives pass in the protected browser matrix.

## 6. N3 — browser-led device onboarding

Objective: one guided Console-to-Mac flow with no manual candidate ID, key
fingerprint, endpoint, or invitation JSON handling.

Implementation work:

1. Freeze the public preflight DTO and invitation/receipt schemas across Core,
   OpenAPI, Console BFF, CLI, and native setup state.
2. `agentpass setup prepare` verifies the installed signed release and native
   identities, creates/reuses the non-exportable enrollment key, and returns
   only public candidate and key-fingerprint data.
3. Console selects a compatible release, requires operation-bound WebAuthn,
   issues one bounded invitation, and transfers it over an origin-pinned,
   nonce-bound loopback channel held only in memory.
4. Provide bounded stdin copy/paste as the recovery path when Private Network
   Access or local delivery is unavailable. Never use argv, environment, query
   strings, browser persistence, analytics, or shell history.
5. Resume safely after browser closure, invitation expiry, listener timeout,
   Cloud timeout, ambiguous enrollment response, CLI/native restart, and power
   loss. A definitive or ambiguous POST is never blindly replayed.
6. Verify the signed possession receipt before atomically installing control
   trust, then show pending/applied/blocked device truth in Console.

Exit gate: a clean physical Mac completes enrollment from one documented
command; interruption tests at every durable transition converge without a
duplicate key/enrollment; secret scans remain empty; Console and native state
agree through a verified receipt and control ACK.

## 7. N4 — macOS broker, Claude Code, Cursor, and distribution

Objective: deliver unattended policy-bound Git signing through one native
authority path.

### N4.1 Native transaction closure

- re-observe peer code identity, process ancestry, repository/worktree, branch,
  remote, control generation, device state, key state, TTL, and budget directly
  before key use;
- durably reserve authorization and append secret-free intent, sign once in
  Secure Enclave, fsync result/audit state, and then reply;
- classify ambiguity after key use as `outcome_unknown`; never retry signing;
- unify process exit, XPC invalidation, policy change, revoke, emergency stop,
  key rotation, shutdown, and deployment drain in one monotonic invalidation
  model.

### N4.2 Agent integrations

- complete Claude Code first with `install`, `setup`, `doctor`, `launch`,
  `status`, `close`, `revoke`, `uninstall`, and explicit `purge` commands;
- produce two unattended commits verified by `git verify-commit`;
- add Cursor only against the frozen adapter contract and same broker
  transaction; adapter code cannot select keys or widen policy;
- reject wrong executable, signature, ancestry, PID reuse, repository,
  worktree, branch, remote, generation, expiry, or exhausted budget.

### N4.3 Immutable distribution

- build one universal or architecture-paired hardened-runtime PKG;
- pin nested identifiers, entitlements, ownership, permissions, launchd jobs,
  CLI, adapters, and receipt inventory;
- sign nested code and package with Developer ID, notarize, staple, verify
  Gatekeeper and CodeDirectory identities, and emit SBOM/provenance;
- make direct download and Homebrew verify/install the same immutable PKG;
- qualify the exact digest on Apple silicon/Secure Enclave and Intel/T2 for
  install, restart, upgrade, rollback refusal, uninstall-preserve,
  reinstall-recover, and purge.

Exit gate: both agents pass the complete physical positive/negative matrix on
the same notarized artifact digest and no reusable secret appears in argv,
environment, stdin except the explicit one-shot recovery channel, shell
history, repository files, logs, crash reports, or support bundles.

## 8. N5 — managed signer and hosted authority

Objective: replace all hosted evaluation authority with purpose-separated,
non-exportable managed signing and operationally safe PostgreSQL state.

### N5.0 Graceful drain/shutdown closure (source-complete slice)

The hosted runtime now exposes the PostgreSQL drain controller as the shared
managed-signer admission authority. Readiness is withdrawn when draining
begins, and every hosted signer/provider-operation path checkpoints that
authority before durable reservation, after an awaited reservation/start
boundary, immediately before an external provider call, and during recovery.
New work is rejected fail-closed; accepted work that loses the race is
quarantined as durable `uncertain` rather than starting a new provider call.
Runtime close and the underlying drain close remain bounded and idempotent.

The focused unit/model tests cover a new request after drain, reservation and
provider-start races, direct adapter fencing, readiness withdrawal, bounded
timeout behavior, and repeated/concurrent close. Protected AWS/GCP evidence,
multi-instance termination evidence, and provider-specific cancellation
behavior remain qualification gates below.

Implementation work:

1. Provision distinct keys and workload identities for capability,
   ControlBundle, refresh hint, possession receipt, Agent Session Grant,
   qualification manifest, audit anchor, and promotion evidence.
2. Pin provider, account/project, region, resource, algorithm, public-key
   fingerprint, immutable key version, protocol/signing version, and lifecycle
   epoch for every purpose.
3. Require all purpose mappings and PostgreSQL authority checks before hosted
   readiness. Reject duplicate/shared keys, aliases, missing versions, broad
   credentials, local/file signers, and private material in configuration.
4. Complete `reserve -> provider start -> provider acceptance/lookup -> verify
   exact signature -> commit exact bytes -> reply` for every purpose.
5. Qualify 100-request/two-instance contention, conflicting idempotency reuse,
   timeout/throttle/outage, malformed receipt/signature, lookup absence,
   process termination at every boundary, lost commit response, database
   failover, rotation overlap, emergency disablement, and graceful drain.
6. Implement dashboards and operator actions for active/retiring/revoked keys,
   uncertain operations, rotation, compromise, audit anchoring, and immediate
   authority reduction without exposing provider diagnostics to tenants.

Exit gate: protected AWS/GCP qualification proves key non-exportability,
cross-purpose IAM denial, exact-result convergence, rotation/recovery, and no
fallback in deployed images/configuration. Every ambiguity is either one
verified committed result or an explicit durable operator-actionable state.

## 9. N6 — staging, operations, review, and promotion

Objective: deploy and operate the exact qualified candidate without rebuilding.

Implementation work:

1. Provision isolated development, staging, and production accounts; private
   PostgreSQL, workload identity, KMS/HSM, object storage, DNS/TLS, WAF/rate
   limits, and protected migration/release roles through reviewed IaC.
2. Build immutable Console/API/worker images and a one-writer forward-only
   migration stage with compatibility preflight, advisory lock, canary,
   graceful drain, traffic rollback, and forward-fix procedure.
3. Configure encrypted backups, PITR, cross-failure-domain copies, scheduled
   restore verification, and authority-manifest comparison; measure RPO/RTO.
4. Add SLOs and fixed-cardinality alerts for authentication, WebAuthn, signer
   latency/error, bundle freshness, ACK/revocation propagation, audit gaps,
   outbox lag, database saturation, migration drift, and backup age.
5. Execute provider/database outage, restore, rollback, signer rotation and
   compromise, emergency stop, owner recovery, dead-letter, tenant isolation,
   and queue-backlog drills against the immutable release candidate.
6. Run dependency/SAST/DAST/container/IaC/redaction reviews and an independent
   security assessment. Resolve every critical/high finding and assign owners
   and deadlines to accepted lower findings.
7. Produce one signed promotion record binding source, images, migrations,
   signer versions, SBOM/provenance, browser reports, restore/incident drills,
   security review, notarized PKG, and both physical hardware reports.

Exit gate: staging meets measured SLO/RPO/RTO and rollback targets, no
critical/high finding remains, promotion is allow-listed and reversible, and
production receives the exact already-qualified artifacts.

## 10. Parallel ownership lanes

| Lane | Immediate scope | Must serialize on |
| --- | --- | --- |
| Integration/DB | N1 CI, PostgreSQL 16/17, migrations, catalog | migrations, SQL functions, authority manifests |
| Console/Human | N2 organization, role, passkey, session, operations UX | Human DTOs, recent-auth semantics, destructive actions |
| Device/native | N3 handoff/resume tests and N4 harness preparation | Device schema, XPC selectors, durable state, entitlements |
| Signer/cloud | N5 providers, reconciliation, lifecycle qualification | purpose registry, domains, key metadata, hosted readiness |
| Release/ops | N4 package verification and N6 IaC/runbooks | code identity, artifact digest, credentials, promotion record |

Parallel agents own disjoint files and return reviewable commits. They do not
independently merge a migration, widen a public protocol, enable production,
or modify a signing domain. Integration order is N1; then N2 and N5; then N3;
then N4; then final N6 qualification and promotion.

## 11. Immediate merge queue

1. `test: qualify Console session-rotation repair` — run `6601c31` through the
   live PostgreSQL/Cloud/Console/Chromium topology, require complete role and
   WebAuthn success, and preserve only source-bound secret-free diagnostics.
2. `fix: close CLI handoff browser regression if reproducible` — inspect the
   current production-built browser result and repair the owning boundary only;
   do not suppress the artifact scanner or render reusable handoff material.
3. `test: close one-SHA qualification` — finish PostgreSQL 16/17, PostgreSQL
   integration, root/native, browser, and P0-B without replacement commits.
4. `test: close protected console identity matrix` — organization switch,
   invitation/role mutations, passkey/session lifecycle, expiry, self-logout,
   tenant substitution, and virtual-WebAuthn tests through real PostgreSQL.
5. `feat: complete organization and identity console` — production UI states,
   accessibility, Japanese errors, pagination/conflict recovery, and no fixture
   fallback.
6. `test: qualify all hosted signer purposes` — purpose-by-purpose real-provider
   IAM/non-exportability, response-loss, rotation, and image/configuration scan.
7. `feat: complete browser-led device onboarding` — complete loopback/PNA and
   stdin recovery journeys, interruption matrix, authoritative receipt/ACK UI.
8. `feat: close claude code native signing transaction` — durable sign-once,
   invalidation races, installer/doctor, and two verified commits.
9. `feat: add cursor adapter parity` — same closed adapter protocol and full
   negative matrix, with no new authority path.
10. `build: publish immutable notarized candidate` — Developer ID signatures,
   notarization/stapling, SBOM/provenance, direct download, and Homebrew.
11. `test: qualify physical mac release candidate` — Apple silicon and Intel/T2
   reports for the exact candidate digest.
12. `ops: deploy staging and close production review` — restore/rollback/outage
    drills, independent review, signed promotion record, then explicit go/no-go.

Each queue item is a reviewable commit or short ordered series. Every push runs
its focused tests plus contract validation, lint, root/Console/native suites,
and `git diff --check`; boundary-specific PostgreSQL, browser, provider,
packaging, or physical tests are added as required.

## 12. Execution ledger and acceptance matrix

This ledger is the operational source of truth for deciding what to implement
next. A work package moves to `qualified` only when its source, negative tests,
and required retained evidence all refer to the same commit. Source-complete
work that still needs protected infrastructure or physical hardware remains
`implemented`; it is not silently promoted.

| Package | Current state | Next merge-sized deliverables | Required acceptance evidence | Unlocks |
| --- | --- | --- | --- | --- |
| N1 qualification closure | `Q1 source complete at 6601c31; protected rerun open` | Verify session-rotation adoption in P0-B; reproduce the prior CLI handoff failure; repair only a proven owning boundary; rerun all six CI jobs on one head; retain clean browser/P0-B artifacts. | One terminal green run: root/Console/native, browser, P0-B, PostgreSQL integration, PostgreSQL 16, and PostgreSQL 17. | N2/N5 qualification claims |
| N2 organization and identity Console | `implemented, qualification open` | Finish real-process Owner/Admin/Auditor/Viewer journeys; cover invitation acceptance/resend, last-owner protection, current-session revoke, final-passkey guard, response loss, and accessibility. | Production-built Console and Cloud API against PostgreSQL; virtual WebAuthn; secret-free DOM/storage/network/artifact scan. | Non-engineer control plane |
| N5 hosted signer | `drain closure implemented, protected evidence open` | Provision eight isolated AWS/GCP keys and identities; run exact-byte convergence, response-loss lookup, rotation, disablement, cross-purpose denial, multi-instance termination, and provider-specific cancellation tests. | Signed, source-bound AWS/GCP reports proving immutable versions, public fingerprints, non-exportability, least privilege, no fallback, bounded drain behavior, and operator-actionable uncertainty. | Hosted release candidate |
| N3 device onboarding | `foundation implemented` | Freeze preflight/handoff DTO; implement browser-to-loopback transfer plus bounded stdin recovery; add interruption/resume state machine and verified receipt/ACK reconciliation. | Clean-machine physical Mac enrollment with restart/expiry/timeout/ambiguous-response matrix and zero secret-bearing artifacts. | Agent installation journey |
| N4 native agents and distribution | `foundation implemented` | Close durable sign-once transaction; Claude Code lifecycle and two verified commits; Cursor parity; immutable PKG/Homebrew path; Developer ID signing and notarization. | Same artifact digest passes identity, entitlement, Gatekeeper, upgrade, uninstall-preserve, reinstall, rollback-refusal, and negative policy matrix on Apple silicon and Intel/T2. | Staging candidate |
| N6 operations and production | `design/runbooks partial` | Finish reviewed IaC, immutable image promotion, migration/canary/drain, backup/PITR restore, SLOs/alerts, incident drills, and independent security assessment. | Exact candidate passes staging SLO/RPO/RTO, restore, outage, rotation/compromise, tenant-isolation, DAST/SAST/IaC/container review, and signed promotion adjudication. | Explicit production go/no-go |

### 12.1 Next source sequence

1. Close N1 on the current head. No broader protocol or migration work lands
   while the terminal qualification run is red.
2. Land N2 browser negatives in three independently reviewable slices:
   organization/invitation, passkey/session, then accessibility and artifact
   hygiene. Each slice must use authoritative refresh after response loss and
   must never replay an unconfirmed destructive mutation.
3. In parallel with N2, retain the N5 graceful-drain and provider-reconciliation
   harnesses as source-complete slices. The protected AWS/GCP executor is
   configuration-only; it cannot add a local signer path or private key input.
4. Freeze the N3 public handoff contract only after N2 session/recent-auth
   behavior and N5 possession-receipt metadata are stable. Generate validators
   from the catalog and reject every unknown field at each boundary.
5. Implement N3 as explicit durable states: `prepared`, `invitation_issued`,
   `delivered`, `enrollment_uncertain`, `receipt_verified`, `trust_installed`,
   and `control_acknowledged`. Every restart must resume or terminate safely
   from one of these states.
6. Close N4 first for Claude Code, then reuse the frozen adapter contract for
   Cursor. Both integrations must pass through the same signed broker and must
   be unable to choose a key, alter policy, or retry an unknown signing outcome.
7. Build, sign, notarize, and staple once. Direct download and Homebrew consume
   the same immutable PKG; physical qualification and staging never rebuild it.
8. Deploy that digest to staging, execute N6 drills and independent review,
   then produce a signed promotion record. Production requires an explicit
   human go/no-go after all evidence has been independently verified.

### 12.2 Per-slice merge contract

Every merge-sized slice must include all applicable items below:

- source and generated contract changes, with forward-only migration/catalog
  updates when the public or PostgreSQL boundary changes;
- positive, denial, replay, stale-version, cross-tenant, malformed-input,
  contention, timeout, response-loss, and process-loss tests for every changed
  authority path;
- threat-model and operator/runbook updates for newly introduced states,
  failure classifications, recovery actions, and observability;
- bounded, secret-free evidence containing source SHA, artifact/image digest,
  migration head, provider/key version where applicable, command digests, and
  verifier result;
- focused tests before commit, then complete contract/lint/root/Console/native
  qualification before push; protected or physical claims require their named
  external executor and cannot be substituted by mocks or skips.

### 12.3 Ticket-level execution backlog

The following backlog is ordered by dependency, not by apparent UI priority.
Each ticket is small enough to review independently and must satisfy the
per-slice merge contract above.

| ID | Deliverable | Depends on | Implementation boundary | Mandatory verification | Done when |
| --- | --- | --- | --- | --- | --- |
| Q1.3 | Live session-rotation qualification for `6601c31` | none | CI harness only; no production fallback | trusted-TLS PostgreSQL, production Cloud/Console builds, Chromium, all roles, secret scan | fixture WebAuthn begins only after the Console rotation is adopted and the retained report binds the exact SHA |
| Q1.4 | First-next-failure repair, only if Q1.3 advances and fails | Q1.3 | the single owning boundary identified by a fixed marker | focused regression plus full P0-B rerun | no speculative retries, fixture bypass, or weakened decoder is introduced |
| Q2.1 | One-SHA six-lane qualification | Q1 | CI/workflow and evidence validators | root/native, browser, P0-B, PostgreSQL integration, PostgreSQL 16/17 | all jobs finish successfully on one unreplaced SHA |
| H1.1 | Invitation reissue Console interaction | Q2, backend at `ca19091` | Console client/components/tests | Owner/Admin allow; Auditor/Viewer deny; recent-auth, stale version, response loss, a11y, token scan | raw token is shown exactly once and never reaches URL, storage, logs, traces, or blind replay |
| H1.2 | Invitation revoke and acceptance reconciliation | H1.1 | Console/BFF/browser tests | expiry, accepted/revoked terminal states, concurrent acceptance, cross-tenant denial | authoritative refresh converges every ambiguous response |
| H1.3 | Member role update/removal | H1.2 | contract, PostgreSQL, Cloud, BFF, Console | `If-Match`, idempotency, last-owner, self-change, contention, response loss | role authority changes atomically and session epochs invalidate stale authority |
| H2.1 | Passkey lifecycle closure | Q2 | PostgreSQL/Cloud/BFF/Console | add/rename/revoke, clone counter, final-auth-path, replayed/expired recent-auth | no user can accidentally remove the final usable authentication/recovery path |
| H2.2 | Human Session lifecycle closure | H2.1 | PostgreSQL/Cloud/BFF/Console | current/other/all-other revoke, idle/absolute expiry, self-revoke, cross-tenant | revoked authority is unusable immediately and UI clears tenant state predictably |
| H2.3 | Console accessibility and remediation pass | H1, H2 | Console UI and Playwright | keyboard, focus, live regions, 200% zoom, reduced motion, Japanese/English stable errors | all expected failure states explain a safe recovery action without requiring CLI access |
| S1.1 | Eight-purpose source-path inventory | Q2 | signer registry/readiness/tests | unique resource/version/fingerprint/domain, no local/file/private-key input | hosted readiness rejects every missing, shared, aliased, stale, or fallback configuration |
| S1.2 | Exact-byte provider reconciliation | S1.1 | provider operation repositories/workers | two-instance contention, response loss, lookup absence, malformed response, process loss | each operation converges to one verified result or durable `uncertain` without re-signing |
| S1.3 | Rotation, disablement, and drain | S1.2 | signer lifecycle/runtime | reserve/start/commit race matrix, active-to-retiring transition, emergency disable, bounded close | no provider call begins after authority reduction and accepted ambiguity is quarantined |
| D1.1 | Freeze onboarding public contract | H2, S1 metadata | catalog/OpenAPI/Core/CLI/native DTOs | generated-validator sync, duplicate/unknown field, canonical vectors, downgrade denial | one versioned contract contains no caller-controlled authority field |
| D2.1 | Loopback and stdin delivery | D1.1 | Console, CLI, native setup state | origin/nonce binding, PNA denial, listener timeout, argv/env/history/storage scans | invitation material exists only in bounded memory or explicit one-shot stdin recovery |
| D2.2 | Durable onboarding resume machine | D2.1 | CLI/native/PostgreSQL/Console reconciliation | interruption at every durable state, expiry, ambiguous POST, duplicate enrollment | restart resumes safely through `control_acknowledged` without duplicate authority |
| M1.1 | Native durable sign-once transaction | D1.1 | broker/XPC/native persistence | process/policy/repository substitution, kill/restart, expiry, unknown outcome | key use occurs once after final re-observation and ambiguous signing is never retried |
| M1.2 | Claude Code lifecycle | M1.1, D2.2 | CLI/adapter/installer/doctor | install/setup/launch/status/close/revoke/uninstall; two unattended verified commits | adapter cannot select a key or widen policy and both commits verify independently |
| M1.3 | Cursor parity | M1.2 | Cursor adapter only | same positive/negative matrix as Claude Code | no new broker selector, signing path, or authority surface is introduced |
| R1.1 | Immutable signed PKG | M1 | release scripts/artifact manifests | hardened runtime, nested signatures, entitlements, SBOM, provenance, Gatekeeper | one digest is Developer ID signed, notarized, stapled, and independently verifiable |
| R1.2 | Distribution and physical qualification | R1.1 | direct download/Homebrew/hardware runners | digest equality, install/upgrade/uninstall/reinstall/rollback; Apple silicon and Intel/T2 | both channels and both hardware reports identify the exact R1.1 digest |
| O1.1 | Staging deployment and resilience drills | Q2, S2, R1 | IaC/deployment/runbooks | migration/canary/drain, restore, outage, compromise, tenant isolation, rollback | measured SLO/RPO/RTO and alert routing meet the reviewed targets |
| O1.2 | Independent review and production record | O1.1 | review findings/promotion evidence | SAST/DAST/dependency/container/IaC, independent assessment, evidence verification | zero unresolved critical/high findings and explicit human go/no-go for the exact candidate |

Execution concurrency after Q2 is limited to three disjoint lanes: H1/H2,
S1/S2, and D1/M1 preparation. Contract catalog changes, migrations, signing
domains, XPC selectors, entitlements, and release identity remain serialized.
No lane may declare another lane qualified from mocked or local-only evidence.

### 12.4 Delivery sequence, parallel capacity, and effort bands

The estimates below are engineering effort, not calendar promises. They exclude
GitHub runner queue time, cloud-account approval, Apple notarization latency,
physical hardware availability, and independent-review scheduling. A range is
re-estimated whenever a protected test exposes a new authority-boundary defect.

| Milestone | Included tickets | Parallel shape | Estimated engineering effort | Start condition | Exit condition |
| --- | --- | --- | --- | --- | --- |
| M0 trustworthy baseline | Q1.3, conditional Q1.4, Q2.1 | one integration owner; no feature merges | 1–4 engineer-days if no new boundary defect | current pushed head | all six CI lanes green on one SHA, retained evidence verified |
| M1 complete human control plane | H1.1–H1.3 and H2.1–H2.3 | invitation/member and passkey/session slices may be implemented in parallel; shared Human DTO and migration changes serialize | 10–18 engineer-days | M0 qualified | full role/WebAuthn browser matrix, response-loss convergence, accessibility and secret scans pass |
| M2 hosted authority + onboarding contract | S1.1–S1.3 in parallel with D1.1 preparation; D1 freezes after H2/S1 metadata | signer lane and device-contract lane; one contract integration owner | 12–22 engineer-days plus protected provider execution | M0 qualified; D1 freeze additionally requires H2 and S1 metadata | eight source paths reconcile exactly; onboarding contract is versioned and downgrade-closed |
| M3 onboarding and native transaction | D2.1–D2.2 and M1.1 | loopback/Console and native persistence can proceed in parallel after D1 | 14–24 engineer-days | D1.1 frozen | interrupted enrollment converges through ACK; native sign-once never retries ambiguity |
| M4 agent adapters and immutable Mac distribution | M1.2–M1.3, R1.1–R1.2 | Claude first, Cursor second; packaging follows broker freeze; hardware runs may execute in parallel | 15–25 engineer-days plus Apple/hardware execution | M3 qualified and signing identities available | two agents and two Mac hardware classes pass on the same notarized PKG digest |
| M5 staging and production adjudication | O1.1–O1.2 | IaC, observability, and review preparation parallelize; migration, promotion, and go/no-go serialize | 12–20 engineer-days plus independent review | M0, protected S2, and R1 qualified | drills meet SLO/RPO/RTO, zero open critical/high findings, signed explicit go/no-go |

With three implementation lanes, the intended steady state after M0 is:

1. **Console/Human lane:** H1 and H2, owning browser journeys and remediation.
2. **Signer/Cloud lane:** S1/S2, owning provider adapters, IAM evidence, and
   reconciliation.
3. **Device/native lane:** D1 preparation followed by D2 and M1, owning the
   loopback protocol, durable setup state, XPC, and adapters.

The integration owner alone merges catalog versions, migrations, public error
codes, signing domains, XPC selectors, entitlements, and release identities.
Each lane returns a reviewable commit with focused tests; integration runs the
cross-lane contract suite before merge. If a lane needs a serialized boundary,
it submits the smallest boundary-only change first and waits for that merge
instead of carrying a private schema fork.

### 12.5 Progress reporting and stop/go rules

At every pushed checkpoint, record the source SHA, completed ticket IDs,
focused test counts, complete-lane status, skipped/external evidence, and the
first safe failure marker. Work stops at the owning boundary when any of these
conditions occurs:

- a migration or public contract would need an incompatible rewrite rather
  than a forward version;
- a test would need reusable secret material in logs, traces, URLs, storage,
  argv, environment, or retained artifacts;
- an ambiguous provider/native signing outcome would be automatically retried;
- a UI would claim success without authoritative PostgreSQL state or a verified
  signed ACK;
- a protected or physical gate is unavailable and a mock would be the only
  evidence.

Work proceeds without product-owner interruption for ordinary implementation
choices inside the frozen boundaries. Explicit approval is required for a new
trust boundary, broader role authority, production credentials, destructive
data migration, release signing, external deployment, or production promotion.

## 13. External requirements and final definition of done

The following cannot be manufactured by source changes: protected AWS/GCP KMS
accounts and IAM evidence, Apple Developer ID Application/Installer and
notarization credentials, one supported Apple silicon Mac, one supported
Intel/T2 Mac, protected staging/production accounts, release approvers, and an
independent security reviewer.

AgentPass v1 is complete only when a new user can install the verified package,
enroll from the browser-led flow, configure Claude Code and Cursor, produce
unattended policy-bound verified commits, inspect and revoke authority in the
Console, recover without single-party takeover, and safely upgrade or remove
the product. The same immutable candidate must pass real PostgreSQL, managed
signer, browser, physical hardware, restore, rollback, and security-review
gates with zero unresolved critical/high finding.
