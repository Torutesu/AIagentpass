# AgentPass production implementation plan — 2026-08-16

Status: active

Planning baseline: `codex/agent-platform` after `e950ea1`

This document converts the v1 architecture into the remaining implementation
and qualification gates. [`V1_EXECUTION_PLAN.md`](./V1_EXECUTION_PLAN.md)
remains the authoritative product definition and release gate. This plan owns
the day-to-day merge order from the current source checkpoint.

## 1. Current source checkpoint

The repository currently has 181 catalog entries, 49 JSON Schemas, 62 OpenAPI
operations, and 70 forward-only PostgreSQL migrations. The implemented source
boundary includes:

- organization-qualified Human identity, roles, sessions, WebAuthn credentials,
  recent authorization, invitations, recovery, and audit foundations;
- PostgreSQL-backed platform signing challenges, sessions, lifecycle fencing,
  provider-operation reconciliation, exact-byte idempotency, and least-privilege
  role qualification;
- a strict Console BFF, organization workspace, passkey management, session
  management, device/control status, emergency actions, and recovery surfaces;
- purpose-separated hosted signer configuration and provider adapters with
  hosted file/private-key fallback rejection;
- resumable headless onboarding, v2 device enrollment, native broker/XPC,
  release-manifest verification, installer and hardware-qualification scaffolding.

This is not production completion. The current branch still needs a terminal
green cross-version CI run, complete browser journeys, protected real-provider
evidence, physical Mac evidence, a signed/notarized artifact, staging drills,
and independent security review.

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

## 4. N1 — terminal qualification closure

Objective: establish one trustworthy source baseline before expanding product
surface.

Implementation work:

1. Make PostgreSQL 16 and 17 apply migrations 0001–0070 from an empty database.
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

1. `test: close postgres platform authority qualification` — finish the active
   PostgreSQL 16/17 CI run and fix every newly exposed authority lane.
2. `test: close protected console identity matrix` — organization switch,
   invitation/role mutations, passkey/session lifecycle, expiry, self-logout,
   tenant substitution, and virtual-WebAuthn tests through real PostgreSQL.
3. `feat: complete organization and identity console` — production UI states,
   accessibility, Japanese errors, pagination/conflict recovery, and no fixture
   fallback.
4. `test: qualify all hosted signer purposes` — purpose-by-purpose real-provider
   IAM/non-exportability, response-loss, rotation, and image/configuration scan.
5. `feat: complete browser-led device onboarding` — complete loopback/PNA and
   stdin recovery journeys, interruption matrix, authoritative receipt/ACK UI.
6. `feat: close claude code native signing transaction` — durable sign-once,
   invalidation races, installer/doctor, and two verified commits.
7. `feat: add cursor adapter parity` — same closed adapter protocol and full
   negative matrix, with no new authority path.
8. `build: publish immutable notarized candidate` — Developer ID signatures,
   notarization/stapling, SBOM/provenance, direct download, and Homebrew.
9. `test: qualify physical mac release candidate` — Apple silicon and Intel/T2
   reports for the exact candidate digest.
10. `ops: deploy staging and close production review` — restore/rollback/outage
    drills, independent review, signed promotion record, then explicit go/no-go.

Each queue item is a reviewable commit or short ordered series. Every push runs
its focused tests plus contract validation, lint, root/Console/native suites,
and `git diff --check`; boundary-specific PostgreSQL, browser, provider,
packaging, or physical tests are added as required.

## 12. External requirements and final definition of done

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
