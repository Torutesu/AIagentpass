# Hosted v1 implementation plan

Status: active  
Baseline: `codex/agent-platform` at migration `0063`
Updated: 2026-08-15

This is the implementation plan for the Hosted identity, first-organization,
WebAuthn, Console, Device API, managed signer, and production qualification
path. It refines P2-P6 in `EXECUTION_PLAN.md`; the frozen public behavior remains
defined by `HOSTED_IDENTITY_BOOTSTRAP_V1.md` and its machine-readable contract.

## 1. Current checkpoint

Implemented and pushed:

- frozen six-route Hosted bootstrap contract and validator;
- GitHub OAuth adapter with server-side exchange, exact endpoint pinning,
  bounded streaming responses, numeric subject normalization, PKCE/state, and
  redacted errors;
- strict HTTP boundary for Origin, CSRF, cookie, query, body, and response
  handling;
- migration `0057` for durable OAuth/bootstrap/idempotency/WebAuthn state;
- function-only runtime authority for Hosted tables and least-privilege checks;
- PostgreSQL adapter for all ten `0057` procedures, hashing every raw selector
  before SQL and using database-clock results.
- migration `0058` and its v2 PostgreSQL adapter for exact state/code/redirect
  claim, one-use encrypted PKCE envelopes, and function-only runtime access;
- AES-256-GCM PKCE codec with version/key/attempt/state/redirect/expiry AAD,
  strict envelope parsing, rotation-capable key resolution, and redacted errors;
- durable OAuth state-store composition and an internal callback envelope that
  keeps `{provider, subject}` separate from server-generated attempt context.
- migration `0059` atomic identity completion with subject serialization,
  immutable mapping resolution, orphan-free member creation, database-owned
  membership-history classification, and one-transaction OAuth consumption.
- migration `0060` atomic first-organization creation with normalized-name
  request binding, complete membership-history locking, one owner membership,
  immutable idempotency replay, initial audit-chain event, and transition to
  `webauthn_required`.
- migration `0062` and its Hosted WebAuthn service atomically commit the first
  verified credential and ordinary Human Session with database-owned identity,
  epochs, session ID, limits, and timestamps. A digest-only, one-use receipt
  supports a two-minute response-loss retry without storing bearer values;
- migration `0063` adds deterministic, digest-only WebAuthn verification claims
  with a database-owned 30-second lease, monotonic generation fencing, safe
  same-response restart, expired-lease takeover, claim-bound completion/failure
  entry points, and append-only claim lifecycle evidence;
- the frozen catalog validates 173 entries, 49 schemas, 61 OpenAPI operations,
  and all 63 forward-only migrations. Hosted bootstrap remains a separately
  frozen six-route contract with its own validator.

Not yet implemented as a production-composable path:

- real-PostgreSQL restart/race qualification of the new PKCE/state boundary;
- real-PostgreSQL restart/race qualification of atomic identity completion;
- real-PostgreSQL restart/race and rollback qualification of atomic WebAuthn
  credential plus Human Session completion;
- real-PostgreSQL qualification of leased/recoverable WebAuthn verification
  claims under process death, lease expiry, takeover, and changed responses;
- runtime routing, Console pages, deployed E2E, and production evidence.
- a terminal green CI qualification at schema head `0063`; the previous run
  proved fresh migration and role/login boundaries, and this repair set aligns
  legacy 0048 authority, shared-integration fixtures, and live-browser budgets.

## 2. Security invariants

1. Browser input never selects member, organization, membership, role, provider
   subject, RP ID, Origin, key, session authority, or timestamps.
2. OAuth state, authorization code, bootstrap cookie, CSRF token, WebAuthn
   challenge, access token, and PKCE verifier never enter logs, metrics, URLs,
   durable browser storage, or public DTOs.
3. PostgreSQL owns attempt state, expiry, replay, membership-history decisions,
   idempotency, and every authority transition. Application clocks cannot
   extend authority.
4. A normal Human Session cannot exist unless the credential row and consumed
   bootstrap challenge are committed in the same database transaction.
   Compensating revocation is not an acceptable substitute for atomic commit.
5. Revoked membership history does not mean a user is new. It produces the
   fixed `no_membership` outcome and requires invitation or recovery.
6. Hosted runtime roles call reviewed security-definer procedures only; direct
   Hosted table DML and local/evaluation identity fallbacks remain denied.
7. Unknown, ambiguous, timed-out, or malformed outcomes fail closed with stable
   public errors and retain only bounded, non-secret operational evidence.

## 3. Dependency graph

```text
H1 durable OAuth coordinator ----+
                                +--> H3 bootstrap HTTP/runtime --> H5 Console/E2E
H2 atomic bootstrap authority ---+                |
                                                  +--> H4 organization/session UI

H6 Device API/helper -----------+--> H8 Agent E2E --> H10 production
H7 managed cloud signers -------+
H9 signed/notarized distribution -----------------+
```

H1 and H2 share migration/procedure contracts and merge serially. Console,
Device, signer infrastructure, and packaging may proceed in parallel after
their consumed contracts are frozen. Production claims require one source SHA
and one immutable artifact set across all lanes.

## 4. Merge-sized implementation packages

### H1 — restart-safe OAuth coordinator

State: implementation complete locally; real PostgreSQL 16/17 and two-instance
qualification pending.

Deliverables:

1. Add an encrypted, purpose-bound PKCE verifier envelope or a dedicated
   short-lived server store. Persist only ciphertext, key version, nonce,
   attempt ID, OAuth-state ID, exact redirect URI, and expiry; never plaintext.
2. Make `start` create attempt/state and verifier envelope atomically enough
   that no redirect is returned unless durable correlation exists. On partial
   failure, make the state unusable.
3. Make callback consume the exact state before provider calls, decrypt the
   verifier only in memory, exchange the code once, bind the returned numeric
   subject to the consumed OAuth-state ID, and erase verifier material on every
   terminal path.
4. Keep the public identity DTO exactly `{provider, subject}`. Carry attempt
   context in a separate internal envelope that cannot be serialized by the
   HTTP response mapper.
5. Add bounded stale-`consuming` recovery. Recovery may fail or safely resume a
   known provider operation; it must never blindly exchange the same code twice.

Tests: restart between redirect/callback, wrong state/redirect/PKCE/key version,
duplicate callback, response loss, verifier corruption, provider timeout,
oversized response, concurrent callbacks, log/metric scans, and expiry under a
database clock.

Exit: two API instances accept at most one callback for one state, a restart
does not lose valid correlation, and no plaintext verifier/token is durable.

### H2 — atomic identity and first-organization authority

State: source implementation complete through migrations `0059` and `0060`;
the `0061` forward repair is ready for exact PostgreSQL 16/17 qualification.

Deliverables:

1. Add one reviewed transaction procedure/service operation that resolves or
   creates `members` plus immutable `upstream_identities`, validates the exact
   provider subject, completes the consuming OAuth state, rotates the bootstrap
   selector, and returns only attempt state and expiry.
2. Lock membership history for the member. Classify zero rows as
   `organization_required`, any active row as `identity_verified`, and
   revoked-only history as `no_membership`.
3. Add one transaction that normalizes the organization name, creates the
   organization and server-derived owner membership, commits the exact
   idempotency response, advances the attempt to `webauthn_required`, and emits
   immutable audit evidence.
4. Reconcile existing organization/member repository semantics rather than
   duplicating role, last-owner, epoch, or audit rules in HTTP code.

Tests: same-subject contention, upstream mapping substitution, orphan member,
revoked history, active/multiple memberships, same/different idempotency key,
response loss, cross-attempt cookie, stale attempt, rollback at every write,
and two-pool convergence.

Exit: one verified subject maps to one immutable member; first organization
creation converges to one organization and one owner membership.

### H3 — atomic bootstrap WebAuthn and Human Session issuance

State: migrations `0062` and `0063`, PostgreSQL repository adapter,
strict-verifier service, one-use response-recovery receipt, deterministic claim
lease with generation fencing, append-only claim evidence, and focused tests
are implemented in source. Real PostgreSQL 16/17,
two-instance contention, and process-kill qualification remain before this
package is production-composable.

Deliverables:

1. Reuse the production registration verifier for exact challenge, RP ID,
   HTTPS Origin, UV-required, credential ID, public key, transports, backup
   state, and sign counter validation.
2. Keep options generation separate and read only authority-derived member and
   organization bindings from `0057`.
3. Implement one transaction coordinator that locks the consuming challenge
   and attempt, inserts the credential, resolves the active owner membership,
   snapshots organization/membership/session epochs, inserts the Human Session,
   consumes the challenge, completes the attempt, and rotates/clears bootstrap
   selectors before commit.
4. Return Session and CSRF cookies only after commit. A process kill before
   commit leaves no credential or usable Session; response loss permits a
   bounded, selector-bound result lookup without repeating verification.

Tests: cross-attempt challenge, replay, RP/Origin/UV substitution, cloned
credential, duplicate credential race, verifier timeout, process kill before
each write/commit/response, stale membership/epoch, response loss, and cookie
rotation/clear semantics.

Exit: there is no database state containing a usable ordinary Session without
the matching credential and completed bootstrap ceremony.

### H4 — runtime wiring and complete Hosted API

Deliverables:

1. Compose H1-H3 in the hosted runtime with exact startup configuration,
   readiness, rate limiting, deadlines, graceful drain, and no evaluation
   fallback.
2. Implement status, CSRF issuance, first-organization creation, WebAuthn
   options, and verify handlers behind the already frozen six-route boundary.
3. Add schemas/OpenAPI/catalog fixtures only where they match the frozen v1
   route inventory; reject aliases and legacy identity assertions.
4. Emit fixed-cardinality metrics and immutable audit events without selectors,
   subjects, credentials, tokens, or provider bodies.

Exit: hosted startup fails on missing identity/database/key configuration and
all six routes run against real PostgreSQL with least-privilege roles.

### H5 — Console onboarding and organization controls

Deliverables:

1. Build GitHub sign-in, bootstrap status, first organization, passkey setup,
   recovery/error, and authenticated landing states using one typed BFF client.
2. Continue with organization switcher, member invitations, role changes,
   sessions, credentials, devices, Agent Sessions, activity, and emergency
   revocation. Role decisions remain server-authoritative.
3. Cover keyboard, screen reader, reduced motion, narrow/wide layouts, Japanese
   and English copy, retry, stale state, offline, response loss, and recovery.
4. Scan URL, DOM, console, network metadata, local/session storage, IndexedDB,
   Cache Storage, screenshots, and retained traces for reusable authority.

Exit: a new user can complete Hosted onboarding without CLI-only knowledge;
Owner/Admin/Auditor/Viewer each see and can invoke only allowed operations.

### H6 — PostgreSQL Device API and headless helper

Deliverables:

1. Finish invitation, possession proof, enrollment completion, signed control
   bundles, monotonic ACK, refresh, wake, reconnect, revoke, and repair against
   PostgreSQL authority.
2. Keep macOS delivery headless-first: signed PKG, native broker/XPC, CLI, Git
   helper, Claude Code adapter, and Cursor adapter. A menu-bar app remains an
   optional later convenience layer.
3. Create/reuse non-exportable Secure Enclave P-256 keys, bind local requests to
   peer/process/repository/worktree/branch/operation/budget/TTL, and revalidate
   immediately before signing.

Exit: install and browser-led setup complete on supported physical Macs, and
revocation reaches the helper within the measured bound.

### H7 — production managed signers

Deliverables:

1. Provision purpose-separated non-exportable AWS KMS/GCP KMS-class keys for
   control, capability, Human assertion, enrollment receipt, audit checkpoint,
   release/evidence, promotion, and any remaining frozen purpose.
2. Pin provider, region, resource, algorithm, public-key fingerprint, lifecycle
   version, and IAM identity; hosted readiness rejects local/file fallback.
3. Complete PostgreSQL idempotency, fencing, rotation overlap, disablement,
   throttle/outage handling, and accepted-but-response-lost reconciliation.

Exit: two instances under contention produce one verified committed result per
operation, and private key bytes never enter AgentPass hosts or artifacts.

### H8 — Claude Code and Cursor E2E

Run each agent through setup, two unattended signed commits, independent
`git verify-commit`, budget exhaustion, malicious sibling process, repository
substitution, 100-request contention, daemon restart, network loss, Cloud
response loss, audit failure, revocation during signing, and a blocked next
commit. Both adapters consume the same frozen local protocol.

### H9 — signed distribution and physical-Mac matrix

Produce one immutable universal or architecture-paired PKG, sign nested code
and installer identities, notarize, staple, verify Gatekeeper, and distribute
the same digest by direct download and Homebrew. Qualify clean install, upgrade,
rollback, uninstall-preserve, reinstall, and explicit purge on Apple
silicon/Secure Enclave and supported Intel/T2 hardware.

### H10 — production qualification and rollout

Deploy immutable Console/API/worker images, managed PostgreSQL, TLS/DNS/rate
limits, managed signers, telemetry, alerts, backups, and restore automation.
Run canary, drain, rollback, PITR, signer/database outage, emergency stop,
owner recovery, incident response, dependency/SBOM/secret/parser review, and
independent security review. Close all critical/high findings before promotion.

## 5. Parallel execution order

1. Serialize H1 then H2/H3 database contract changes.
2. After H1 DTOs freeze, run H4 runtime and H5 read-only UI in parallel.
3. Run H6 Device/helper, H7 signer infrastructure, and H9 packaging harnesses
   in parallel; do not claim completion until real hardware/cloud evidence is
   attached to the same source SHA.
4. Merge H2-H4, then enable H5 authority-changing journeys and complete the
   real PostgreSQL/browser matrix.
5. Freeze one release candidate, run H8 on it, then use that unchanged candidate
   for H9 physical qualification and H10 staging/production promotion.

## 6. Required gate for every merge

- focused positive and negative unit tests;
- contract/catalog/schema-head validation and `git diff --check`;
- lint plus complete Node/Console/Swift/package suites appropriate to scope;
- fresh and upgrade PostgreSQL 16/17 migration tests and negative privilege
  checks for SQL changes;
- two-instance/replay/response-loss/process-kill tests for authority changes;
- browser accessibility and secret-storage scans for Console changes;
- startup/readiness/drain and no-fallback tests for runtime/provider changes;
- source-bound, sanitized evidence that distinguishes mocked, local, staging,
  managed-cloud, browser, simulator, and physical-hardware results.

## 7. Immediate commit queue

Each item is independently reviewable and must leave `main` deployable. SQL
authority changes are forward-only; a pushed migration is never rewritten.

1. `fix: restore postgres privilege qualification` — implemented
   - add the missing relation-kind projection used by bounded diagnostics;
   - run the static checker tests, lint, PostgreSQL 16/17 fresh migration,
     seeded upgrades, login-boundary checks, and P0-B live process;
   - exit only when the same pushed SHA is green in GitHub Actions.
2. `feat: atomically bind hosted identity and oauth completion` (`0059`) — implemented
   - add `agentpass_hosted_identity_oauth_complete_v2` with server-generated
     OAuth-state ID, bootstrap-cookie digest, candidate member ID, verified
     provider/subject, and subject digest;
   - take a transaction-scoped advisory lock derived from provider/subject,
     lock the consuming OAuth state and attempt, resolve the immutable mapping,
     create a member only when absent, and prevent orphan members under races;
   - classify membership history in PostgreSQL and commit `consumed` plus
     `organization_required`, `identity_verified`, or `no_membership` in the
     same transaction; return only attempt ID, state, organization count, and
     database expiry;
   - replace caller-selected `member_id` completion in the repository and
     callback coordinator; remove runtime EXECUTE on the legacy completion
     function while retaining it only as non-callable migration history.
3. `test: qualify atomic hosted identity completion` — implemented in source;
   head-61 CI qualification is the current gate
   - add PostgreSQL 16/17 tests for same-subject contention, different-subject
     concurrency, mapping substitution, active/multiple/revoked memberships,
     stale/duplicate callbacks, rollback after each write, and two-pool
     convergence;
   - assert no duplicate/orphan member, no reusable OAuth state, no direct
     Hosted-table DML, and no subject/token/cookie in evidence or logs.
4. `feat: atomically create the first hosted organization` (`0060`) — implemented
   - normalize names server-side, lock the member and complete membership
     history, require the exact `organization_required` attempt, and generate
     organization/membership IDs on the server;
   - insert organization plus active owner membership, store a secret-free
     canonical idempotency result, emit the audit event, and advance to
     `webauthn_required` in one transaction;
   - make same-key replay byte-equivalent and different-key contention return a
     stable conflict without creating a second organization.

Implemented checkpoint (2026-08-15): migration `0060` adds a function-only
first-organization boundary. It validates the normalized name and its SHA-256
request binding, locks the exact bootstrap attempt and complete member history,
creates the organization plus active owner membership, derives the public replay
object, appends the initial admin audit-chain event, and advances the attempt to
`webauthn_required` in one PostgreSQL transaction. The application role loses
EXECUTE on the legacy caller-payload function and receives only the v2 entry
point. Real PostgreSQL contention and response-loss qualification remains part
of the same commit gate.
5. `fix: qualify hosted OAuth output-column resolution` (`0061`) — implemented
   - preserve both frozen v2 function signatures while pinning PL/pgSQL column
     resolution for `RETURNS TABLE` names that also exist as physical columns;
   - retain function-only deployment authority and qualify the fix on fresh and
     upgraded PostgreSQL 16/17 databases.
6. `feat: commit bootstrap webauthn and human session atomically` (`0062`) — implemented in source; PostgreSQL qualification pending
   - reuse the production verifier and pass only its strict verified result to
     a transaction procedure;
   - lock attempt/challenge/membership/epochs, insert the credential and Human
     Session, consume the challenge, complete the attempt, and clear bootstrap
     authority before commit;
   - persist a one-use response-loss receipt so retry can recover cookies
     without re-registering or creating a second session.
   - PostgreSQL generates the session ID and owns the eight-hour absolute,
     30-minute idle, and five-session limits; the caller supplies no tenant,
     role, epoch, session identifier, timestamp, or lifetime authority;
   - derive response bearer values from an exact-response HMAC binding so the
     same committed session can be reconstructed once during the two-minute
     window without durably storing plaintext bearer material.
7. `feat: fence hosted webauthn verification claims` (`0063`) — implemented
   - bind external verification to a deterministic digest-only 30-second lease
     owned by the PostgreSQL clock, never to raw browser-visible authority;
   - return and require a monotonic claim generation on completion and failure,
     so a worker from an expired generation cannot mutate a reclaimed ceremony;
   - preserve same-response restart and one-use response-loss recovery while
     rejecting changed responses and ambiguous claims;
   - append immutable claimed/takeover/completed/replayed/failed/expired events
     and remove application-role table reads in favor of reviewed functions;
   - focused source tests are green; PostgreSQL 16/17 fresh/upgrade,
     two-instance contention, process-kill, and rollback qualification remain
     mandatory CI gates before production use.
8. `feat: expose hosted bootstrap status and csrf authority` (`0064`)
   - add function-only status/CSRF procedures that derive state, membership,
     organization, WebAuthn requirement, expiry, and completion from the exact
     bootstrap selector under a database clock;
   - derive the browser CSRF value from a dedicated stable server key and exact
     attempt binding, persist only its digest, use constant-time comparison at
     the application boundary, and rotate/clear it on terminal transitions;
   - compose a single bootstrap service exposing `status`, `verifyCsrf`, and
     `createOrganization`, with stable 401/403/409/428/503 classifications and
     no SQLSTATE or selector leakage;
   - exit when restart, multiple API instances, stale cookie, wrong CSRF,
     response loss, and direct-table privilege tests converge on PostgreSQL.
9. `feat: compose hosted bootstrap runtime routes`
   - construct the Hosted repository in PostgreSQL runtime, then compose GitHub
     OAuth, identity, status/CSRF, organization, WebAuthn, and HTTP services in
     dependency order with no local/evaluation fallback;
   - require separate stable keys for OAuth envelopes, bootstrap CSRF, WebAuthn
     response recovery, and ordinary Human Auth; fail startup on omission,
     aliasing, malformed length, or unsupported hosted profile;
   - adapt operation- and peer-scoped rate limiting to the HTTP boundary,
     enforce deadlines/readiness/drain, and dispatch all six exact routes before
     Human Auth without pre-consuming request bodies or writing twice;
   - add request correlation and fixed-cardinality secret-free telemetry, then
     prove cookie rotation, redirects, multiple `Set-Cookie`, strict path/query,
     404 fallthrough, restart, and two-instance behavior at the real server.
10. `feat: build hosted console onboarding`
   - implement GitHub start/callback recovery, first-organization, passkey,
     completion, expired, no-membership, and authenticated landing screens;
   - use HttpOnly/Secure/SameSite cookies and in-memory UI state only; add
     keyboard, screen-reader, reduced-motion, mobile, Japanese, and English
     coverage;
   - then add organization switcher and the role-gated member/session/device/
     agent/activity/revocation screens against existing Human APIs.
11. `test: qualify hosted browser and restart security matrix`
   - exercise two API instances plus PostgreSQL under restart, callback replay,
     response loss, concurrent tabs, stale cookies, Origin/CSRF substitution,
     WebAuthn replay, and network/provider failure;
   - scan URL, DOM, console, storage, traces, screenshots, metrics, and audit
     payloads for reusable selectors and credentials.
12. `feat: complete device helper and managed signer production paths`
   - finish PostgreSQL Device API enrollment/control/ACK/revocation and the
     headless signed PKG + CLI + Git/Claude Code/Cursor adapters;
   - replace every hosted signing fallback with purpose-separated managed KMS
     keys and qualify idempotency, fencing, rotation, outage, and response loss.
13. `release: qualify and promote one immutable agentpass candidate`
    - freeze one source SHA and artifact manifest; run Claude Code/Cursor E2E,
      physical-Mac Secure Enclave/T2 tests, Developer ID signing, notarization,
      stapling, Gatekeeper, Homebrew/direct-download digest equality, staging,
      canary, rollback, PITR, emergency stop, and independent security review;
    - promote only that unchanged candidate with no open critical/high finding.

### Execution lanes and merge order

- Critical path: schema-head qualification -> `0062`/`0063` PostgreSQL
  race/rollback/lease qualification -> runtime composition ->
  Console onboarding -> Hosted E2E.
- Parallel lane A after `0059` freezes DTOs: read-only Console states, typed BFF
  client, accessibility harness, localization, and browser secret scanner.
- Parallel lane B now: Device API/helper correctness and physical-Mac harness.
- Parallel lane C now: managed signer provisioning adapters, provider-operation
  qualification, packaging/notarization automation, and production runbooks.
- Integration rule: database migrations merge serially; parallel code consumes
  frozen contracts; production evidence is accepted only when every lane names
  the same source SHA and immutable artifact digests.

### Milestone gates

- M1 Identity-safe: H1/H2 green on PostgreSQL 16/17 and two instances.
- M2 Account-ready: first organization, passkey, and Human Session are atomic.
- M3 Console-ready: non-engineer onboarding and organization controls pass the
  browser accessibility/security matrix.
- M4 Agent-ready: Device API, helper, Claude Code, Cursor, and managed signers
  pass unattended signing, contention, restart, and revocation tests.
- M5 Production-ready: signed/notarized distribution, restore/rollback,
  independent review, and one immutable release candidate all pass.

## 8. Production definition of done

Hosted v1 is complete only when a non-engineer can create an account and
organization, register a passkey, enroll a supported Mac, configure Claude Code
and Cursor, and obtain verified unattended signed commits while all private
keys remain non-exportable. Revocation must block the next operation within a
measured bound; restore and rollback must be rehearsed; the exact signed and
notarized artifact must pass independent review with no unresolved critical or
high finding. Local mocks, green unit tests, unsigned packages, skipped cloud
tests, or simulator-only evidence do not satisfy this definition.
