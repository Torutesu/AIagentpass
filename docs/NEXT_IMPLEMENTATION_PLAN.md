# AgentPass next implementation plan

Status: active  
Baseline: `5a5842c` (`codex/agent-platform`)  
Planning date: 2026-08-14

## 1. Target release

The first production release is a headless-first AgentPass distribution for Claude Code and Cursor. A user installs one signed and notarized macOS package, completes organization and device enrollment through the browser Console or CLI-guided browser flow, and then lets an approved agent perform policy-bound signing without repeated human prompts. Private signing keys remain non-exportable in Secure Enclave or the platform hardware boundary. Human operators can inspect, reduce, revoke, recover, and audit authority from the Console.

The primary macOS delivery is not a required menu-bar application. The release artifact is one immutable Developer ID-signed and notarized PKG containing the native broker, XPC services, launchd jobs, CLI, Git helper, and agent adapters. Direct download and a Homebrew bootstrap install the same PKG and verify the same manifest. A native onboarding application may be added later as a convenience client, but it must not become a second security or protocol implementation.

## 2. Current implemented boundary

The current branch has the versioned Core/OpenAPI/JSON Schema catalog, 31 forward-only PostgreSQL migrations, tenant-qualified hosted repositories, Human sessions and organization roles, WebAuthn registration/authentication and operation-bound recent authorization, Device API foundations, signed control bundles and ACK state, audit ingestion, emergency revocation, threshold-owner recovery, and a secret-free recovery-notification outbox with dead-letter management primitives.

At the `5a5842c` checkpoint, recovery dead-letter redrive and suppression require an exact resource-bound WebAuthn context. The repository recomputes that context and consumes the proof in the same organization-locked transaction. The full suite passes with 1,682 tests (1,648 pass and 34 intentionally skipped), lint and contract validation pass, and all 31 migrations apply to PostgreSQL 16.

This is not yet a production release. Browser qualification, complete Console operations, managed production signers, physical Mac qualification, signed/notarized artifacts, deployment infrastructure, restore drills, and independent security review remain open.

## 3. Delivery rules

1. Every authority-changing commit lands with negative tests for replay, tenant substitution, stale versions, actor substitution, malformed input, response loss, and concurrent execution where applicable.
2. OpenAPI, JSON Schema, SQL migrations, signing domains, XPC selectors, native durable state, entitlements, and release identities have one integration owner and change serially.
3. UI success means authoritative PostgreSQL state or a verified signed device ACK, not merely a successful browser request.
4. Browser storage, URLs, telemetry, logs, crash reports, argv, environment variables, shell history, and repository files must never contain reusable credentials, assertions, capability tokens, recovery material, or private keys.
5. Evaluation-mode file stores and file signers remain explicit and fail closed in hosted mode. They are never a production fallback.
6. A modeled, mocked, skipped, or simulator-only test is labeled as such and never promoted as physical or production evidence.
7. Each merge-sized slice updates relevant threat-model claims, operator documentation, and the evidence index in the same commit.

## 4. Critical path and merge-sized execution plan

### W0 — close recovery dead-letter operations

State: in progress.

Merge slices:

1. Add real-PostgreSQL qualification for context mismatch, cross-tenant access, consumed-proof replay, concurrent proof consumption, stale management-version races, and semantic idempotent retry with a fresh WebAuthn proof.
2. Add a strict Console/BFF client for dead-letter list, redrive, and suppress. Validate exact response shapes; forward only allow-listed session, Origin, CSRF, `If-Match`, idempotency, and recent-auth controls.
3. Add an Owner/Admin operations surface with loading, empty, error, pagination, conflict refresh, retry-attempt visibility, redrive confirmation, suppression reason, and injected WebAuthn step-up.
4. Add browser tests for role visibility, keyboard operation, stale-version recovery, one-use recent-auth, request retry, and absence of sensitive material in storage and rendered output.

Exit gate:

- unit, Console, contract, and real-PostgreSQL suites pass;
- two concurrent mutations produce one committed result and one stable conflict/replay result;
- another tenant receives the same not-found surface as an absent resource;
- an exact semantic retry can use a fresh WebAuthn authorization without duplicating the mutation;
- the UI never claims success before the returned authoritative version is accepted.

### W1 — finish recovery delivery and abuse resistance

Depends on W0.

Merge slices:

1. Run the recovery notification worker with PostgreSQL leases, bounded exponential backoff, deterministic idempotency, poison-message isolation, and crash-safe lease recovery.
2. Define provider adapters that accept only secret-free notification DTOs. Reject provider responses that echo credentials or unexpected payload fields.
3. Add dead-letter retention, suppression retention, redrive-attempt ceilings, bounded pruning, and immutable audit records for all operator actions.
4. Complete shared PostgreSQL throttles for login, WebAuthn, recovery creation/approval/exchange, and management mutations; add concurrent-session ceilings and organization session epochs.
5. Add metrics for queue age, attempts, dead-letter count, suppression, redrive success, rate denial, and recovery state latency without member PII or secret-bearing labels.

Exit gate:

- two workers cannot deliver the same logical notification twice;
- kill/restart at lease, provider-call, commit, and response-loss boundaries converges safely;
- provider outage cannot block authority transactions or widen authority;
- recovery enumeration, replay, race, and notification substitution tests pass across two API instances.

### W2 — production Console journey and browser qualification

Depends on W1 for recovery screens; read-only work may proceed in parallel.

Merge slices:

1. Remove remaining sample operational state. Every organization, member, session, credential, device, policy, agent, activity, recovery, and emergency state must come from an authenticated BFF response.
2. Complete the guided journey: sign in/passkey, organization selection/create, invitations and roles, device enrollment, repository policy, Claude Code/Cursor setup, sessions, activity, revoke, emergency stop, recovery, and purge.
3. Centralize strict DTO parsing, cursor handling, stale-version reconciliation, authorization visibility, no-store behavior, and stable localized error mapping.
4. Add Playwright virtual-WebAuthn matrices for Owner/Admin/Auditor/Viewer, session expiry/revocation, organization switch, CSRF/origin rejection, conflict refresh, recovery, and destructive confirmations.
5. Add accessibility and responsive gates: keyboard-only completion, focus restoration, dialog semantics, live-region behavior, reduced motion, 200% zoom, and mobile-safe recovery.
6. Inspect browser bundles, DOM, local/session storage, IndexedDB, Cache Storage, logs, traces, and screenshots for forbidden material.

Exit gate:

- all supported role journeys pass in Chromium and WebKit, with Firefox included where virtual-authenticator support permits;
- no production screen falls back to fixture/sample data;
- production browser requests contain no Cloud operator bearer token;
- CSP, HSTS, same-origin BFF, cookie, Origin, CSRF, redirect, and cache tests pass.

### W3 — purpose-separated managed signers

May prepare behind disabled hosted feature gates while W2 runs. Production enablement depends on W2.

Merge slices:

1. Freeze a provider-neutral signer interface for capability, ControlBundle, refresh hint, possession receipt, Agent Session Grant, qualification manifest, audit anchor, and promotion evidence purposes.
2. Give each purpose a separate workload identity and KMS/HSM key. The caller cannot select an arbitrary key, purpose, algorithm, or signing domain.
3. Persist immutable key ID/version metadata and implement active, retiring, revoked, and emergency-disabled states with bounded verification overlap.
4. Preserve exact committed signed bytes for idempotent response-loss retries; never re-sign the same authority mutation on retry.
5. Implement timeout, throttling, circuit-breaker, health, rotation, restore, compromise, and no-file-fallback behavior.

Exit gate:

- IAM tests prove cross-purpose and key-export denial;
- rotation preserves required historical verification and prevents new signing with retired keys;
- outage, malformed provider responses, partial rotation, database rollback, and response loss fail closed;
- hosted startup refuses file-backed signers or incomplete purpose mappings.

### W4 — headless macOS onboarding and agent adapters

Depends on stable hosted Device/Human APIs and signer contracts from W2–W3.

Merge slices:

1. Finish one resumable state machine shared by CLI and any future native UI: verify artifact, initialize broker, enroll device, bind organization, install policy, connect agent, run signed-commit self-test.
2. Complete `agentpass install`, `setup`, `doctor`, `launch`, `status`, `close`, `revoke`, `uninstall`, and explicit `purge` behavior with repair guidance and secret-free machine-readable output.
3. Complete the Claude Code adapter first. Pin executable identity/version, process ancestry, repository/worktree, branch/ref, operation, TTL, policy generation, and capability budget.
4. Add Cursor parity only after the same Claude Code authority lifecycle passes. Keep adapters thin and route signing through the same native broker transaction.
5. Complete refresh-hint/polling, atomic ControlBundle installation, applied/blocked ACK, offline expiry, audit upload, emergency stop, and crash recovery.
6. Test install, upgrade, rollback refusal, uninstall-preserve, reinstall-recover, and current-user purge across interruption points.

Exit gate:

- each adapter performs two unattended commits verified with `git verify-commit`;
- revocation, expiry, process death, executable substitution, PID reuse, ancestry substitution, repository/worktree substitution, and concurrent budget exhaustion fail closed;
- no private key or reusable authority crosses Secure Enclave/Keychain/XPC boundaries;
- secrets are absent from argv, environment, stdin, shell history, repository files, logs, and crash reports.

### W5 — immutable macOS distribution and hardware qualification

Depends on W4.

Merge slices:

1. Build one universal hardened-runtime PKG containing the broker, XPC services, launchd jobs, CLI, Git helper, and adapters.
2. Sign all nested code with the fixed Developer ID team and entitlements, notarize, staple, and independently verify the final archive.
3. Generate checksums, SBOM, provenance, nested code-identity manifest, and a signed release manifest. Direct download and Homebrew install the same immutable PKG.
4. Execute clean-machine install, enroll, Claude Code/Cursor commit, audit, revoke, offline expiry, recovery, upgrade, uninstall, reinstall, and purge journeys.
5. Run the protected fault/identity matrix on Apple silicon with Secure Enclave and Intel with T2 against the exact same artifact digest.

Exit gate:

- untouched signed reports from both hardware lanes bind source commit, PKG digest, Team ID, nested CodeDirectory identities, notarization ticket, OS/hardware, Cloud image/schema, and signer key versions;
- all required negative identities fail before the privileged selector;
- teardown proves no residual qualification listener, authority, grant, or mutable candidate remains;
- Homebrew and direct-download verification resolve to the same release manifest and PKG digest.

External requirements: Apple Developer Program credentials, Developer ID Application/Installer identities, notarization credentials, and physical Apple silicon and Intel/T2 machines. These gates cannot be replaced with mocks.

### W6 — hosted staging and production deployment

Infrastructure preparation may run beside W4–W5. Promotion depends on W3 and W5.

Merge slices:

1. Provision isolated development, staging, and production accounts; private PostgreSQL connectivity; workload identity; KMS/HSM; object storage; DNS/TLS; WAF/rate limits; and protected migration and release roles.
2. Build immutable Console, API, and worker images. Apply migrations as an explicit one-writer stage with compatibility preflight, canary, graceful drain, traffic rollback, and forward-fix procedure.
3. Configure encrypted backups, PITR, retention, cross-failure-domain copies, scheduled restore verification, and authority-manifest comparison.
4. Add SLO-derived metrics and alerts for authentication, WebAuthn, enrollment, signer latency/error, stale bundles, ACK lag, stop propagation, audit gaps, outbox lag, DB saturation, migration drift, and backup age.
5. Complete redaction review, dependency scanning, SAST, DAST, container/IaC scanning, load/failure tests, incident runbooks, on-call ownership, and disclosure procedures.
6. Commission an independent security review, remediate every critical/high finding, and record accepted lower findings with owner and deadline.

Exit gate:

- staging restore and rollback drills meet measured RPO/RTO;
- multi-instance race, region/provider outage, KMS rotation, DB failover, queue backlog, and emergency-disable exercises pass;
- one signed promotion record binds the commit, images, PKG, migrations, signer versions, SBOM/provenance, browser E2E, restore drill, security review, and both hardware reports;
- there are zero unresolved critical/high findings and no undocumented security exceptions.

## 5. Parallel work lanes

| Lane | May proceed now | Serialization boundary |
| --- | --- | --- |
| Recovery data/API | W0 PostgreSQL qualification and W1 worker design | migrations, recovery state machine, recent-auth context |
| Console | W0 client/UI and W2 read-only journeys | Human DTOs, BFF security policy, destructive enablement |
| Managed signers | W3 provider adapters behind disabled gates | signing domains, key metadata, hosted activation |
| Native | W4 CLI/adapter tests against frozen contracts | XPC selectors, entitlements, durable state, code identities |
| Release/operations | CI, SBOM, IaC, runbook preparation | artifact digest, production credentials, promotion record |

The integration owner reviews every serialized boundary before dependent lanes resume. Parallel agents use disjoint file ownership and return changes for central review; they do not merge, migrate, or widen a security contract independently.

## 6. Commit and verification cadence

Each slice should be one reviewable commit or a short, ordered commit series. The minimum local gate is:

```text
npm run contracts:validate
npm run lint
npm test
npm run test:native
npm run test:native-app
npm run test:native-installer-preservation
npm test --prefix apps/web-console
npm run lint --prefix apps/web-console
git diff --check
```

Add real PostgreSQL, two-instance, Playwright, KMS/IAM, packaging/notarization, restore, and physical-hardware gates whenever the changed boundary requires them. A commit is pushed only after its applicable gates pass; a production claim is made only after the external evidence is attached.

## 7. Immediate commit queue

1. `test: qualify recovery dead-letter authorization in postgres`
2. `feat: add strict recovery dead-letter console client`
3. `feat: add recovery dead-letter operations surface`
4. `test: qualify recovery operations with virtual webauthn`
5. `feat: run crash-safe recovery notification workers`
6. `feat: enforce shared recovery abuse limits and retention`
7. `test: close the production console browser matrix`
8. `feat: add purpose-separated managed signer providers`
9. `feat: complete claude code headless onboarding`
10. `feat: add cursor adapter parity`
11. `build: produce signed notarized immutable pkg`
12. `ops: qualify and promote hosted production release`

Items 11 and 12 remain externally gated until the required Apple, cloud, hardware, and review resources are available.

## 8. Final definition of done

AgentPass v1 is complete only when a new user can install the verified PKG, enroll from the browser/CLI flow, configure Claude Code and Cursor, produce unattended policy-bound commits, inspect and revoke authority in the Console, recover access without a single-party takeover, and safely upgrade or remove the product. The exact production release must use PostgreSQL and purpose-separated managed keys, pass browser and two-lane physical qualification, survive restore and rollback drills, and have no unresolved critical/high security finding.
