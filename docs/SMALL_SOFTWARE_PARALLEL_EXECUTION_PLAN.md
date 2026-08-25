# AgentPass Small Software + Self-Maintaining APIs Parallel Execution Plan

Status: active implementation plan; not a production-readiness claim
Baseline commit: `8337884`
Branch: `codex/agent-platform`
PostgreSQL schema head at planning time: `0118_authority_generation_update_qualification.sql`
Date: 2026-08-25

## Implementation checkpoint — 2026-08-25

The initial private-alpha control-plane slice is implemented on the current
`codex/agent-platform` branch. The following items are now present and covered
by focused tests:

- plan-only Small Software CLI (`inspect`, `bundle`, `prepare`, `publish`) with
  bounded project inventory and manifest/artifact digests;
- Console Apps/Small Software surface with explicit Early Alpha, plan-only, and
  `NOT PROVEN` states;
- MCP inspect, publish-prepare, deployment-status, app-list/open, and
  maintenance-status read models with tenant binding and redaction;
- maintenance patch proposals, independent verification aggregation, and
  provider-neutral draft-PR intent/status projection;
- demo app, README/Product Hunt launch material, and bilingual product copy;
- PostgreSQL 16/17 authority lanes, integration tests, P0-B artifact scanning,
  and browser E2E (83/83 in the latest run).

The following are deliberately still outside the proof boundary and must not be
described as production-qualified: provider deployment, GitHub PR mutation,
real external WebAuthn qualification, live Cloudflare routing, and production
data/egress connectors. The current OSS path remains plan-only until those
external evidence inputs are supplied.

Parent specifications:

- [Small Software Cloud](SMALL_SOFTWARE_CLOUD_SPEC.md)
- [Self-Maintaining APIs](SELF_MAINTAINING_APIS_SPEC.md)
- [Contract authority ADR](ADR-003-contract-authority-and-versioning.md)
- [Current production roadmap](IMPLEMENTATION_ROADMAP.md)

## 1. Goal and completion boundary

This plan converts the two product specifications into an issue-level build
contract suitable for parallel execution by `gpt-5.6-luna` coding agents.

The immediate engineering goal is an invited private alpha with both loops:

```text
Loop A — publish
supported TypeScript app
  -> agentpass publish
  -> isolated private preview
  -> exact Publish Plan
  -> passkey approval
  -> protected team URL
  -> suspend / expire / rollback / delete

Loop B — maintain
signed API advisory
  -> affected deployed app detected
  -> bounded isolated patch
  -> verified Draft PR
  -> human merge
  -> Publish Plan delta
  -> protected republish
```

Private-alpha completion requires working code, integrated tests, deployed-like
browser/provider tests, real PostgreSQL authority tests, and explicit external
evidence status. It does not require auto-merge, public apps, arbitrary Docker,
custom domains, privileged production connectors, or multi-provider runtime.

## 2. Fixed product decisions for implementation

The following defaults are frozen for the first implementation unless the
product owner changes them before Wave 0 completes:

| Decision | Private-alpha value |
| --- | --- |
| Runtime | Cloudflare Workers for Platforms adapter |
| App profile | TypeScript/JavaScript, static assets, Worker API |
| Data | optional new isolated per-app SQL; no existing production DB |
| Creator OS | macOS signed AgentPass path |
| Agents | Claude Code, Codex-compatible CLI, Cursor/MCP |
| Identity | existing AgentPass organization members |
| Sharing | creator, named member, organization |
| Public links | disabled |
| Preview lifetime | 24 hours |
| First active lifetime | 7 days |
| Repository provider | GitHub App only |
| Maintenance languages | TypeScript/JavaScript |
| Advisory formats | AgentPass envelope + OpenAPI/SDK selectors |
| Maintenance modes | Notify and Draft PR only |
| Workflow modification | prohibited |
| Auto-merge/publish | prohibited |
| Privileged connector | none before later data/egress milestone |

## 3. Current repository baseline

Reusable implementation exists for:

- organization, membership, role, Human Session, WebAuthn, recent-auth, CSRF,
  session rotation, and hosted bootstrap;
- device, agent, Agent Session, capability, policy, bundle, refresh, revocation,
  emergency stop, audit, and audit export;
- Platform promotion authorization/evidence and purpose-separated signers;
- strict contract catalog, schemas, fixtures, canonical vectors, forward-only
  PostgreSQL migrations, role/authority validation, and release evidence;
- Web Console, Cloud API, CLI, MCP, Claude Code/Cursor integration, browser/CLI
  one-consume handoff, native macOS boundary, and production qualification
  infrastructure.

Not present yet:

- Small Software app/release/source/build/deployment/access domain;
- `agentpass publish` CLI/MCP journey;
- safe source bundle and object-storage abstraction;
- build sandbox boundary;
- Cloudflare runtime adapter and protected dispatch ingress;
- app approval/sharing/lifecycle Console surfaces;
- API provider/advisory/usage/maintenance domain;
- GitHub App fixed repository-operation service;
- maintenance sandbox, patch receipt, and Draft PR flow;
- combined publish-to-maintain E2E and external production evidence.

The pre-existing untracked `.n3e-release-materializer-VhMrkt/` directory is out
of scope and must remain untouched.

## 4. Parallel-agent operating model

### 4.1 Concurrency

The execution environment has four active slots. Every implementation Wave uses:

- **root:** planner, contract owner, integrator, conflict resolver, final tester;
- **Luna A:** one disjoint implementation lane;
- **Luna B:** one disjoint implementation lane;
- **Luna C:** one disjoint implementation lane.

Use model `gpt-5.6-luna` for implementation workers. Root retains ownership of
shared contracts and final integration decisions. No Wave starts more than
three subagents concurrently.

When root starts a worker, it uses a model override with `fork_turns: "none"`
and supplies the complete task packet defined in section 4.4. This avoids
passing an oversized or stale conversation history to the worker while keeping
the worker's authority, baseline, scope, and acceptance tests explicit. The
root agent does not delegate integration, release claims, or Goal completion.

### 4.2 Worktree isolation

Before each Wave, root creates one worktree/branch per lane from the exact
integrated Wave baseline:

```text
/tmp/agentpass-ssc-w{wave}-a  codex/ssc-w{wave}-a
/tmp/agentpass-ssc-w{wave}-b  codex/ssc-w{wave}-b
/tmp/agentpass-ssc-w{wave}-c  codex/ssc-w{wave}-c
```

Rules:

1. A Luna worker edits only its assigned worktree and allowlisted files.
2. Each worker begins by reporting `git rev-parse HEAD`, `HEAD^{tree}`, branch,
   `git status --short`, and assigned paths.
3. Workers do not push, merge, rebase, delete branches, or change protection.
4. Each worker commits one or more reviewable commits and returns exact SHAs.
5. Root inspects each diff and cherry-picks in the defined integration order.
6. Root reruns tests on the combined tree; worker tests are not integration
   evidence.
7. After integration, a separate review Wave inspects the combined current tree.
8. Worktrees remain available until the Wave is accepted, then root removes
   only the exact validated temporary paths.

### 4.3 Shared-file ownership

The following files are root-owned unless explicitly assigned for one Wave:

- `contracts/catalog-v1.json`;
- shared OpenAPI documents;
- `packages/protocol/src/index.mjs`;
- `apps/cloud-api/src/server.mjs`;
- `apps/cloud-api/src/runtime.mjs`;
- `apps/cloud-api/src/postgres/index.mjs`;
- `package.json` and lockfiles;
- production-readiness and promotion workflows;
- release qualification matrices;
- parent specifications and this execution plan.

Workers may propose patches for these files but must not edit them concurrently.
Root applies shared integration wiring after lane commits land.

### 4.4 Luna task packet

Every Luna task message must contain:

- exact baseline commit and worktree;
- objective and non-goals;
- file allowlist;
- contracts and invariants to preserve;
- concrete positive and adversarial tests;
- required commit/handoff format;
- explicit prohibition on production claims from local/mock evidence;
- instruction to stop and report when a shared-contract change is required.

Required handoff:

```text
Status: complete | partial | blocked
Baseline commit/tree:
Commit SHA(s):
Files changed:
Behavior implemented:
Tests run and exact results:
Tests not run:
Security invariants checked:
External evidence: passed | failed | not_proven
Known risks / integration notes:
```

## 5. Definition of Done

An issue is complete only when all applicable items hold:

1. Implementation and strict closed-schema validation exist.
2. Positive, negative, substitution, replay, response-loss, and redaction tests
   exist for its trust boundary.
3. Contract catalog, schemas, fixtures, OpenAPI, authority manifest, roles, and
   migration head are updated together where applicable.
4. Unknown fields/versions/aliases fail closed.
5. Tenant, actor, app/repository, source, release, artifact, provider, operation,
   and expiry bindings are explicit where relevant.
6. Idempotency conflicts are bound to exact canonical request bytes.
7. Uncertain provider/GitHub/sandbox effects enter reconciliation, not blind
   retry.
8. Errors and logs contain stable safe codes without source, path leakage where
   prohibited, prompts, secrets, tokens, cookies, assertions, or raw provider
   responses.
9. Focused tests pass in the worker worktree and again after integration.
10. Static/local evidence is labeled separately from external qualification.
11. Documentation and operator remediation reflect the implemented behavior.
12. Root accepts the combined diff after independent review.

## 6. Milestones and critical path

```text
M0 Contracts and skeleton
  -> M1 Private preview
  -> M2 Protected publish and sharing
  -> M3 Advisory impact / Notify
  -> M4 Draft maintenance PR
  -> M5 Merge-to-republish
  -> M6 Isolated data / egress
  -> M7 Production beta qualification
```

M3 can begin after M1 has stable app/release/source/SBOM identities. M4 requires
M3 plus repository identity and maintenance contracts. M5 requires M2 and M4.
M6 may run in parallel with late M4/M5 only after app/release authority is
stable. M7 always evaluates one integrated immutable candidate.

## 7. Wave 0 — Contract freeze and implementation skeleton

Target: freeze cross-lane contracts before parallel product code begins.

### Lane A — SSC contracts

Issues: `SSC-001` through `SSC-007`.

Owned paths:

- new `contracts/schemas/small-software-*.schema.json`;
- new `contracts/fixtures/small-software-*`;
- new `contracts/vectors/small-software-*`;
- new `packages/small-software-contracts/`;
- focused package tests.

Deliverables:

- app manifest v1;
- source bundle statement v1;
- build receipt v1;
- Publish Plan v1;
- application grant v1;
- deployment receipt v1;
- provider operation/result v1;
- canonical digest vectors and redaction projection.

Acceptance:

- producer/consumer vectors agree;
- unknown fields, duplicate semantic aliases, invalid paths/origins/times/IDs,
  noncanonical timestamps, oversized arrays/strings, and secret-like values are
  rejected;
- existing Git capability operation set is unchanged;
- application-grant signing purpose is distinct.

### Lane B — Maintenance contracts and sample provider

Issues: `SM-001` through `SM-008`.

Owned paths:

- new `contracts/schemas/maintenance-*.schema.json`;
- new `contracts/fixtures/maintenance-*`;
- new `contracts/vectors/maintenance-*`;
- new `packages/maintenance-contracts/`;
- new `test/fixtures/sample-api-provider/`;
- focused package tests.

Deliverables:

- provider identity, advisory, usage attestation, maintenance policy, plan,
  grant, receipt, and provider-key event contracts;
- signed sample advisories for endpoint, method, field, SDK symbol, pagination,
  version-header, webhook-field, and error changes;
- old/new sample OpenAPI and SDK fixtures;
- purpose separation and canonical vectors.

Acceptance:

- advisory correction/withdrawal is a new signed event, never mutation;
- provider authority cannot encode repository/app selection or approval;
- executable migration material is treated as untrusted attachment metadata;
- malformed/overbroad selectors fail closed.

### Lane C — Domain skeleton and test harness

Issues: `PLAT-001` through `PLAT-005`.

Owned paths:

- new `apps/cloud-api/src/small-software/` skeleton;
- new `apps/cloud-api/src/maintenance/` skeleton;
- new focused test support under `apps/cloud-api/test/support/`;
- new provider/sandbox fake interfaces under test-only paths;
- no shared runtime/server edits.

Deliverables:

- explicit service/repository/provider interfaces;
- stable domain error codes and safe messages;
- deterministic fake clock/UUID/provider operation harness;
- no-op test compositions that fail closed when dependencies are absent.

Acceptance:

- hosted profile cannot instantiate domain services with test fakes;
- no raw provider/GitHub error is exposed;
- interfaces reserve then inspect external effects;
- no monolithic additions to `server.mjs`.

### Root integration

Integration order: A → B → C → catalog/OpenAPI/shared validator wiring.

Root-owned work:

- contract catalog entries and authority ownership;
- root validation scripts and package scripts;
- OpenAPI route placeholders marked unavailable;
- threat-model update;
- shared naming/version/error review.

Wave gate:

```sh
npm run contracts:validate
npm run lint
node --test packages/small-software-contracts/test/*.test.mjs
node --test packages/maintenance-contracts/test/*.test.mjs
node --test apps/cloud-api/test/small-software-*.test.mjs apps/cloud-api/test/maintenance-*.test.mjs
```

No runtime route or mutation is enabled in Wave 0.

## 8. Wave 1 — PostgreSQL authority foundation

Target: durable app/release/provider-operation and provider/advisory authority.

Wave baseline: accepted Wave 0 integrated commit.

### Lane A — Small Software migrations

Issues: `SSC-101` through `SSC-108`.

Owned paths:

- new contiguous `contracts/postgres/0119_*` onward reserved for this lane;
- new `apps/cloud-api/src/postgres/small-software-*.mjs`;
- focused PostgreSQL tests;
- no edits to existing released migration bytes.

Tables/functions:

- apps, releases, publish plans, approvals, deployments, routes, access rules;
- provider operations and lifecycle jobs;
- reserve app/release/plan/external effect;
- approve exact plan;
- reconcile deployment;
- activate monotonic route generation;
- suspend, expire, rollback, and delete reservation.

Acceptance:

- immutable release identity cannot update after reservation;
- approval binds exact plan/artifact/release/org/member/session operation;
- stale generation cannot activate;
- response-loss retries converge;
- tenant RLS and direct-DML denial are tested with real roles when available;
- fixed lock order is documented and concurrency-tested.

### Lane B — Maintenance migrations

Issues: `SM-101` through `SM-110`.

Owned paths:

- next reserved contiguous migration range after Lane A;
- new `apps/cloud-api/src/postgres/maintenance-*.mjs`;
- focused PostgreSQL tests.

Tables/functions:

- providers, provider keys, advisories/events;
- repository installations/snapshots;
- usage attestations and maintenance policies;
- jobs, effects, results, pull requests, receipts, exceptions;
- advisory publish/supersede/withdraw;
- reserve/cancel/complete/reconcile maintenance effect.

Acceptance:

- provider database role cannot read any customer tenant relation;
- advisory bytes are immutable;
- compromised key blocks new jobs;
- exact repository installation is tenant-bound;
- job effects cannot be blindly retried;
- customer app role cannot directly mutate authority relations.

### Lane C — Authority/role qualification support

Issues: `DB-101` through `DB-106`.

Owned paths:

- `scripts/postgres/` new/isolated validators;
- new qualification tests;
- proposed role/authority-manifest patch isolated from A/B.

Deliverables:

- expected role/ACL/RLS/function-execute manifest for both domains;
- cross-tenant negative matrix;
- migration/catalog/head qualification fixtures;
- concurrency/deadlock/response-loss scenario driver;
- clean `not_proven` behavior without live PostgreSQL.

Acceptance:

- missing live database exits nonzero for external qualification;
- fixtures cannot set `passed` external status;
- failures expose safe check IDs, not SQL/connection secrets;
- PostgreSQL 16 and 17 lanes are independently identified.

### Root integration

Root reserves exact migration numbers before spawning agents. Root integrates A,
then B, then C, and updates:

- catalog checksums;
- schema-head tests;
- `roles.sql` and authority manifest;
- PostgreSQL exports/runtime composition stubs;
- migration readiness and release evidence inventory.

Wave gate:

- fresh database migration from zero;
- upgrade from current `0118` head;
- catalog/checksum/head agreement;
- repository unit tests;
- real PostgreSQL role/RLS/concurrency lane if credentials are available;
- otherwise external PostgreSQL status remains `not_proven` and nonzero.

## 9. Wave 2 — Safe source bundle and private preview

Target: `agentpass publish` creates a creator-only expiring preview.

### Lane A — CLI, source inventory, and MCP

Issues: `SSC-201` through `SSC-209`.

Owned paths:

- new `lib/publish-*.mjs`;
- `bin/agentpass.mjs` only in this lane;
- new MCP publish modules/tools;
- CLI/MCP tests;
- documentation for supported project profile.

Deliverables:

- `agentpass publish`, `publish status`, `apps list/open`;
- project/framework detection;
- app manifest load/generate preview;
- safe source inventory and content-addressed archive;
- local preflight/scanner summary;
- strict `--json` output and friendly normal output;
- MCP prepare/status/open tools.

Required source defenses:

- real project root, no `/` or unsafe ancestor;
- `.git`, `.env*`, secrets, keys, sockets, device files, caches excluded/denied;
- symlink, hardlink, traversal, duplicate normalized path, case collision,
  unicode normalization, archive bomb, TOCTOU, and file-replacement tests;
- exact Git commit/tree and dirty-tree digest;
- bounded files/bytes/path lengths/depth.

### Lane B — Source/build service and object storage

Issues: `SSC-210` through `SSC-218`.

Owned paths:

- new `apps/cloud-api/src/small-software/source-*.mjs`;
- new build service modules;
- object-storage interface/adapters;
- isolated tests and test provider;
- no Cloudflare adapter yet.

Deliverables:

- source upload/resume/finalize protocol;
- content-addressed object metadata and retention;
- build request reservation;
- isolated build runner interface;
- signed build receipt;
- private preview orchestration with fake runtime provider;
- lifecycle status and cleanup worker.

Acceptance:

- source mismatch/replacement denied;
- builder receives no AgentPass production credentials;
- timeout/output/network/process/disk limits tested;
- incomplete upload/build cannot become preview-ready;
- expired preview cleanup is deterministic or reconciliation-required.

### Lane C — Cloudflare preview adapter

Issues: `CF-201` through `CF-208`.

Owned paths:

- new `apps/cloud-api/src/providers/cloudflare/`;
- provider adapter tests and fixtures;
- deployment verification scripts under new paths;
- no Cloud API shared runtime wiring.

Deliverables:

- workload-identity/provider credential boundary;
- create/inspect/delete preview;
- normalized closed provider receipts;
- provider operation idempotency and uncertainty reconciliation;
- hard limits and direct-route visibility metadata;
- fake and optional live-development adapter modes clearly separated.

Acceptance:

- raw Cloudflare response/token never reaches user/agent output;
- timeout/duplicate/partial success converges;
- provider IDs are not tenant authority;
- local fake cannot report external qualification passed;
- live preview evidence binds account/namespace/deployment/artifact identities.

### Root integration

Root wires CLI/device request routes, Cloud API services, PostgreSQL repositories,
object storage, build service, and Cloudflare adapter. Root updates hosted
readiness so missing production dependencies fail closed.

Wave gate:

- supported sample app reaches expiring creator-only preview from one command;
- changed source produces changed release/artifact;
- unsupported projects fail with actionable safe errors;
- source/build/provider adversarial suites pass;
- optional real Cloudflare preview is evidence-labeled, otherwise `not_proven`.

## 10. Wave 3 — Protected ingress, approval, sharing, lifecycle

Target: exact preview becomes a protected team URL after human approval.

### Lane A — Approval and access authority

Issues: `SSC-301` through `SSC-309`.

Owned paths:

- Small Software Cloud API domain service/routes;
- WebAuthn operation binding modules/fixtures;
- app access authorization repository/service;
- focused Cloud API tests;
- no Console component edits.

Deliverables:

- Publish Plan delta and risk classification;
- WebAuthn approval options/verify bound to exact plan/artifact/release;
- access-rule create/revoke/list;
- suspend, expiry, rollback, delete intents;
- stable public projections and audit events.

Acceptance:

- changed bytes/plan/audience/org/member/session rejects approval replay;
- authority widening always requires configured approval;
- access rule cannot exceed approved plan/org policy ceiling;
- expired/suspended/deleted apps deny access;
- dangerous lifecycle actions are idempotent and response-loss safe.

### Lane B — Ingress/dispatch runtime

Issues: `CF-301` through `CF-310`.

Owned paths:

- new ingress/dispatch Worker project under `apps/`;
- runtime-context contract implementation;
- routing/access/rate-limit tests;
- Cloudflare route activation/reconciliation adapter extensions.

Deliverables:

- org/app/release resolution;
- Human Session/service identity validation;
- access, expiry, suspend, emergency-stop checks;
- bounded signed runtime identity projection;
- monotonic active release generation;
- direct provider URL bypass denial strategy;
- route activate/suspend/delete reconciliation.

Acceptance:

- authorized member succeeds; unauthorized/cross-tenant member fails;
- user Worker never receives AgentPass cookie;
- direct route cannot bypass ingress;
- stale callback cannot reactivate prior generation;
- emergency stop denies ingress without async Console dependency;
- revocation propagation target measured in live/deployed qualification only.

### Lane C — Console app/publish UX

Issues: `UI-301` through `UI-312`.

Owned paths:

- new Small Software Console components/clients;
- routes/pages/styles dedicated to apps;
- browser/component/accessibility tests;
- no Cloud API authority implementation.

Surfaces:

- Apps list/detail;
- release/preview status;
- approval summary and authority delta;
- audience/lifetime/access rules;
- activity, suspend, rollback, delete;
- loading, empty, stale, expired, revoked, reconciliation, and blocked states.

Acceptance:

- UI never renders secrets, raw IDs unnecessarily, provider errors, cookies,
  assertions, source, or raw plan internals;
- high-risk confirmation is explicit and keyboard/screen-reader usable;
- stale response cannot overwrite newer session/organization/app state;
- browser tests cover every role and denial path.

### Root integration

Root owns BFF/API routing, shared session authority, OpenAPI, readiness, and full
browser journey wiring.

Wave gate:

- creator publishes, approves, opens, shares with named member;
- unauthorized member denied;
- suspend/expire/rollback/delete behavior proven in deployed-like test;
- passkey local fixtures pass but real WebAuthn remains separate external gate;
- no manual Cloudflare dashboard step in the tested journey.

## 11. Review Wave R1 — Private publish independent audit

No implementation starts until R1 findings are dispositioned.

### Reviewer A — Contracts/provenance

Read-only scope: source→build→artifact→plan→approval→deployment→route bindings,
schema/version/key-purpose drift, replay/idempotency, redaction.

### Reviewer B — PostgreSQL/tenant authority

Read-only scope: migrations, RLS, ACLs, SECURITY DEFINER, role grants, lock order,
direct DML, cross-tenant, lifecycle authority, response loss.

### Reviewer C — Browser/runtime/provider

Read-only scope: session/CSRF/WebAuthn, ingress bypass, stale UI authority,
Cloudflare uncertainty, direct route, emergency stop, expiry/deletion.

Required report per finding:

- severity;
- exact file/line;
- violated invariant;
- attack/failure scenario;
- minimal remediation;
- adversarial test;
- runtime status: proven, failed, or `not_proven`.

Root remediates P0/P1 and reruns the combined matrix before M2 acceptance.

## 12. Wave 4 — API advisory registry and impact/Notify mode

Target: detect API changes affecting deployed apps before enforcement.

### Lane A — Provider identity and advisory registry

Issues: `SM-401` through `SM-409`.

Owned paths:

- maintenance provider/advisory services and HTTP routes;
- provider key verification/rotation/compromise;
- advisory registry workers;
- focused tests.

Acceptance:

- provider publishes only under verified purpose key;
- advisory immutable; supersede/withdraw separate signed events;
- key compromise suspends new jobs;
- provider cannot query customer app/repository data;
- raw attachments are content-addressed and treated untrusted.

### Lane B — Usage index and impact classifier

Issues: `SM-410` through `SM-421`.

Owned paths:

- analyzer/index modules;
- app manifest/build/SBOM extensions;
- sample API analyzers and fixtures;
- focused TypeScript/JavaScript tests.

Deliverables:

- SDK/import/symbol/endpoint/method/field/event fingerprints;
- confirmed/probable/possible/not-affected/unknown classification;
- freshness and exact source/release binding;
- privacy-safe usage attestation.

Acceptance:

- fixture accuracy measured with false positives/unknowns visible;
- no source/request/response/customer data in attestation;
- stale index cannot produce confirmed auto action;
- overbroad advisory does not silently match every app.

### Lane C — Maintenance policy and Notify Console

Issues: `SM-422` through `SM-432`.

Owned paths:

- maintenance policy/service client;
- Console provider/advisory/impact/policy views;
- deadline/ignore/escalation UI and tests;
- notification worker under isolated new paths.

Acceptance:

- policy default is Notify/Draft PR only;
- exact provider/repository/app/mode/risk ceiling visible;
- ignore/exception is time-bounded, reasoned, and audited;
- roles and stale-response guards enforced;
- no source content disclosed to provider or Console analytics.

### Root integration and gate

Root connects app releases to usage attestations and provider advisories to
tenant-scoped impacts. Gate requires signed sample advisory → affected deployed
app → visible impact/deadline, with cross-tenant and compromised-key negatives.

## 13. Wave 5 — Isolated maintenance patch and Draft PR

Target: affected app receives a verified Draft PR without exposing GitHub token.

### Lane A — GitHub App fixed connector

Issues: `GH-501` through `GH-512`.

Owned paths:

- new `apps/cloud-api/src/providers/github/`;
- installation/repository/webhook/token service;
- fixed branch/patch/PR operation service;
- response-loss reconciliation tests.

Acceptance:

- selected repository only;
- installation token never enters agent/sandbox/model/log/output;
- token permissions minimized and TTL bounded;
- expected base commit, branch namespace, paths, patch digest/limits verified;
- workflows, CODEOWNERS, AgentPass policy, auth/deployment/security paths denied;
- duplicate/uncertain branch/PR operations reconcile without duplication.

### Lane B — Maintenance agent and sandbox

Issues: `SM-501` through `SM-513`.

Owned paths:

- maintenance orchestrator/runner/tool boundary;
- isolated workspace implementation;
- provider hint/agent attachment sandboxing;
- prompt-injection and resource-limit tests.

Acceptance:

- exact base commit immutable;
- maintenance grant limits paths/ops/tools/network/time/cost;
- repository content and PR comments are untrusted data, not authority;
- provider code cannot alter policy/evidence/GitHub operations;
- result is content-addressed patch/tree only;
- cancellation/revocation stops new effects and records terminal state.

### Lane C — Verification and maintenance receipt

Issues: `SM-514` through `SM-526`.

Owned paths:

- verification pipeline;
- affected-usage recheck;
- test/conformance/security/authority-delta checks;
- receipt/PR-body/labels generation;
- MCP/CLI maintenance status.

Acceptance:

- each verification layer recorded independently;
- missing test is `not_run`, not passed;
- agent-generated tests cannot be sole proof;
- receipt binds advisory→base→plan→patch→head tree→tests→PR;
- PR clearly displays uncertainty and manual steps;
- no false `verified` claim.

### Root integration and gate

Root wires job authority, GitHub connector, sandbox, verification, Console, and
audit. Gate: five supported sample/real apps receive correct Draft PRs; token
isolation, sensitive-path denial, prompt injection, changed base, response loss,
cross-tenant, and compromised-provider tests pass.

## 14. Review Wave R2 — Maintenance independent audit

### Reviewer A — Provider/supply chain

Audit provider identity, keys, advisory selectors, attachments, compromise,
prompt injection, dependencies, sandbox escape, exfiltration.

### Reviewer B — Repository/GitHub authority

Audit installation binding, token isolation, permissions, base/head/patch/path,
workflow denial, webhook authenticity, response-loss reconciliation.

### Reviewer C — Verification/claims

Audit impact confidence, generated tests, receipt semantics, PR language,
authority delta, audit/redaction, false production/verification claims.

Root closes P0/P1 before enabling external design partners.

## 15. Wave 6 — Merge-to-republish

Target: accepted maintenance PR produces a newly approved protected release.

### Lane A — Merge identity and source/release bridge

Issues: `SM-601` through `SM-608`.

- exact installation/repository/PR/base/head webhook binding;
- merge commit/tree reconciliation;
- verified-head equality or mandatory re-verification;
- new source/release identity and maintenance linkage.

### Lane B — Publish Plan delta and deployment verification

Issues: `SM-609` through `SM-617`.

- maintenance-specific authority delta;
- passkey escalation for widened authority;
- preview/conformance/post-deploy checks;
- activation and rollback orchestration;
- runtime completion evidence.

### Lane C — Completion UX and provider analytics

Issues: `UI-601` through `UI-608`.

- merged/deployed/completed/rolled-back states;
- customer evidence chain;
- aggregate provider completion without source/customer leakage;
- stale/deadline/superseded handling.

Wave gate:

- changed PR head forces re-verification;
- maintenance label/receipt cannot bypass Publish Plan approval;
- post-deploy failure cannot mark completed;
- rollback is explicit and data compatibility respected;
- full advisory→impact→job→PR→merge→release→deployment receipt verifies.

## 16. Wave 7 — Isolated data and safe egress

Target: useful CRUD apps and first safe external API access.

### Lane A — Per-app data lifecycle

- provision isolated SQL binding;
- migration classification and schema identity;
- backup/restore evidence;
- destructive-change approval;
- retention/deletion receipt;
- cross-app/tenant negative qualification.

### Lane B — Egress and connector broker

- exact HTTPS origin/method rules;
- outbound Worker/proxy;
- application egress capability;
- managed connector interface, purpose-separated secret use;
- limits, redaction, provider uncertainty;
- no raw long-lived credential in user Worker.

### Lane C — Usage/cost/operations UX

- per-app request/egress/storage/schedule/cost ceilings;
- usage and failure diagnostics;
- quota alerts, suspend controls, retention UI;
- privacy-safe logs/traces.

Wave gate:

- app cannot enumerate/access another data binding;
- non-approved egress denied;
- raw connector secret absent from source/build/runtime/logs;
- destructive migration needs owner approval plus recovery evidence;
- deletion matches retention policy and produces bound receipt.

## 17. Wave 8 — Production beta hardening

Parallel implementation lanes:

### Lane A — Operations and abuse

- quotas/billing events;
- organization/app deletion;
- support-safe diagnostics;
- alerts, SLOs, cost ceilings;
- incident kill switches;
- provider/customer dispute and compromise procedures.

### Lane B — Distribution and creator journey

- finish `agentpass start` automatic browser connect with signed endpoints;
- signed/notarized universal macOS distribution;
- update/rollback/uninstall preservation;
- Claude Code/Codex/Cursor publish journey;
- clean-machine installation and onboarding.

### Lane C — Qualification/evidence automation

- real PostgreSQL 16/17 authority/races;
- Cloudflare runtime/ingress/egress isolation;
- GitHub App/token/PR/response-loss;
- WebAuthn real browser/hardware;
- KMS/workload identity;
- backup/PITR/restore/rollback;
- source/artifact/deployment/policy/run binding;
- published archive secret scan.

Root integrates one immutable release candidate and runs the release gate. No
Lane may self-approve its own evidence.

## 18. External qualification matrix

| Boundary | Local evidence | Required external evidence |
| --- | --- | --- |
| Contracts | schemas/vectors/tests | independent consumer compatibility |
| PostgreSQL | fake/unit/static SQL | real PG16/17 roles, RLS, ACL, races, locks, PITR |
| WebAuthn | fixtures/browser mocks | real HTTPS origin/RP ID/passkey/hardware |
| Cloudflare | adapter fakes | real account/namespace/Worker/route/egress isolation |
| Build sandbox | mocked limits | deployed isolation/network/resource/cleanup evidence |
| GitHub | API fakes | real App installation, scoped token, PR, webhook, response loss |
| macOS | source/unit tests | signed/notarized Apple Silicon and Intel/T2 path |
| KMS/workload | fake signer | provider identity, IAM, key version, outage/uncertainty |
| Backup/rollback | scripts/fixtures | actual restore target, traffic rollback, post-checks |
| Revocation | local state | deployed propagation and outage/restart behavior |

Every external runner must bind exact source commit/tree, built artifact,
deployment instance, policy/config digests, run/job IDs, protected runner
identity, timestamps, and retained evidence digests. Missing, skipped, local,
mock, fixture, stale, or self-reported evidence is `not_proven` and nonzero.

## 19. Integrated test commands by gate

Commands are finalized as packages land; root keeps one checked-in gate script
per milestone rather than relying on prose commands.

### M0 contract gate

```sh
npm run contracts:validate
npm run lint
node --test packages/small-software-contracts/test/*.test.mjs
node --test packages/maintenance-contracts/test/*.test.mjs
```

### M1 private preview gate

```sh
node --test test/publish-*.test.mjs adapters/mcp-server/test/publish-*.test.mjs
node --test apps/cloud-api/test/small-software-*.test.mjs
node --test apps/cloud-api/test/provider-cloudflare-*.test.mjs
```

### M2 protected publish gate

```sh
npm run test:console
node --test apps/cloud-api/test/small-software-*.test.mjs
node --test apps/cloud-api/test/postgres/small-software-*.test.mjs
```

### M3/M4 maintenance gate

```sh
node --test packages/maintenance-contracts/test/*.test.mjs
node --test apps/cloud-api/test/maintenance-*.test.mjs
node --test apps/cloud-api/test/provider-github-*.test.mjs
node --test apps/cloud-api/test/postgres/maintenance-*.test.mjs
```

### Full integrated candidate gate

```sh
npm test
npm run test:console
npm run lint:console
npm run test:native
npm run lint
npm run release:readiness -- /protected/evidence/production-readiness-gate.json
```

The full gate command does not imply qualification if protected evidence is
missing or environment-limited.

## 20. Merge and remediation protocol

For every Wave:

1. Root records baseline commit/tree and creates exact worktrees.
2. Root spawns up to three Luna agents with disjoint allowlists.
3. Root continues shared integration preparation without editing lane files.
4. On completion, root inspects `git show --stat`, `git diff baseline..commit`,
   test output, and untracked files for each lane.
5. Root rejects scope expansion or asks the same agent for a focused correction.
6. Root cherry-picks in the Wave-defined order.
7. Root resolves only shared integration conflicts and records the resolution.
8. Root runs focused then combined gates.
9. Root launches the review Wave against the integrated tree.
10. Root assigns P0/P1 fixes to new isolated Luna lanes; the original author
    does not act as sole reviewer.
11. Root reruns the full relevant matrix and commits the integrated Wave.
12. Root removes temporary worktrees only after the Wave commit is retained.

If a shared contract changes mid-Wave, all affected lanes stop. Root creates a
new contract commit, rebases the plan baseline by creating fresh worktrees, and
restarts only the dependent tasks. Agents do not independently resolve protocol
drift.

## 21. Estimated sequencing

With root plus three Luna workers, focused use of existing AgentPass components,
and prompt access to external accounts:

| Milestone | Engineering range | Main elapsed-time risk |
| --- | --- | --- |
| M0 contracts/skeleton | 1–2 weeks | contract/security review |
| M1 private preview | 3–5 weeks | sandbox/runtime account integration |
| M2 protected publish | 4–6 weeks | ingress/WebAuthn/browser/DB integration |
| M3 impact/Notify | 3–5 weeks | usage accuracy and provider fixtures |
| M4 Draft PR | 5–8 weeks | GitHub/token isolation and patch quality |
| M5 merge/republish | 4–6 weeks | release/rollback verification |
| M6 data/egress | 5–8 weeks | database/connector security and recovery |
| M7 production beta | 6–10 weeks | external qualification and incident readiness |

Parallel agents reduce implementation latency but do not remove critical-path
contract reviews, provider provisioning, real-environment evidence, independent
security review, or operational drills. M3 can overlap late M2 preparation;
M6 can overlap late M4/M5 after authority contracts freeze.

## 22. First development session after plan approval

The next goal-mode development session begins with Wave 0 only.

Root actions:

1. verify canonical branch/status and preserve the existing untracked materializer;
2. tag the exact Wave 0 baseline commit/tree in the task log;
3. create three isolated worktrees;
4. spawn three `gpt-5.6-luna` workers with `fork_turns: "none"`: Luna A for SSC
   contracts, Luna B for maintenance contracts/sample API, and Luna C for the
   domain skeleton/test harness;
5. implement root-owned catalog/OpenAPI/validator integration after lane contracts
   are returned;
6. run M0 gates and a three-lane read-only contract/security review;
7. close P0/P1, commit the integrated Wave 0, and only then start Wave 1.

This prevents early runtime code from inventing incompatible contracts and
keeps the later Luna waves independently mergeable.
