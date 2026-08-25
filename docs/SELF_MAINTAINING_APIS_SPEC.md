# AgentPass Self-Maintaining APIs — Product and Implementation Specification

Status: proposed implementation contract; not a production-readiness claim  
Date: 2026-08-25  
Parent direction: [Small Software Cloud](SMALL_SOFTWARE_CLOUD_SPEC.md)

## 1. Executive decision

AgentPass will add Self-Maintaining APIs as the maintenance plane for Small
Software and, later, ordinary customer repositories.

The product promise is:

> When an API changes, AgentPass finds the affected code, prepares and verifies
> the fix, and opens a reviewable PR before the application breaks.

The complete product loop becomes:

```text
Prompt -> Build -> Publish safely -> Share -> Detect API change
       -> Patch in isolation -> Verify -> PR -> Approve -> Republish
```

AgentPass must not give an API vendor's agent standing access to customer code.
The provider publishes a signed, machine-readable change advisory. A
customer-authorized AgentPass maintenance agent receives a short-lived,
repository- and branch-scoped grant, performs the change in an isolated
workspace, and returns an auditable patch and verification receipt.

Private-alpha automation stops at a Draft PR. Auto-merge and automatic
production promotion are separate policy modes introduced only after the
repository, verification, and rollback boundaries are qualified.

## 2. Why this belongs in AgentPass

Small Software makes the maintenance problem larger:

- organizations will create far more applications;
- many apps will have no dedicated engineering owner;
- generated code will integrate with Stripe, HubSpot, Slack, Notion, Google,
  internal APIs, and rapidly changing SDKs;
- changelogs will not be read consistently;
- dormant apps can silently become insecure or stop working;
- an API vendor's generic migration instructions do not know the customer's
  exact implementation, policy, tests, or deployment state.

AgentPass already owns the relevant trust concepts:

- enrolled organizations, humans, devices, and coding agents;
- short-lived, narrowed capabilities;
- project and repository binding;
- immutable source/artifact/promotion identity;
- human approval and WebAuthn;
- audit, revocation, emergency stop, and response-loss reconciliation.

Self-Maintaining APIs turns those primitives into a controlled software
maintenance system. Small Software Cloud knows what is deployed; the
maintenance plane knows what must change and proves what changed.

## 3. Product roles

### 3.1 API provider

An API provider registers a verified provider identity and publishes signed
change advisories. The provider can supply:

- old and new OpenAPI/AsyncAPI/GraphQL/SDK identities;
- affected endpoints, fields, events, scopes, and SDK methods;
- release, deprecation, enforcement, and sunset times;
- severity and expected failure behavior;
- machine-readable transformation hints;
- migration guide and examples;
- conformance tests or provider-hosted test endpoint metadata;
- rollback/compatibility guidance;
- provider agent/container identity when provider-authored migration logic is
  offered.

The provider cannot select customer repositories, view customer code, approve
its own patch, widen customer permissions, or bypass customer policy.

### 3.2 Customer organization

The customer installs the AgentPass GitHub App on exact repositories, chooses
maintenance policy, and owns every authorization decision. The customer can:

- subscribe apps/repositories to providers or neutral advisory feeds;
- choose notification, Draft PR, verified PR, auto-merge, or auto-publish mode;
- limit paths, branches, providers, operations, data, time, and cost;
- require specific tests, reviewers, labels, environments, or deployment gates;
- pause one provider, repository, application, or all maintenance;
- inspect and export the full evidence chain.

### 3.3 AgentPass

AgentPass verifies advisory provenance, finds affected usage, issues one bounded
maintenance job, runs the agent in isolation, verifies the result, creates the
PR through a least-privilege repository connector, and connects the merge to an
approved Small Software release.

AgentPass is a neutral trust intermediary. It must distinguish:

- provider assertions;
- AgentPass-derived impact analysis;
- agent-generated changes;
- customer tests and policy;
- runtime/provider evidence;
- human approval.

None of these alone is a universal proof of correctness.

## 4. User experience

### 4.1 Customer setup

The owner opens AgentPass Console and selects `Maintenance`:

```text
Connect repository
  GitHub organization: acme
  Repository: sales-dashboard

Maintenance mode
  ○ Notify only
  ● Prepare Draft PR
  ○ Open verified PR
  ○ Auto-merge low-risk fixes

Providers detected
  Stripe API 2025-04
  HubSpot CRM v3
  Slack Web API

[Enable protected maintenance]
```

Private-alpha default is `Prepare Draft PR`.

The GitHub App installation must be limited to selected repositories. Requested
permissions are shown in plain language. Workflow-file modification is disabled
by default and requires a separate permission/approval path.

### 4.2 Change arrives

The provider publishes a signed advisory. AgentPass shows:

```text
Stripe API change affects 2 apps

Enforcement: 30 September 2026
Risk if unchanged: payment confirmation may fail

Affected code
  apps/billing/src/confirm.ts
  apps/ops/src/refunds.ts

Proposed action
  Prepare separate Draft PRs in isolated workspaces

[Prepare fixes] [Review advisory] [Ignore with reason]
```

For a policy-authorized provider and low-risk advisory, preparation may begin
without waiting for a human. This authorizes only isolated analysis and a Draft
PR, never merge or deployment.

### 4.3 Pull request

The resulting PR contains:

- provider, advisory ID, version, severity, and deadline;
- why this repository was considered affected;
- exact files and API usages changed;
- authority requested and actually used;
- source commit and patch digest;
- agent/model/toolchain identity;
- tests, static checks, provider conformance checks, and results;
- permissions, API scopes, secrets, data, and runtime changes;
- remaining uncertainty and manual verification steps;
- rollback and deployment impact;
- signed AgentPass maintenance receipt link.

PR labels are stable and policy-controlled, for example:

```text
agentpass-maintenance
provider:stripe
risk:medium
deadline:2026-09-30
verified:partial
```

`verified:partial` is not equivalent to safe-to-merge. The PR must never claim
full verification when integration, provider sandbox, deployment, or runtime
checks were not executed.

### 4.4 Merge and republish

After customer review:

1. existing branch protection and required checks remain authoritative;
2. the merge commit is bound to the maintenance job and receipt;
3. Small Software Cloud creates a new immutable release;
4. AgentPass shows the authority delta from the active release;
5. any widened egress, connector scope, data authority, or destructive migration
   requires a new human approval;
6. the exact release is deployed and reconciled;
7. post-deploy health and provider conformance checks run;
8. failure suspends promotion or triggers the approved rollback policy.

## 5. Automation modes

| Mode | AgentPass may do | Human still controls |
| --- | --- | --- |
| Notify | impact report only | all code and release changes |
| Draft PR | isolated patch and Draft PR | mark ready, merge, deploy |
| Verified PR | patch, checks, non-draft PR | merge and deploy |
| Auto-merge | merge only when exact low-risk policy and branch protection pass | policy, exceptions, widened authority |
| Auto-publish | merge and promote a no-authority-delta release | policy, high-risk changes, rollback ceiling |

Private alpha supports `Notify` and `Draft PR` only.

Auto-merge is prohibited when the patch:

- changes authentication, authorization, billing, money movement, deletion,
  cryptography, logging/redaction, or tenant isolation;
- modifies CI workflows, deployment configuration, infrastructure, lockfile
  sources, or organization policy;
- adds a dependency, API origin, secret, OAuth scope, webhook, schedule, data
  store, destructive migration, or elevated runtime limit;
- lacks every required test or produces flaky/non-deterministic results;
- crosses a configured size/file/risk threshold;
- comes from an untrusted or newly rotated provider key;
- was generated using an unapproved toolchain or provider agent;
- cannot be rolled back safely.

## 6. End-to-end architecture

```text
Provider control plane
  -> signed API Change Advisory
  -> AgentPass advisory registry
  -> provider identity/key/status verification
  -> usage and deployment impact graph
  -> customer maintenance policy
  -> maintenance job reservation
  -> isolated repository workspace
       -> affected-usage confirmation
       -> bounded maintenance agent
       -> tests/conformance/security checks
       -> patch + maintenance receipt
  -> AgentPass GitHub App
  -> Draft PR
  -> customer review / branch protection
  -> merge
  -> AgentPass Publish Plan delta
  -> protected deployment + post-deploy verification
```

### 6.1 Advisory registry

The registry stores immutable signed advisories, provider key history,
revocations, supersession, and ingestion evidence. An advisory cannot be edited
after publication. A correction or withdrawal is a new signed statement that
references the prior advisory.

Advisories may originate from:

1. a verified API provider;
2. an AgentPass-maintained neutral feed;
3. an organization-private internal API provider.

Origin is always visible. AgentPass must not present a neutral inference as a
provider-authored statement.

### 6.2 Usage and deployment impact graph

AgentPass builds an evidence graph from:

- `agentpass.app.json` connection and egress declarations;
- OpenAPI/GraphQL/AsyncAPI client generation metadata;
- package and SDK identities from SBOM/lockfiles;
- import and call-site static analysis;
- endpoint/method/field/event usage fingerprints;
- provider API/version headers observed through the egress broker;
- deployed release and source/artifact identities;
- customer-confirmed API ownership mappings.

Raw request/response bodies and customer data are not needed for the index.
Runtime observations must be privacy-preserving and policy-controlled.

Impact classifications:

- `confirmed`: exact endpoint/method/field/SDK usage matches advisory;
- `probable`: package/version and call shape match but exact use is unresolved;
- `possible`: provider dependency exists without enough usage evidence;
- `not_affected`: exact supported negative evidence;
- `unknown`: insufficient or stale evidence.

Only `confirmed` may qualify for later automatic modes. Private alpha may create
Draft PRs for `confirmed` and `probable`, clearly labeled.

### 6.3 Maintenance orchestrator

The orchestrator is a durable state machine. It reserves each effect before
calling GitHub, a sandbox, model provider, or runtime provider and reconciles
uncertain results before retrying.

It must bind:

- organization, repository, application, and active release;
- provider and advisory identity;
- source commit and branch protection context;
- maintenance policy generation;
- agent, model, prompt/template, toolchain, sandbox, and time limits;
- allowed paths, operations, network destinations, and test commands;
- GitHub App installation and repository identity;
- output patch and evidence digests.

### 6.4 Repository connector

The private alpha uses a GitHub App with repository selection and the minimum
permissions required for reading contents, creating an AgentPass branch, and
opening/updating a pull request. It does not request organization administration,
secrets, environments, actions secrets, or workflow permission.

Write authority is exercised only by a short-lived installation token inside a
fixed repository-operation service. The maintenance agent never receives the
token. It submits a content-addressed patch to the service; the service verifies
the maintenance grant, expected base commit, allowed paths, patch limits, and
branch name before applying it.

Workflow files under `.github/workflows/`, CODEOWNERS, branch-protection files,
AgentPass policy, deployment credentials, and security configuration are denied
by default even when the GitHub App installation technically has contents
write authority.

### 6.5 Isolated maintenance workspace

The workspace uses the same untrusted-code boundary as Small Software builds,
with additional restrictions:

- checkout one exact base commit;
- no customer or provider credentials;
- no access to another repository or maintenance job;
- default-deny egress except bounded package mirrors, model/tool endpoints, and
  explicitly allowed provider conformance hosts;
- fixed maximum patch size, file count, execution time, processes, output, and
  spend;
- immutable base tree and content-addressed result tree;
- command and network audit without secret/request-body capture;
- full destruction after evidence commit.

The provider may supply transformation hints or an agent package. Provider code
is untrusted and runs inside the same sandbox. It cannot alter AgentPass policy,
verification commands, evidence generation, or GitHub operations.

## 7. Canonical contracts

Every contract follows ADR-003 authority ownership, versioning, canonical JSON,
unknown-field rejection, tenant/actor binding, purpose-separated signatures,
and replay/idempotency rules.

### 7.1 `agentpass.api-provider-identity` v1

Contains:

- provider ID, verified domains, legal/display name, and status;
- signing keys by purpose and validity interval;
- advisory and optional provider-agent capabilities;
- supported API/product namespaces;
- verification method and AgentPass approval record;
- key rotation, compromise, suspension, and revocation metadata.

Provider domain control alone is insufficient for privileged automation.
Provider identities require AgentPass review and customer trust policy.

### 7.2 `agentpass.api-change-advisory` v1

Required identity and lifecycle:

- provider/advisory/API IDs;
- advisory version, release time, enforcement time, and optional sunset time;
- severity: informational, low, medium, high, critical;
- supersedes/withdraws relationships;
- old/new API, SDK, schema, and documentation digests;
- signature purpose, key ID, algorithm, and signature.

Change selectors:

- HTTP method, normalized path template, parameter, request/response field;
- event/webhook topic and payload field;
- GraphQL type/field/argument;
- SDK package, version range, symbol, and call signature;
- authentication method, OAuth scope, error, rate, or idempotency behavior;
- semantic tag when structure alone cannot express the change.

Migration material:

- human explanation;
- structured preconditions and transformation hints;
- examples as data, not executable authority;
- provider conformance test identity;
- required manual checks and known limitations.

OpenAPI Overlay documents may be attached as repeatable API-description
transformations, but they do not authorize source-code changes.

### 7.3 `agentpass.api-usage-attestation` v1

Contains one repository/release usage finding:

- organization, app/repository, source commit, and release identities;
- provider, API, SDK, endpoint/field/symbol fingerprints;
- evidence sources and freshness;
- impact classification and confidence explanation;
- analyzer/tool version and result digest;
- no raw source, request body, response body, secret, or customer data.

### 7.4 `agentpass.maintenance-policy` v1

Contains:

- allowed providers and trusted key status;
- repositories/apps/branches/paths;
- automation mode and risk ceiling;
- allowed agent/model/toolchain identities;
- test commands and required status checks;
- egress, time, token, patch, file, and cost limits;
- denied sensitive paths and change classes;
- reviewer/CODEOWNER requirements;
- deadline/escalation/ignore policy;
- merge, republish, rollback, and post-deploy rules;
- policy generation and approval identity.

### 7.5 `agentpass.maintenance-plan` v1

The plan is the exact job authorization preimage:

- advisory and usage-attestation digests;
- repository, app, base commit, branch, and active release;
- effective maintenance policy and authority intersection;
- requested/allowed paths, operations, tools, tests, network, budget, and TTL;
- provider migration material digests;
- human approval requirement and risk classification;
- idempotency and execution nonce.

### 7.6 `agentpass.maintenance-receipt` v1

The receipt binds:

- plan, advisory, provider, repository, base commit, and active release;
- agent/model/toolchain/sandbox identities;
- result commit/tree/patch and changed-path digests;
- commands, tests, conformance, scanners, and terminal results;
- authority requested, effective, and actually used;
- network destinations and package identities;
- PR repository/number/head/base identities;
- unresolved uncertainty and human checks;
- creation/expiry times and AgentPass signature.

A maintenance receipt proves process and binding, not semantic correctness.

## 8. Maintenance grant

The new `agentpass.maintenance-grant` is purpose-separated from Git-signing and
Small Software application grants.

Allowed private-alpha operations:

- `repository.snapshot.read`;
- `repository.patch.propose`;
- `repository.branch.create` through the fixed connector;
- `repository.pull_request.create` through the fixed connector;
- `maintenance.test.execute` inside the sandbox;
- `provider.conformance.execute` against approved hosts.

Explicitly absent:

- merge;
- default-branch push;
- workflow modification;
- secret read/write;
- environment/deployment modification;
- organization/repository administration;
- arbitrary GitHub API;
- production data or provider credential access.

The effective grant is the intersection of organization maintenance policy,
repository policy, advisory trust, usage evidence, actor role, Agent Session,
branch/path restrictions, sandbox policy, connector policy, and job TTL.

## 9. Cloud API additions

Provider routes:

```text
POST /v1/api-providers/registrations
POST /v1/api-providers/{provider}/keys
POST /v1/api-providers/{provider}/advisories
POST /v1/api-providers/{provider}/advisories/{advisory}/supersede
POST /v1/api-providers/{provider}/advisories/{advisory}/withdraw
GET  /v1/api-providers/{provider}/advisories
```

Customer human routes:

```text
POST /v1/organizations/{org}/repository-installations
GET  /v1/organizations/{org}/repositories
POST /v1/organizations/{org}/maintenance-policies
GET  /v1/organizations/{org}/maintenance/impacts
POST /v1/organizations/{org}/maintenance/jobs
GET  /v1/organizations/{org}/maintenance/jobs/{job}
POST /v1/organizations/{org}/maintenance/jobs/{job}/cancel
POST /v1/organizations/{org}/maintenance/jobs/{job}/approve
POST /v1/organizations/{org}/maintenance/jobs/{job}/ignore
GET  /v1/organizations/{org}/maintenance/jobs/{job}/receipt
```

GitHub webhook and internal worker routes use separate workload/repository
authentication namespaces. Webhook signature verification does not grant human
or provider authority; it only authenticates the event source.

## 10. PostgreSQL data model

| Relation | Purpose |
| --- | --- |
| `api_providers` | verified provider identity and lifecycle |
| `api_provider_keys` | purpose-separated signing key history |
| `api_change_advisories` | immutable signed advisory envelopes |
| `api_change_advisory_events` | publish, supersede, withdraw, compromise |
| `repository_installations` | exact GitHub App installation/repository binding |
| `repository_source_snapshots` | source commit/tree and usage-index identity |
| `api_usage_attestations` | tenant-bound affected-usage evidence |
| `maintenance_policies` | versioned customer automation policy |
| `maintenance_jobs` | durable job lifecycle and exact plan digest |
| `maintenance_job_effects` | sandbox/GitHub/provider uncertain-operation ledger |
| `maintenance_results` | patch/tree/tests/evidence identities |
| `maintenance_pull_requests` | exact GitHub PR/base/head/reconciliation state |
| `maintenance_receipts` | immutable signed public receipt metadata |
| `maintenance_exceptions` | audited ignore/waiver/deadline decisions |

Authority requirements:

- provider relations and tenant customer relations use separate roles;
- provider identity cannot query customer repository or impact relations;
- app role cannot directly mutate advisory, policy, job authority, PR effect,
  replay, idempotency, or audit relations;
- job reservation, effect reservation, completion, cancellation, and response-
  loss reconciliation use authority-owned functions with fixed lock order;
- every customer row carries `organization_id` and RLS;
- GitHub installation IDs and repository node IDs are provider identifiers, not
  tenant authority without the stored organization binding;
- source, patch, logs, prompts, tokens, and raw provider documents live outside
  authority tables under content-addressed, tenant-bound retention policy.

## 11. State machines

### 11.1 Advisory

```text
received -> verified -> active -> superseded | withdrawn | suspended
                    -> rejected
```

A provider key compromise suspends affected active advisories and blocks new
jobs until customer/AgentPass policy decides how to handle previously generated
patches.

### 11.2 Maintenance job

```text
impact_detected
  -> planned
  -> authorized
  -> workspace_preparing
  -> patching
  -> verifying
  -> pr_creating
  -> pr_open
  -> awaiting_customer
  -> merged
  -> release_preparing
  -> deployed
  -> post_deploy_verified
  -> completed
```

Side/terminal states:

```text
not_affected | ignored | cancelled | patch_failed | verification_failed |
pr_failed | provider_operation_uncertain | superseded | merge_failed |
deployment_failed | rolled_back | manual_action_required
```

No retry occurs across an uncertain external effect until reconciliation proves
the prior effect absent, present, or safely resumable.

## 12. Verification policy

Verification layers are recorded independently:

1. advisory signature and provider identity;
2. exact affected-usage confirmation;
3. syntax/type/build checks;
4. existing repository test suite;
5. AgentPass-generated regression tests;
6. provider conformance tests;
7. static security and secret scan;
8. permission/API-scope/egress/data authority delta;
9. preview deployment and smoke test;
10. post-merge/post-deploy observation.

An agent-generated test cannot be the sole proof of the behavior it introduced.
Organization-required pre-existing tests and branch protection remain separate
evidence. Missing layers are displayed as `not_run` or `not_proven`, not green.

## 13. Security and abuse model

### 13.1 Primary threats

- malicious or compromised API provider publishes a weaponized advisory;
- provider migration agent exfiltrates source or injects a backdoor;
- provider key rotation/compromise is confused with valid continuity;
- advisory selectors intentionally overmatch unrelated repositories;
- agent uses repository access outside the affected paths;
- generated patch modifies workflow, policy, auth, or deployment controls;
- source or patch changes between impact analysis, tests, PR, and merge;
- test generation hides failure or deletes assertions;
- dependency confusion or package install scripts compromise the workspace;
- GitHub token leaks to the agent, model, logs, or provider code;
- cross-tenant repository, source, advisory subscription, or PR confusion;
- provider/GitHub response loss creates duplicate branches or PRs;
- automatic merge widens secrets, OAuth scopes, egress, or production authority;
- PR comments or repository contents prompt-inject the maintenance agent;
- runtime breakage persists after a green but insufficient patch.

### 13.2 Mandatory invariants

1. Provider authority ends at a signed advisory; it never becomes repository
   authority.
2. The maintenance agent never receives a GitHub installation token or customer
   secret.
3. Every patch binds one advisory, one repository, one base commit, one plan,
   one job, and one result tree.
4. The connector applies only a content-addressed patch to the expected base and
   approved paths.
5. No default-branch push or merge in the private alpha.
6. Workflow, policy, secrets, auth, deployment, and sensitive paths are denied
   by default.
7. Provider-supplied code runs as untrusted code inside the sandbox.
8. Agent-generated tests do not replace customer tests or branch protection.
9. Authority widening requires a new human approval even after a PR is merged.
10. Revocation of provider, policy, Agent Session, repository installation, or
    emergency state blocks new effects immediately.
11. Unknown GitHub/provider/sandbox effect state is reconciled before retry.
12. Audit records contain digests and safe metadata, never source, secrets,
    tokens, prompts containing code, or customer payloads.

## 14. Initial supported change classes

Private alpha supports TypeScript and JavaScript changes where impact can be
confirmed structurally:

- SDK package/version and renamed symbol;
- HTTP endpoint path or method change;
- request/response field rename with explicit provider mapping;
- required/removed parameter;
- pagination envelope change;
- error-code handling change with fixtures;
- API version header change;
- webhook/event payload field change with fixtures.

Excluded initially:

- semantic business-logic rewrites without machine-verifiable behavior;
- payment, money movement, authentication, authorization, cryptography, or data
  deletion logic;
- migrations needing real production customer data;
- changes requiring new OAuth scopes or secrets;
- mobile/native clients;
- arbitrary internal repositories without an app/release/source identity;
- auto-merge or auto-production deployment.

## 15. Product metrics

North-star metric:

> API-breaking changes resolved by verified customer PR before enforcement.

Activation and value metrics:

- repositories connected with a maintenance policy;
- deployed apps with a current usage index;
- confirmed impacts detected before deadline;
- median advisory-to-Draft-PR time;
- percentage of generated PRs accepted with minor/no edits;
- incidents prevented and estimated engineer time saved;
- apps remaining healthy across API enforcement dates;
- provider adoption and customers covered per provider.

Guardrails:

- false-positive impact rate;
- incorrect or reverted patch rate;
- security/policy-denied patch rate;
- customer source exposure incidents;
- provider key/advisory incidents;
- duplicate PR/effect reconciliation rate;
- auto-mode rollback rate when later enabled;
- unreviewed authority widening: target zero.

## 16. Business model and network effects

Customer side:

- maintenance included with active AgentPass Cloud apps;
- paid tiers based on protected repositories/apps, maintenance jobs, and
  verification/runtime usage;
- enterprise BYOC, SSO/SCIM, policy packs, evidence retention, and support.

Provider side:

- free signed advisory publishing and basic customer-impact analytics;
- paid provider migration agent, conformance infrastructure, rollout cohorts,
  deadline management, support routing, and verified migration performance;
- internal API provider mode for enterprise platform teams.

Potential network effect:

- more customer apps produce better privacy-preserving usage fingerprints;
- more providers publish structured changes and tests;
- AgentPass learns robust migration patterns and policy classifications;
- customers prefer APIs that maintain their integrations automatically;
- providers prefer AgentPass because migration completion reduces support and
  version fragmentation.

The graph and evidence history, not the model prompt, becomes the defensible
asset.

## 17. Implementation plan

### Phase SM-0 — Contracts and one design provider

Goal: prove one API change can be represented and mapped to real code.

Deliverables:

- select one design provider or an internal sample API with old/new OpenAPI and
  SDK versions;
- collect 10 real affected repositories/apps;
- freeze provider identity, advisory, usage attestation, maintenance policy,
  plan, grant, and receipt contracts;
- create signed fixture advisories for five supported change classes;
- implement offline advisory verification and static usage matching prototype;
- design the Maintenance Console flow and PR evidence template.

Exit criteria:

- exact structural impact is confirmed in at least seven collected apps;
- false-positive/unknown cases are measured, not hidden;
- a security review accepts the provider/customer authority split;
- customers accept Draft PR as the first automation boundary.

Estimated focused effort: 1–2 weeks.

### Phase SM-1 — Impact graph and notify mode

Goal: detect affected deployed Small Software before the deadline.

Work items:

- **SM-101:** add `apps/cloud-api/src/maintenance/` domain modules;
- **SM-102:** add provider/advisory PostgreSQL migrations, repositories, RLS,
  authority functions, roles, and contract catalog entries;
- **SM-103:** extend app manifest/build/SBOM output with API usage fingerprints;
- **SM-104:** implement advisory ingestion, signature verification,
  supersession, withdrawal, and key-compromise handling;
- **SM-105:** implement exact/probable/possible impact classifier;
- **SM-106:** add Console advisory/impact/subscription/policy surfaces;
- **SM-107:** add notification, deadline, exception, and escalation worker;
- **SM-108:** qualify cross-tenant, stale-index, provider-key, overmatch, and
  replay behavior.

Exit criteria:

- signed advisory ingestion is idempotent and immutable;
- affected deployed apps are visible with evidence and freshness;
- provider cannot query customer source or app identities;
- withdrawal/key compromise prevents new jobs and updates prior-job status;
- deadline notification and ignore decisions are audited.

Estimated focused effort: 3–5 weeks after SM-0.

### Phase SM-2 — Isolated patch and Draft PR

Goal: produce a bounded, verified Draft PR without exposing repository tokens.

Work items:

- **SM-201:** implement GitHub App installation and exact repository binding;
- **SM-202:** implement source snapshot and content-addressed checkout;
- **SM-203:** add maintenance policy, plan, grant, job, result, PR, and effect
  migrations/repositories;
- **SM-204:** compose the isolated maintenance agent and fixed tool interface;
- **SM-205:** implement fixed repository-operation service and token isolation;
- **SM-206:** implement patch validation, sensitive-path denial, limits, and
  expected-base checks;
- **SM-207:** implement test/conformance/security verification pipeline;
- **SM-208:** implement PR body, labels, receipt, and response-loss
  reconciliation;
- **SM-209:** add MCP/CLI status and Console job/receipt controls;
- **SM-210:** run adversarial provider-agent, prompt-injection, token, path,
  patch, GitHub uncertainty, and cross-tenant tests.

Exit criteria:

- one supported advisory produces correct Draft PRs in at least five real apps;
- maintenance agent never observes the GitHub token;
- branch/PR creation is limited to the exact repository/base/paths/plan;
- sensitive paths and widened authority are blocked or escalated;
- duplicate/uncertain GitHub operations reconcile without duplicate PRs;
- receipt binds advisory through exact PR head tree and test evidence.

Estimated focused effort: 5–8 weeks after SM-1.

### Phase SM-3 — Merge-to-publish verification

Goal: connect accepted maintenance PRs to protected Small Software releases.

Work items:

- **SM-301:** consume signed GitHub merge webhook through exact installation,
  repository, PR, base, and head binding;
- **SM-302:** create new immutable source/release identity after merge;
- **SM-303:** run Publish Plan authority delta and approval classification;
- **SM-304:** deploy private preview and execute post-change conformance checks;
- **SM-305:** implement customer approval, activation, post-deploy observation,
  rollback, and advisory completion;
- **SM-306:** expose provider/customer completion analytics without customer
  source or data leakage;
- **SM-307:** qualify merge races, stale base, force-push, changed PR head,
  deployment uncertainty, runtime failure, and rollback.

Exit criteria:

- merged bytes must equal the verified/reviewed head or trigger re-verification;
- authority delta cannot be bypassed by a maintenance label or receipt;
- post-deploy failure prevents completion and follows explicit rollback policy;
- provider sees aggregate completion, not customer source or sensitive metadata;
- full advisory→impact→PR→merge→release→runtime evidence chain verifies.

Estimated focused effort: 4–6 weeks after SM-2 and Small Software SS-2.

### Phase SM-4 — Provider platform and safe automation

Goal: support external providers and carefully unlock higher automation modes.

Deliverables:

- provider onboarding, domain/legal verification, key rotation/compromise,
  advisory authoring/validation, sandbox tests, and rollout cohorts;
- internal enterprise API-provider mode;
- verified PR policy for low-risk supported changes;
- later auto-merge/auto-publish only for exact no-authority-delta policies;
- billing, quotas, abuse detection, retention, privacy export/deletion, incident
  response, provider/customer dispute handling, and support diagnostics;
- independent repository-integration, sandbox, supply-chain, and provider-
  authority security reviews;
- protected real GitHub, WebAuthn, PostgreSQL, runtime, rollback, and provider
  key-compromise qualification.

Exit criteria:

- critical/high findings closed;
- provider compromise and malicious advisory drills pass;
- customer repository removal immediately blocks new access/effects;
- auto modes are off by default and bounded by immutable organization policy;
- observed rollback/incorrect-patch rate remains below the beta threshold;
- operational owner, on-call, alerts, kill switch, and evidence retention active.

Estimated focused effort: 6–10 weeks after SM-3. External qualification and
provider onboarding determine elapsed time.

## 18. Dependency on Small Software Cloud

The two products can launch in stages:

```text
Small Software SS-0/SS-1
  -> deployed app/release/source/SBOM identity
  -> Self-Maintaining SM-0/SM-1 impact detection

Small Software SS-2
  -> protected ingress and promotion
  -> Self-Maintaining SM-2 Draft PR

Small Software SS-3
  -> data/egress/connector authority
  -> Self-Maintaining SM-3 authority-delta and republish
```

Self-Maintaining APIs should not block the first `agentpass publish` alpha.
However, the initial app manifest, SBOM, build receipt, source identity, egress
declarations, and deployment receipt must be designed so the maintenance plane
can consume them without a breaking migration.

## 19. Go-to-market demonstration

The combined launch story is stronger than either feature alone:

1. An agent builds a customer tracker using a sample CRM API.
2. `agentpass publish` creates a protected team URL.
3. The API provider publishes a breaking field change.
4. AgentPass identifies the exact affected call site.
5. A bounded maintenance agent opens a Draft PR with tests.
6. The user merges it.
7. AgentPass republishes the exact release after authority review.
8. The app remains available and the full evidence chain is visible.

Positioning:

> Deploy AI-built software safely. Keep it working automatically.

## 20. Immediate decisions

Recommended defaults:

1. GitHub only for the private alpha.
2. TypeScript/JavaScript only.
3. OpenAPI plus SDK symbol changes first.
4. Small Software apps first; arbitrary external repositories later.
5. Notify and Draft PR modes only.
6. Selected repositories, never organization-wide repository access by default.
7. No workflow-file modification.
8. No agent access to GitHub tokens or customer secrets.
9. No auto-merge or auto-publish before SM-4.
10. One design provider or sample API before building a provider marketplace.

## 21. Primary external references

- Y Combinator, “Self-Maintaining APIs”: https://www.ycombinator.com/rfs
- GitHub App permission design:
  https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app
- GitHub App versus OAuth permission model:
  https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/deciding-when-to-build-a-github-app
- GitHub Dependabot pull request model:
  https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/supply-chain-security/dependabot-pull-requests
- OpenAPI Overlay Specification:
  https://spec.openapis.org/overlay/latest.html
