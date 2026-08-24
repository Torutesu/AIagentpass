# AgentPass Small Software Cloud — Product and Implementation Specification

Status: proposed implementation contract; not a production-readiness claim  
Date: 2026-08-25  
Working name: AgentPass Cloud / AgentPass Publish

## 1. Executive decision

AgentPass will expand from a coding-agent authorization broker into the trust
and control plane for small software created by AI agents.

The first product is not a new general-purpose compute cloud. The first product
is a safe publishing path on top of an existing platform runtime:

```text
Prompt
  -> coding agent builds an app
  -> AgentPass analyzes the app and its requested authority
  -> a human approves one exact immutable release
  -> AgentPass deploys it behind identity and access policy
  -> teammates receive a protected URL
  -> AgentPass audits, expires, suspends, rolls back, or deletes it
```

The product promise is:

> Turn an AI-built internal app into a protected, shareable URL in under three
> minutes, without opening a cloud console or copying a secret.

The durable moat is not source-code generation or commodity hosting. It is the
cross-agent authorization, release provenance, user access, secret mediation,
audit, revocation, and lifecycle system that makes generated software safe to
use inside a real organization.

## 2. Strategic position

### 2.1 Category

AgentPass is the secure cloud control plane for Small Software:

- **Build plane:** Claude Code, Codex, Cursor, or another coding agent.
- **Trust plane:** AgentPass.
- **Runtime plane:** Cloudflare first; other providers through adapters later.
- **Human surface:** AgentPass Console and the one-command CLI journey.

### 2.2 Initial ideal customer profile

The initial customer is a 5–200 person company whose employees already create
small internal tools with coding agents but cannot safely share or operate
those tools.

Primary users:

1. A non-engineering operator building a CRM, tracker, dashboard, or workflow.
2. A technical team lead allowing team members to create internal tools.
3. An IT/security owner who needs access control, audit, expiry, and emergency
   stop without reviewing every generated line of code.

### 2.3 Job to be done

> When an agent has built a useful internal app, let me share it with the right
> people immediately, without learning IAM, OAuth, databases, DNS, or secret
> management, while keeping my company data and credentials under control.

### 2.4 Positioning boundary

AgentPass must not initially compete on:

- model quality or chat-based code generation;
- general container hosting;
- global CDN or database infrastructure;
- arbitrary framework support;
- a replacement for AWS, Azure, Cloudflare, Vercel, or Supabase.

It competes on the protected path from generated code to authorized use.

## 3. Product principles

1. **One normal command.** The regular path is `agentpass publish`, not a list
   of provider, OAuth, database, IAM, and DNS commands.
2. **The agent requests; the human authorizes.** An agent may prepare a preview
   and publish plan. It may not widen audience, data, secrets, egress, cost, or
   lifetime without a new human authorization.
3. **Approval binds immutable bytes.** A passkey approval covers one canonical
   release digest and one exact authority plan. A changed artifact requires a
   new approval.
4. **No plaintext production credentials in generated code.** Credentials are
   stored in a managed secret boundary and exposed only through constrained
   bindings or an egress broker.
5. **Private by default.** New apps are accessible only to the creator until an
   explicit audience is approved.
6. **Expiry by default.** Preview and alpha apps expire automatically. An owner
   may explicitly convert a release to a longer-lived production lifecycle.
7. **Fail closed.** Missing identity, stale policy, unverified artifact,
   unavailable revocation, or unknown provider state denies new authority.
8. **Provider portability.** AgentPass owns the application, release, access,
   policy, and audit contracts. A runtime adapter owns provider-specific calls.
9. **No false production claims.** Static tests and local emulators are not
   evidence of runtime isolation, tenant separation, passkey correctness,
   revocation propagation, or provider deployment.

## 4. User experience specification

### 4.1 First publish

The creator works in the app project and asks the coding agent to publish.
The agent invokes the AgentPass MCP tool or the user runs:

```sh
agentpass publish
```

AgentPass performs the following journey:

1. Detect the project, framework, package manager, Git state, and supported
   runtime target.
2. Build a source inventory that excludes `.git`, local caches, `.env*`, key
   files, credentials, and ignored files.
3. Scan dependencies, routes, data declarations, environment references,
   outbound hosts, scheduled work, and requested platform bindings.
4. Upload the bounded source bundle to an isolated build sandbox, or resolve an
   exact Git commit when the project is already pushed.
5. Produce a preview and a canonical Publish Plan.
6. Open AgentPass Console in the system browser through the existing bounded
   browser/CLI handoff.
7. Show the human a plain-language approval screen.
8. After approval, deploy the exact release behind the AgentPass ingress
   gateway and return a protected URL.

The CLI output must be short and human-readable:

```text
AgentPass analyzed “Sales Follow-up”.

Who can open it: You only
Data: New isolated database
External access: api.hubspot.com
Secrets: HubSpot connection through AgentPass
Expires: 7 days
Estimated monthly ceiling: organization policy limit

Review opened in your browser.
```

### 4.2 Approval screen

The primary approval surface must show, above the fold:

- app name and recognizable project path/repository;
- preview screenshot and protected preview link;
- exact audience: creator, named people, group, or organization;
- release lifetime and automatic deletion/retention behavior;
- data stores created and existing systems requested;
- secrets/connections requested, described by service and purpose;
- outbound network destinations;
- scheduled/background work;
- cost ceiling and resource limits;
- material change from the previous active release;
- human-readable risk summary.

The primary action is `Approve and publish`. High-risk or production promotion
requires a fresh passkey ceremony bound to the release and Publish Plan digest.
The secondary action is `Keep private preview`. Denial requires no explanation.

### 4.3 Sharing

The creator can share an active app using:

- named organization members;
- an organization group;
- everyone in the organization;
- an exact verified email address, when guest sharing is allowed by policy.

Public anonymous links are out of scope for the private alpha. Share links are
not bearer credentials. Every request passes through the ingress identity and
authorization boundary.

Default sharing policy:

- new app: creator only;
- preview lifetime: 24 hours;
- first active release lifetime: 7 days;
- guest access: disabled;
- organization-wide access: owner policy-controlled;
- access renewal: explicit, audited action;
- deleted/expired app: immediately unroutable.

### 4.4 Update and rollback

Running `agentpass publish` against an existing project creates a new immutable
release. AgentPass shows only the material authority delta:

- new audience;
- new or widened egress;
- new secret or data binding;
- destructive schema migration;
- increased limit or lifetime;
- new scheduled task;
- change from read to write authority.

Code-only changes that do not widen authority may use the organization policy's
reduced approval mode. Any authority widening always requires fresh approval.

Rollback switches routing to a previously approved immutable release. It does
not roll back database state automatically. A release with an incompatible or
destructive migration must declare and pass a separate rollback plan.

### 4.5 Suspend, expire, and delete

- **Suspend:** deny ingress and egress immediately; retain state for recovery.
- **Expire:** automatic suspension at the approved deadline.
- **Delete:** remove routing, runtime deployment, bindings, and data according
  to retention policy; produce a deletion receipt.
- **Emergency stop:** organization owner denies all Small Software ingress,
  egress, deployment, and new capability issuance while preserving evidence.

## 5. MVP scope

### 5.1 Included in private alpha

- macOS creator flow through Claude Code, Codex-compatible CLI, and Cursor/MCP;
- JavaScript/TypeScript projects with one supported AgentPass web-app profile;
- static assets plus a Cloudflare Worker-compatible API;
- one isolated database per app where the profile declares relational data;
- AgentPass organization identity and named-member access;
- creator-only and organization-member sharing;
- private preview, active release, expiry, suspend, rollback, and delete;
- exact release provenance and Publish Plan approval;
- per-app resource limits, request limits, and outbound-domain allowlist;
- per-app activity/audit view;
- Cloudflare runtime adapter only;
- hosted AgentPass control plane plus OSS local agent connector.

### 5.2 Explicitly excluded from private alpha

- arbitrary Docker images, native binaries, GPU workloads, or long-running
  stateful servers;
- arbitrary database engines or connecting generated code directly to a
  production database;
- public anonymous apps;
- custom domains;
- customer-supplied arbitrary OAuth scopes;
- inbound webhooks from unverified providers;
- marketplace templates executing privileged connectors;
- automatic destructive database migrations;
- multi-region data residency guarantees;
- provider portability in the UI, despite the internal adapter boundary.

## 6. System architecture

```text
Coding agent / CLI
        |
        | short-lived Agent Session + source/repo binding
        v
AgentPass Publish API
        |
        +--> Source scanner / manifest normalizer
        |
        +--> Isolated build sandbox --> immutable artifact + SBOM + preview
        |
        +--> Publish Plan authority diff
        |
        v
Human approval / WebAuthn
        |
        v
Promotion authority + deployment orchestrator
        |
        +--> Runtime adapter --> Cloudflare Workers for Platforms
        +--> Data adapter ----> isolated per-app data binding
        +--> Secret broker ---> provider connection / egress mediation
        |
        v
AgentPass ingress gateway
        |
        +--> human identity + app access policy
        +--> rate/cost/abuse controls
        +--> release routing
        v
Isolated user Worker
```

### 6.1 Control plane

The existing AgentPass Cloud API remains authoritative for organizations,
memberships, human sessions, devices, agents, policies, capabilities,
revocations, and audit. Small Software adds application and deployment
resources; it does not introduce a second identity or authorization system.

### 6.2 Data plane

The first data plane is Cloudflare Workers for Platforms behind an AgentPass
dispatch/ingress Worker. User code runs in a per-application isolated Worker.
The direct provider URL is not the canonical product URL and must not bypass
AgentPass ingress authorization.

### 6.3 Build plane

Generated code is untrusted. Builds run in a remote ephemeral sandbox with:

- no AgentPass production credentials;
- no organization database access;
- no creator device access;
- bounded CPU, memory, disk, time, processes, and output bytes;
- blocked metadata-service and private-network access;
- default-deny outbound access with a build-specific package mirror policy;
- complete command, dependency, and artifact-digest recording;
- destruction after the artifact and sanitized evidence are committed.

The production runtime never reuses a mutable build workspace.

### 6.4 Ingress gateway

Every application request enters through an AgentPass-owned gateway that:

1. resolves the organization, app, active release, and route;
2. validates the human session or supported service identity;
3. checks app access policy, expiry, suspension, and organization emergency
   state;
4. applies rate, request-size, method, and abuse limits;
5. creates a bounded signed runtime context for the user Worker;
6. dispatches to the exact active release;
7. records a privacy-preserving access event.

The user Worker receives only the minimum identity projection needed by the
app, for example opaque subject, organization/app roles, and request ID. It
does not receive the AgentPass session cookie.

### 6.5 Egress and secret broker

Generated code must not receive raw long-lived connector credentials. For MVP,
external service access uses an AgentPass egress binding:

```text
User Worker
  -> signed app/release/request context
  -> AgentPass egress broker
  -> policy check: service, operation, resource, rate, purpose
  -> provider credential use
  -> redacted result
```

An egress capability binds:

- organization, app, release, and deployment;
- connector and provider account;
- allowed operation and resource scope;
- method and destination host;
- data classification ceiling;
- maximum calls/bytes/cost;
- issuance, expiry, nonce, and sequence;
- policy and connector versions.

The first private alpha may allow simple HTTPS egress to an approved domain
without credentials. Privileged connectors ship only after the broker boundary
and provider-specific schemas are complete.

### 6.6 Existing AgentPass assets to reuse

This direction is an extension of the current architecture, not a rewrite:

| Existing asset | Small Software use |
| --- | --- |
| Human sessions, organizations, memberships, roles | creator and app-user identity |
| WebAuthn and recent-auth operations | release, privileged connector, deletion approval |
| Devices, agents, Agent Sessions | bind the publishing request to an enrolled device, process, and project |
| Capability signing and narrowing | reusable cryptographic patterns for app-scoped grants |
| Platform promotion authority/evidence | basis for immutable release promotion |
| Revocation and emergency stop | suspend app access, egress, and deployment authority |
| Audit chain, ingestion, export | release/access/lifecycle evidence |
| Hosted bootstrap and browser/CLI handoff | one-command review and approval journey |
| Console organization/security surfaces | app, release, sharing, and activity control UI |
| Release qualification and installed receipt | trust the local creator and CLI distribution |

The existing v1 Git capability must not be widened in place. Its operation and
repository-oriented scope are intentionally narrow. Small Software introduces
new versioned contracts and purpose-separated signing keys while reusing the
same fail-closed and effective-intersection design.

## 7. Canonical contracts

All new public, durable, signed, or cross-process structures require versioned
catalog entries under the existing contract-authority rules.

### 7.1 `agentpass.app-manifest` v1

The repository may contain `agentpass.app.json`:

```json
{
  "version": 1,
  "kind": "agentpass.app-manifest",
  "name": "sales-follow-up",
  "runtime": "cloudflare-worker",
  "entrypoint": "dist/worker.js",
  "static_assets": "dist/public",
  "data": [
    { "name": "app_db", "kind": "isolated_sql", "migration_dir": "migrations" }
  ],
  "egress": [
    { "origin": "https://api.hubspot.com", "methods": ["GET", "POST"] }
  ],
  "connections": [
    { "name": "hubspot", "kind": "managed_oauth", "operations": ["contacts.read"] }
  ],
  "schedules": [],
  "health_path": "/_agentpass/health"
}
```

Rules:

- unknown fields fail closed;
- names, paths, origins, methods, operations, and limits are canonicalized;
- paths cannot escape the real project root;
- environment-variable names are declarations, never values;
- manifest authority is a request ceiling, not automatic permission;
- generated defaults are written only with explicit user consent;
- a manifest cannot request an existing production database in v1.

### 7.2 `agentpass.source-bundle` v1

The source bundle statement contains:

- organization, app, project, agent session, and device identities;
- exact Git commit when available, dirty-tree digest, and included-file Merkle
  root;
- ignore policy version and file inventory digest;
- manifest digest, lockfile digests, and total bytes;
- scanner version and redacted finding summary;
- creation and expiry times.

The archive is content-addressed. Symlinks, hardlinks, device files, sockets,
absolute paths, path traversal, duplicate normalized paths, and files outside
the project root are rejected.

### 7.3 `agentpass.build-receipt` v1

The build service signs:

- source-bundle digest;
- builder image identity and sandbox instance identity;
- normalized build command and toolchain versions;
- dependency lock and SBOM digests;
- artifact digest and asset inventory digest;
- scanner policy/results digest;
- preview deployment identity;
- start/end times and terminal result.

### 7.4 `agentpass.publish-plan` v1

The Publish Plan is the exact human authorization preimage:

- organization, app, release, source, build, artifact, and preview identities;
- audience and app roles;
- lifetime, retention, and deletion policy;
- ingress routes and limits;
- data stores, migration digest, backup class, and rollback compatibility;
- egress origins, methods, connectors, operations, and quotas;
- schedule definitions;
- runtime/provider/resource ceiling;
- cost ceiling;
- policy version and authority delta from the active release;
- approval requirement and risk classification.

### 7.5 `agentpass.deployment-receipt` v1

The deployment receipt binds:

- approved Publish Plan digest;
- artifact digest;
- runtime provider and provider deployment/version IDs;
- ingress route and active release generation;
- data/secret binding identities without secret values;
- deployment orchestrator identity;
- timestamps, final state, and reconciliation evidence.

Provider success is not accepted from a single response. The orchestrator must
reconcile the provider deployment and routing state before marking a release
active.

### 7.6 `agentpass.application-grant` v1

Application grants are separate from the existing Git-signing capability. They
use a purpose-separated key and operations such as:

- `app.preview.prepare`;
- `app.release.request`;
- `app.release.activate`;
- `app.access.manage`;
- `app.suspend`;
- `app.rollback`;
- `app.delete`;
- `connector.invoke`.

An agent-facing grant in the private alpha may contain only
`app.preview.prepare` and `app.release.request`. Activation, access widening,
privileged connector use, rollback across incompatible data versions, and
deletion remain human-authority operations. The effective decision intersects
organization policy, app policy, release plan, actor role, session state,
provider state, and the short-lived grant.

## 8. CLI and agent interface

### 8.1 User commands

```text
agentpass publish [--name NAME] [--expires 7d] [--audience self|team]
agentpass publish status
agentpass apps list
agentpass apps open [APP]
agentpass apps suspend APP
agentpass apps rollback APP --release RELEASE
agentpass apps delete APP
```

Normal output is plain language. `--json` exposes strict, versioned, redacted
automation output. Advanced provider options are not present in the regular
user path.

### 8.2 MCP tools

- `agentpass_publish_prepare`: analyze and create/reuse a private preview.
- `agentpass_publish_status`: return redacted lifecycle state and next action.
- `agentpass_app_open`: open the protected app or Console detail page.
- `agentpass_app_logs`: bounded redacted logs for one app/release.

The agent can prepare and observe. It cannot approve, widen access, attach a
privileged connection, lift a quota, make a destructive migration, disable
audit, or suppress security findings.

### 8.3 Idempotency

Every mutation has a canonical idempotency identity bound to organization,
actor/session, operation, app, release, and request digest. Reusing a key with
different bytes fails closed. Response-loss reconciliation is mandatory for
build creation, approval, deployment, routing activation, rollback, suspend,
and delete.

## 9. Cloud API v1 additions

Human routes:

```text
POST   /v1/organizations/{org}/apps
GET    /v1/organizations/{org}/apps
GET    /v1/organizations/{org}/apps/{app}
POST   /v1/organizations/{org}/apps/{app}/releases
GET    /v1/organizations/{org}/apps/{app}/releases/{release}
POST   /v1/organizations/{org}/apps/{app}/releases/{release}/approval-options
POST   /v1/organizations/{org}/apps/{app}/releases/{release}/approve
POST   /v1/organizations/{org}/apps/{app}/releases/{release}/activate
POST   /v1/organizations/{org}/apps/{app}/access-rules
DELETE /v1/organizations/{org}/apps/{app}/access-rules/{rule}
POST   /v1/organizations/{org}/apps/{app}/suspend
POST   /v1/organizations/{org}/apps/{app}/rollback
POST   /v1/organizations/{org}/apps/{app}/delete
GET    /v1/organizations/{org}/apps/{app}/activity
```

Device/agent routes:

```text
POST /v1/organizations/{org}/devices/{device}/publish-requests
PUT  /v1/organizations/{org}/devices/{device}/publish-requests/{request}/source
POST /v1/organizations/{org}/devices/{device}/publish-requests/{request}/complete
GET  /v1/organizations/{org}/devices/{device}/publish-requests/{request}
```

Provider-worker routes are deployment-internal and use workload identity, not
human/device bearer credentials. They must live in a separate authentication
namespace.

Role defaults:

- viewer: open apps granted through access rules;
- auditor: read app/release/activity/security metadata;
- admin: create previews, manage ordinary access, suspend, and rollback;
- owner: approve production promotion, privileged connections, destructive
  migrations, organization-wide sharing, policy ceilings, and deletion.

Organization policy may narrow these defaults.

## 10. PostgreSQL data model

New tenant-scoped authority relations:

| Relation | Purpose |
| --- | --- |
| `small_software_apps` | stable app identity, owner, project binding, lifecycle |
| `small_software_releases` | immutable source/build/artifact identity and state |
| `small_software_publish_plans` | canonical requested/effective authority plan |
| `small_software_approvals` | human/WebAuthn approval bound to one plan digest |
| `small_software_deployments` | provider deployment and reconciliation state |
| `small_software_routes` | active generation and ingress route binding |
| `small_software_access_rules` | subject/group/org audience and app role |
| `small_software_data_bindings` | isolated data resource identities and versions |
| `small_software_connection_bindings` | managed connector identities and scopes |
| `small_software_egress_rules` | exact origins/methods/operations/limits |
| `small_software_lifecycle_jobs` | expiry, suspension, deletion, reconciliation work |
| `small_software_provider_operations` | uncertain provider operation ledger |
| `small_software_usage_daily` | bounded per-app usage and cost attribution |

Requirements:

- every row carries `organization_id` and is covered by tenant RLS;
- app/release IDs are UUIDs; user-visible slugs are not authority;
- immutable release fields cannot be updated after creation;
- approval, activation, route switch, and provider-operation reservation use
  authority-owned PostgreSQL functions with fixed lock order;
- application role cannot directly mutate approval, active route, provider
  operation, replay, or audit authority relations;
- lifecycle workers use separate least-privilege roles;
- source code, secrets, raw OAuth tokens, raw WebAuthn assertions, and session
  cookies are prohibited from these relations;
- large artifacts and source archives live in object storage by digest with
  tenant-bound metadata and retention controls.

## 11. Lifecycle state machines

### 11.1 Release

```text
requested
  -> source_received
  -> analyzing
  -> building
  -> preview_ready
  -> awaiting_approval
  -> approved
  -> deploying
  -> active

Terminal/side states:
  rejected | build_failed | deployment_failed | superseded | suspended |
  expired | deleting | deleted | reconciliation_required
```

No transition may skip required evidence. `deployment_failed` after an
uncertain provider response cannot be retried as a new deployment until the
original provider operation is reconciled.

### 11.2 Application

```text
draft -> private_preview -> active -> suspended -> active
                                  -> expired
                                  -> deleting -> deleted
```

The active route generation is monotonic. A stale worker or provider callback
cannot reactivate an older generation.

### 11.3 Access rule

```text
pending -> active -> expired | revoked
```

An access-rule change never mutates an existing signed Publish Plan. It creates
an audited access-policy generation, subject to the plan's approved audience
ceiling and organization policy.

## 12. Security and abuse model

### 12.1 Primary threats

- generated code exfiltrates secrets or company data;
- prompt injection causes the agent to request excessive authority;
- source archive escapes the project root or races during packaging;
- dependency/build scripts attack the build environment;
- user Worker bypasses ingress authentication through a provider URL;
- cross-tenant route, database, object, log, or connector access;
- stale approval is applied to changed bytes or a widened plan;
- provider timeout creates duplicate or unknown deployments;
- generated migrations destroy data or prevent rollback;
- unbounded loops, egress, storage, schedules, or traffic create cost abuse;
- app logs leak secrets, personal data, session cookies, or connector results;
- deleted/expired apps remain reachable through caches or stale routes.

### 12.2 Mandatory invariants

1. No active release without exact source, build, artifact, plan, approval, and
   deployment receipt bindings.
2. No application request without current ingress identity and access policy.
3. No direct user Worker access that bypasses AgentPass ingress.
4. No raw long-lived connector credential in source, build, Worker environment,
   logs, browser, or application database.
5. No authority widening without a new human approval.
6. No cross-tenant lookup based only on a user-controlled slug or provider ID.
7. No provider retry until uncertain prior state has been reconciled.
8. No destructive schema migration without backup evidence, explicit owner
   approval, and a declared recovery path.
9. Emergency stop and expiry deny ingress and privileged egress even if the
   Console or asynchronous worker is unavailable.
10. Audit and deletion receipts bind the exact release and provider resources.

### 12.3 Scanning is advisory, enforcement is authoritative

Static analysis may explain risk and block known prohibited patterns, but it
cannot prove generated code is safe. Runtime isolation, ingress authorization,
egress mediation, resource limits, tenant-bound data, and revocation are the
security boundary.

## 13. Provider adapter contract

The first interface is `RuntimeProviderV1`:

```text
createPreview(input) -> providerOperation
inspectPreview(operation) -> reconciled preview receipt
deployRelease(input) -> providerOperation
inspectDeployment(operation) -> reconciled deployment receipt
activateRoute(input) -> providerOperation
inspectRoute(operation) -> reconciled route receipt
suspendApp(input) -> providerOperation
deleteRelease(input) -> providerOperation
deleteApp(input) -> providerOperation
readUsage(input) -> normalized usage
```

Each input includes organization, app, release, artifact, plan, idempotency,
expected generation, and limit bindings. Provider credentials are workload
identity or secret-manager references owned by the deployment, never supplied
by the coding agent.

Provider responses are normalized into strict closed schemas. Raw provider
responses, stack traces, tokens, internal hostnames, and credentials are not
returned to users or agents.

## 14. Reliability, privacy, and operating targets

Private-alpha product targets:

- median project-to-private-preview: under 90 seconds;
- median approved-plan-to-protected-URL: under 60 seconds;
- successful first publish for supported profiles: at least 80%;
- ingress availability target: 99.9%;
- suspension/revocation propagation p95: under 10 seconds;
- no manual Cloudflare dashboard step in the user journey;
- no secret values in source archive, contract, CLI output, browser storage,
  analytics, application log, or audit event;
- deterministic cleanup or explicit reconciliation state for every failed
  provider mutation.

Telemetry uses stable error codes and coarse timings. Source contents, prompts,
request/response bodies, secrets, connector payloads, and personal application
data are opt-out by construction and not collected as product analytics.

## 15. Product metrics

North-star metric:

> Weekly active protected Small Software apps used by at least two authorized
> people.

Activation funnel:

1. `agentpass publish` invoked;
2. supported project detected;
3. preview ready;
4. plan reviewed;
5. protected URL active;
6. second authorized person opens the app;
7. app is used again seven days later.

Guardrail metrics:

- manual provider intervention rate;
- publish rejection and unsupported-profile reasons;
- authority-widening approval rate;
- blocked egress and cross-tenant attempts;
- provider uncertainty/reconciliation rate;
- revocation propagation latency;
- expired app cleanup latency;
- cost per active app and per organization;
- secret-scanner true/false positive rate;
- incidents involving generated code.

## 16. Packaging and business model

### OSS

- local AgentPass broker and coding-agent integrations;
- app manifest and Publish Plan schemas;
- provider-adapter interface;
- self-hosted policy/audit components;
- local/static validation and development provider adapter.

### Hosted AgentPass Cloud

- managed build isolation and provider deployment;
- protected ingress URL and organization identity;
- managed access, expiry, audit, emergency stop, and deletion;
- managed connector/secret broker;
- usage limits, operational evidence, backup, recovery, and support;
- BYOC runtime option for larger organizations after the hosted path stabilizes.

Pricing should align with active apps, protected users, connector operations,
and runtime usage rather than developer seats alone. The creator may be one
person while many coworkers receive value from the deployed software.

## 17. Implementation plan

### Phase SS-0 — Contract freeze and demand validation

Goal: verify that protected publishing, not code generation, is the wedge.

Deliverables:

- interview 10 teams already sharing agent-built internal tools;
- collect five real projects and classify framework, auth, data, secrets,
  sharing, and current deployment pain;
- freeze the MVP profile and explicit unsupported cases;
- add the app manifest, source bundle, build receipt, Publish Plan, deployment
  receipt, provider operation, and lifecycle schemas to `contracts/`;
- update ADR-003 catalog ownership and threat model;
- build a clickable approval-flow prototype before implementing Console UI.

Exit criteria:

- at least five design partners agree to test a protected private URL;
- at least three have a real app blocked by auth/permission/sharing/security;
- the supported profile covers at least three collected projects without
  privileged connectors;
- security review accepts the trust-boundary document.

Estimated focused effort: 1–2 weeks. This phase is product validation, not a
technical release.

### Phase SS-1 — Immutable publish core and private preview

Goal: `agentpass publish` creates an isolated, content-addressed private preview.

Work items:

- **SS-101:** add `publish` command and strict argument/output contracts in
  `bin/agentpass.mjs`;
- **SS-102:** implement safe source inventory/archive with race, symlink,
  hardlink, path traversal, size, ignore, and secret-file defenses;
- **SS-103:** add `apps/cloud-api/src/small-software/` domain modules rather
  than adding more monolithic route logic to `server.mjs`;
- **SS-104:** add initial PostgreSQL app/release/provider-operation migrations,
  repositories, RLS, authority functions, and role-manifest updates;
- **SS-105:** implement object storage by digest and bounded retention;
- **SS-106:** implement isolated build service and signed build receipt;
- **SS-107:** implement Cloudflare provider adapter preview creation and
  reconciliation;
- **SS-108:** expose redacted publish status through CLI and MCP;
- **SS-109:** add provider, build, source-archive, and cross-tenant adversarial
  tests.

Exit criteria:

- a supported sample app reaches a creator-only preview from one command;
- changed bytes produce a different artifact/release identity;
- archive substitution, source mutation, build escape, provider response loss,
  and cross-tenant access fail safely;
- no production credential is present in the sandbox or preview Worker;
- every preview expires and is cleaned up or enters visible reconciliation.

Estimated focused effort: 3–5 weeks with one senior engineer using coding
agents. Provider/account setup and external qualification are additional.

### Phase SS-2 — Human approval, protected ingress, and sharing

Goal: convert an immutable preview into an identity-protected shared app.

Work items:

- **SS-201:** implement Publish Plan normalization and authority-delta engine;
- **SS-202:** add WebAuthn approval operation bound to plan/artifact/release;
- **SS-203:** implement app access rules and authorization repository;
- **SS-204:** implement AgentPass ingress/dispatch Worker and prevent direct
  provider-route bypass;
- **SS-205:** implement approval, app, release, access, activity, suspend,
  expiry, rollback, and delete Console surfaces;
- **SS-206:** implement activation generation and response-loss reconciliation;
- **SS-207:** add expiry scheduler and organization emergency-stop integration;
- **SS-208:** run browser, real PostgreSQL, provider, and multi-tenant E2E tests.

Exit criteria:

- a named second member can open the app and an unauthorized member cannot;
- an expired/suspended app becomes unreachable within the target bound;
- approval cannot be replayed for changed bytes, plan, app, or organization;
- direct Worker URLs cannot bypass the ingress policy;
- activation, rollback, and deletion survive process/provider response loss;
- activity shows release, approver, audience, and lifecycle without secrets.

Estimated focused effort: 4–6 weeks after SS-1.

### Phase SS-3 — Isolated data and safe external access

Goal: support useful CRUD/workflow apps without exposing organization secrets.

Work items:

- **SS-301:** provision one isolated database per app and issue only runtime
  bindings, not portable credentials;
- **SS-302:** implement migration classification, backup evidence, schema
  versioning, destructive-change block, and recovery workflow;
- **SS-303:** implement exact HTTPS egress allowlists and outbound Worker;
- **SS-304:** implement first managed connector through the secret/egress broker;
- **SS-305:** add per-app call, byte, storage, schedule, and cost ceilings;
- **SS-306:** add log/trace redaction, retention, and user-visible diagnostics;
- **SS-307:** qualify data isolation, connector scope, egress denial, cost
  limiting, backup/restore, and deletion.

Exit criteria:

- user Worker cannot enumerate or access another app's data binding;
- user code and logs never receive a long-lived connector credential;
- outbound traffic outside the approved policy is denied;
- destructive migrations require owner approval and verified recovery evidence;
- app deletion removes or retains data exactly according to policy and produces
  a verifiable deletion receipt.

Estimated focused effort: 5–8 weeks after SS-2.

### Phase SS-4 — Production beta and agent-native operation

Goal: safely operate the product for invited external organizations.

Work items:

- finish `agentpass start` browser auto-connect with signed hosted endpoints;
- integrate Claude Code, Codex, and Cursor publish tools with the Agent Session
  process/project boundary;
- implement quotas, billing events, abuse controls, tenant deletion, privacy
  exports, support diagnostics, and incident tooling;
- complete Cloudflare production workload identity and provider credential
  rotation;
- run real WebAuthn, managed PostgreSQL, KMS, provider, browser, Apple Silicon,
  signed/notarized distribution, backup/PITR, and revocation qualification;
- commission independent application and infrastructure security reviews;
- invite design partners behind hard organization/app/usage limits.

Exit criteria:

- no manual cloud-console action from install through shared protected URL;
- production evidence binds source, artifact, deployment, database, provider,
  policy, and qualification identities;
- critical/high review findings are closed;
- restore, rollback, emergency stop, provider outage, and deletion drills pass;
- on-call owner, alerting, cost ceilings, privacy terms, retention, and incident
  response are active.

Estimated focused effort: 6–10 weeks after SS-3. Passing external production
gates, not code completion, determines the beta date.

Overall planning range with one senior engineer heavily assisted by coding
agents is approximately 8–13 weeks for a constrained private alpha through
SS-2, and 19–31 weeks for a production-beta candidate through SS-4. This is a
planning range, not a ship-date promise. Account provisioning, provider review,
security review, real-device evidence, managed-database qualification, and
incident drills can dominate elapsed time even when implementation is fast.

### Phase SS-5 — Expansion

Only after product-market pull:

- BYOC Cloudflare accounts;
- Vercel runtime adapter;
- guest access and verified external customer portals;
- custom domains;
- organization groups and SCIM;
- service-to-service identities and webhooks;
- reusable governed templates/connectors;
- provider portability and migration;
- Windows/Linux creator connectors;
- app catalog, discovery, ownership transfer, and policy inheritance.

## 18. Workstream ownership and dependency graph

```text
Contracts / threat model
   |------> CLI + source bundle
   |------> Cloud API + PostgreSQL authority
   |------> build service + object storage
   |------> provider adapter + reconciliation
   |------> Console approval UX
   |------> ingress identity + access policy
                 |
                 v
          cross-component E2E
                 |
                 v
        external qualification + beta
```

Parallel implementation is safe only after the contracts and authority owners
are frozen. Suggested disjoint workstreams:

1. Protocol/catalog/threat model.
2. CLI/source archive/MCP.
3. Cloud API/PostgreSQL authority.
4. build/provider/ingress runtime.
5. Console UX/BFF.
6. independent security and integration audit.

Each implementation workstream needs an independent read-only reviewer before
integration. The final integrated tree requires another cross-boundary review;
component green tests are not sufficient.

## 19. Test and qualification matrix

Minimum automated evidence:

- canonical contract producer/consumer vectors and unknown-field rejection;
- source archive TOCTOU, link, traversal, duplicate, secret, and size attacks;
- build sandbox network, filesystem, process, timeout, output, and credential
  escape tests;
- artifact/plan/approval substitution and replay tests;
- real PostgreSQL RLS, ACL, role, concurrency, idempotency, lock-order,
  response-loss, lifecycle, cross-tenant, and migration tests;
- provider create/inspect/activate/suspend/delete uncertainty tests;
- direct runtime URL bypass and ingress identity substitution tests;
- egress destination, method, operation, connector, quota, and secret-leak tests;
- browser role, WebAuthn, CSRF, origin, session rotation, expiry, sharing,
  suspend, rollback, delete, accessibility, and recovery tests;
- runtime isolation and noisy-neighbor tests;
- emergency stop, provider outage, database outage, KMS outage, backup/PITR,
  restore, rollback, expiration, and cleanup drills;
- published artifact secret scan and deployment identity verification.

Protected external evidence is required for real Cloudflare isolation/routing,
managed PostgreSQL authority, WebAuthn ceremony, KMS/workload identity,
notarized macOS release, backup/restore, and deployed revocation propagation.
Missing protected evidence is `not_proven`, never a local pass.

## 20. Go-to-market wedge

Do not launch as “another cloud.” Launch as:

> Deploy your AI-built internal app safely in one command.

Initial demonstration:

1. Ask Claude Code/Codex to build a tiny customer tracker.
2. Run `agentpass publish`.
3. Show the permission summary, not cloud configuration.
4. Approve with Touch ID/passkey.
5. Open a protected URL as the creator.
6. Share it with one teammate.
7. Show unauthorized access denied.
8. Press suspend and show immediate denial plus audit.

This demonstrates the category more clearly than a generic security-key story.

## 21. Decacorn test

This can become a very large company only if AgentPass becomes the default
trust layer for software produced and operated by agents across many runtimes.
It remains a feature if it only wraps one provider's deployment API.

Evidence supporting the large outcome:

- apps are created continuously, not only during developer projects;
- non-engineers publish and share successfully;
- organizations standardize policy, identity, connectors, and audit on
  AgentPass across multiple coding agents;
- active apps and protected users grow faster than creator seats;
- switching away requires replacing governed application identity, access,
  connector, provenance, and audit history—not merely moving compute.

Kill or reposition signals:

- users mainly want code generation and are satisfied with a builder's bundled
  auth/hosting;
- teams will not grant a control plane access to source or deployment;
- supported profiles cover too little real Small Software;
- security approvals take long enough to erase the speed advantage;
- runtime providers absorb the entire governance layer with adequate
  cross-agent portability.

## 22. Immediate next decisions

Before implementation begins, the product owner must freeze:

1. Private alpha runtime: Cloudflare Workers for Platforms.
2. Supported application profile: TypeScript web app, static assets, Worker API,
   optional isolated SQL.
3. Identity: AgentPass organization members only.
4. Sharing: creator, named member, organization; no public links.
5. Default lifetime: preview 24 hours, first active release 7 days.
6. First privileged connector: none in SS-1/SS-2; choose from design-partner
   demand for SS-3.
7. Source path: safe local bundle plus exact Git identity when available.
8. Product name: AgentPass Publish for the feature; AgentPass Cloud for the
   hosted product until market language is validated.

These defaults minimize scope while preserving the full strategic direction.

## 23. Primary external references

- Y Combinator, “A Cloud for Small Software”: https://www.ycombinator.com/rfs
- Cloudflare for Platforms and Workers for Platforms:
  https://developers.cloudflare.com/cloudflare-for-platforms/
- Cloudflare AI vibe-coding platform reference architecture:
  https://developers.cloudflare.com/reference-architecture/diagrams/ai/ai-vibe-coding-platform/
- Cloudflare enterprise AI vibe-coding platform reference architecture:
  https://developers.cloudflare.com/reference-architecture/diagrams/ai/enterprise-ai-vibe-coding-platform/
- Vercel Sandbox: https://vercel.com/docs/sandbox
- Vercel for Platforms: https://vercel.com/platforms
- Lovable managed Google authentication:
  https://docs.lovable.dev/features/google-auth
