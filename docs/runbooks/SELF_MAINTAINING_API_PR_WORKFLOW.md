# Self-maintaining API: bounded draft PR workflow

The Wave 4 PR adapter is an offline intent boundary. It accepts a maintenance
job/plan, a structured patch result, completed check-run evidence, and a
separate approval statement. It returns data that an independently authorised
provider worker may submit later. The adapter never calls GitHub and never
accepts a GitHub token, repository connector, shell command, or credential.

## Required bindings

- The plan and job must agree on tenant, repository, plan ID, and plan digest.
- The result source commit must equal `plan.base_commit`. A result digest binds
  the job, plan digest, source/result commit and tree, patch digest, and exact
  changed paths.
- Every check run must be `completed` with `success`, point at the exact result
  commit, carry a bounded output digest, and have a unique ID and name. The
  sorted evidence is represented by `check_runs_digest` in the intent.
- The branch is deterministic:
  `agentpass/maintenance/<job-id>/<first-16-patch-digest-hex>`.
- Approval is explicit, tenant/job/plan/patch-bound, unexpired, and itself
  content-addressed. Approval does not authorize merge or deployment.

## States and retry rule

`evaluateDraftPullRequest` returns `awaiting_approval` until approval exists.
With valid approval, `buildDraftPullRequestIntent` returns
`pr_create_intent` with `draft: true`; it contains no external PR number or
URL. A lost provider response is recorded as `uncertain` with
`retry_allowed: false`. `reconcilePullRequestOperation` may move it to
`reconciled` only when an observation carries the same operation and request
digests. `not_found` and `unknown` remain `reconcile_required`; they never
permit a blind second create.

The provider worker must independently authenticate the repository, verify the
intent digest, submit only a draft PR, and persist the response as a separate
effect/receipt. A successful local test or fixture is not external GitHub
qualification.

## Read-only status projection

`projectMaintenancePrStatus` is the read boundary for CLI, MCP, and Console
surfaces. It requires the same tenant, repository, plan, and job bindings as
the intent, and emits only state, branch/commit identities, content digests,
approval/uncertainty flags, and reconciled provider identifiers. PR body,
check-run payloads, provider response bodies, and credentials are excluded.
The projection is read-only and carries `retry_allowed: false` for every
state, including `reconcile_required`.
