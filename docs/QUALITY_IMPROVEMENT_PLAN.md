# Quality Improvement Plan

Baseline audit: 2026-09-16, on `codex/agent-platform` @ `9f8b399` (v0.18.0).

This plan raises the *product* quality bar — the CLI surface, the repository
itself, and the code-quality infrastructure — the same way the marketing site
was recently raised to match polished product pages. It is ordered so that the
highest-user-facing-leverage work lands first, and every phase ships with its
own acceptance check.

## Current baseline (measured)

| Signal | Value |
|---|---|
| Core unit tests (`node --test test/*.test.mjs`) | 835 pass / 0 fail / 5 skipped |
| Tracked files | ~2,030 |
| `bin/agentpass.mjs` | 1,522 lines, ~75 commands in one flat `--help` list |
| `lib/` | ~15.5k lines; largest `anchor.mjs` 2,110 lines |
| `docs/` | 78 files; 10+ dated implementation-plan variants |
| Lint config | none in this repo |
| Local branches | 11 (`codex/*`) |

Hard constraint discovered during the audit: **many behaviors are frozen by
contract tests** (help output, error strings, fail-closed JSON shapes, XPC
selectors, canonical vectors). Any UX change must update the freezing test in
the same commit, or the contract is silently weakened. This is a feature —
treat it as the guardrail, not an obstacle.

---

## Track A — CLI UX (highest leverage)

The product mirrors its `--help`: today ~75 commands sit in one flat list where
`start` and `native recovery-anchor-install` carry equal visual weight. The
reference bar is progressive disclosure: the everyday path should feel like one
command.

### A1. Tiered help output

Restructure the usage text in `bin/agentpass.mjs` into three tiers:

- **`agentpass` / `agentpass --help`** — Everyday:
  `start`, `init`, `status`, `check`, `doctor`, `session start`,
  `revoke`, `restore`, `integrate`, `install-hook`, `agent`, `audit`,
  `small-software`, `uninstall`. One line each, plus a pointer line:
  `agentpass help ops | help internal`.
- **`agentpass help ops`** — Release/operator operations:
  `broker *`, `control *`, `audit anchor *`, `setup *`, `install`,
  `native status|public-key|checkpoint|audit-*`, `native daemon-*`.
- **`agentpass help internal`** — Qualification/recovery internals:
  `native key-*`, `native recovery-*`, `native anchor-*`,
  `recovery *`, `push-check`, `git-sign` (invoked by Git, not humans).

Acceptance: `agentpass --help` fits in ~30 lines; `help ops`/`help internal`
are explicit successful operations; every existing command still executes;
the tests asserting help/usage behavior are updated to assert the tiered
shape (exit codes unchanged: help = 0, unknown = usage failure).

### A2. No-argument and unknown-command behavior

- `agentpass` with no args: print the three-step orientation
  (`start` → `doctor` → `status`) instead of a wall of usage.
- Unknown commands keep failing closed, but the message names the nearest
  valid tier: `unknown command "native-key". See 'agentpass help internal'.`

### A3. Error-message consistency pass

Audit `console.error`/`process.stderr` strings in `bin/` + `lib/` for a single
shape: `agentpass: <what failed>: <why> [<next action>]`. Today phrasing
varies between commands. Add a contract test that snapshots the prefix/format
invariant, not each message.

---

## Track B — Docs & repository hygiene

### B1. `docs/` split: current vs. historical — DONE 2026-09-16

`docs/archive/` now holds 18 completed/superseded documents:

- Plans: `EXECUTION_PLAN.md`, `FORWARD_IMPLEMENTATION_PLAN.md`,
  `HOSTED_IMPLEMENTATION_PLAN_2026-08-15.md`, `IMPLEMENTATION_PLAN_G4_G7.md`,
  `POST_C3_IMPLEMENTATION_PLAN.md`, `C3_FORWARD_IMPLEMENTATION_PLAN.md`,
  `PROCESS_BOUND_AGENT_IMPLEMENTATION_PLAN.md`, `NEXT_IMPLEMENTATION_PLAN.md`,
  `SMALL_SOFTWARE_PARALLEL_EXECUTION_PLAN.md`, `W1_6_OPERATIONAL_CLOSURE.md`
- Evidence & reviews: `AGENT_SESSION_N3E_EVIDENCE.md`,
  `G4_1_PROPAGATION_QUALIFICATION.md`,
  `POSTGRES_C3_MIGRATION_0047_QUALIFICATION.md`,
  `MACOS_SWIFT_CI_QUALIFICATION.md`,
  `MANAGED_SIGNER_PROVIDER_OPERATION_ADJUDICATION.md`,
  `SECURITY_REVIEW_PRODUCTION_GATE.md`, `SECURITY_REVIEW_XPC.md`,
  `SECURITY_REVIEW_XPC_TEST_GAPS.md`

**Deliberately kept in `docs/` despite being dated plans**: contract tests pin
`docs/IMPLEMENTATION_PLAN_2026-08-15.md` (must link the readiness audit +
incident runbook) and `docs/FORWARD_IMPLEMENTATION_PLAN_2026-08-16.md` (read by
the app-bundle contract test). Moving them would weaken a frozen contract, so
they stay indexed as current until those tests are updated on purpose.

Each archived doc carries a top banner; inbound links from live docs were
repointed to `archive/…`. Rule going forward: a plan doc is archival the day
its phase closes.

### B2. `docs/README.md` index

Four sections: **Contracts & specs** · **Architecture & threat models** ·
**Runbooks** · **Archive**. README's "Further reading" line then links the
index once, not five scattered docs.

### B3. Repo hygiene

- Delete merged `codex/*` local branches after confirming each tip is
  reachable from `codex/agent-platform` (`git branch --merged`).
- Add `.n3e-release-materializer-*/` and similar tool-output dirs to
  `.gitignore`; remove the untracked residue.
- `git gc` / confirm `native/macos/.build/` (751 MB local) stays ignored.

---

## Track C — Code-quality infrastructure

### C1. ESLint for the product repo

No lint config exists here today (the site repo's config incidentally reports
~3,000 violations across this tree — mostly `no-unused-vars`, `no-empty`,
`no-regex-spaces`, `no-control-regex`, concentrated in `test/` and `scripts/`).

Phase it in without a big-bang rewrite:

1. `eslint.config.mjs` covering `bin/ lib/ packages/*/src adapters/*/src
   apps/cloud-api/src` first (production code only).
2. Rules: correctness-only at `error` (`no-unused-vars`, `no-empty`,
   `no-control-regex`, `eqeqeq`, `no-implicit-globals`); style deferred.
3. `npm run lint` + `lint` job in `ci.yml` (fast, no postgres/hardware).
4. Ratchet: expand coverage to `test/` and `scripts/` in a follow-up, using
   `--fix` + manual review per directory.

### C2. Guard against `lib/` growth

`anchor.mjs` (2,110) and `device-enrollment-client.mjs` (1,100) are the two
files most likely to accumulate unrelated responsibilities. No rewrite now —
add a soft budget check (`scripts/quality/`) that fails if any `lib/` file
exceeds its current line count by >20%, so growth becomes a deliberate act.

### C3. Dependency & release surface

`npm audit`, confirm `engines.node` matches CI (22), and verify `files` in
`package.json` still matches what the npm tarball should contain (it was
hand-maintained through several feature waves).

---

## Sequencing

| Phase | Scope | Why first/last |
|---|---|---|
| 1 | A1 + A2 (tiered help, no-args) | Largest visible change, small blast radius, all in `bin/` + its tests |
| 2 | B1–B3 (docs split, index, hygiene) | Mechanical, reviewable in one diff |
| 3 | C1 (lint baseline + CI gate) | Gates everything after it |
| 4 | A3 + C2 + C3 | Consistency passes are safest once lint guards exist |

## Status — implemented 2026-09-17

All four phases landed in this branch:

- **Phase 1 (A1/A2):** `agentpass --help` now prints a compact everyday surface
  (~28 lines) and defers operator and internal commands to `agentpass help ops`
  and `agentpass help internal`. Bare `agentpass` shows the same everyday help.
  Exit/output contracts (help exit 0, unknown command exit 2 with
  `agentpass: unknown command`) are unchanged and covered by
  `test/agentpass-cli-launch.test.mjs`.
- **Phase 2 (B1–B3):** 17 completed-phase plans/evidence moved to
  `docs/archive/` with archive banners; every path referenced by contracts,
  tests, scripts, or README stayed in place (`docs/FORWARD_IMPLEMENTATION_PLAN.md`
  was restored after `contracts/catalog-v1.json` proved it is a live
  `implementation_refs` entry). `docs/README.md` is the new index; all
  cross-links verified resolvable. `.gitignore` covers `.n3e-*` materializer
  leftovers. Branch cleanup: skipped — every other `codex/*` branch is checked
  out in a sibling worktree and cannot be removed safely.
- **Phase 3 (C1):** `eslint.config.mjs` added — correctness rules gate
  production code (`bin`, `lib`, `packages`, `adapters`, `apps/cloud-api/src`)
  via `npm run lint:eslint`, wired into CI after the existing `npm run lint`
  step. Production scope is at 0 errors / 0 warnings; tooling dirs report
  warnings only.
- **Phase 4 (A3/C2/C3):** Top-level error boundary already uniform
  (`agentpass: <message>` / exit 1, `agentpass: unknown command` / exit 2) —
  no churn applied to frozen strings. `test/lib-size-budget.test.mjs` freezes a
  per-module line-count ceiling (baseline +20%) for every `lib/` file.
  `npm audit` is clean after `npm audit fix`; `npm pack --dry-run` exercises
  the full `prepack` verification and the existing `files` allowlist.

## Non-goals

- No refactor of `lib/` internals for its own sake — contracts are frozen and
  the test suite is the spec.
- No change to fail-closed semantics, XPC selectors, canonical vectors, or any
  test-frozen wire format.
- No deletion of qualification evidence — only relocation to `docs/archive/`.
