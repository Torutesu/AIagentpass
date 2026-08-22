# Contributing

This project is an early, security-sensitive OSS project. Keep changes small,
explain the threat-model impact in pull requests, and keep the user-facing
CLI/documentation contract synchronized with the implementation.

Before submitting a change:

```sh
npm test
npm run lint
```

For documentation-only changes, check the exact commands and paths in
`README.md` against `node bin/agentpass.mjs --help`, the relevant adapter
`--help` output, `package.json`, and the referenced workflow/runbook. Do not
put private keys, credentials, enrollment invitations, bearer tokens, real
database URLs, or machine-specific evidence in Markdown examples. Use
placeholders such as `AGENT_ID`, `APPLETEAM1`, `<40-char-commit-sha>`, or
`REDACTED`, and say when a value is release metadata rather than a runnable
literal.

Documentation must distinguish local implementation/contract tests,
source-bound CI checks, protected external qualification, and production
promotion. `not_proven`, `not_run`, skipped, fixture, mock, sandbox, and
ad-hoc results remain blockers in user-facing documentation. Never turn a
green local test into a production claim or remove a fail-closed stop condition
to make an example easier to run.

For native boundary changes, also run the focused qualification and provenance
contracts:

```sh
npm run test:native-xpc-contract
node --test scripts/release/artifact-provenance.test.mjs
```

On a checkout where the Native XPC contract is committed, verify its exact
source-tree binding with:

```sh
npm run release:native-xpc-contract-gate
```

This gate is intentionally expected to fail if the contract or any referenced
source file exists only as an uncommitted worktree change.

Do not describe focused tests as proof of a physical macOS release. Changes
to Mach services, signing requirements, XPC selectors, or installer scripts
must state which Developer ID, launchd, notarization, or hardware gate remains
unproven.

Do not commit private keys, real credentials, audit logs, or machine-specific paths.

When changing README or qualification/runbook documentation, run the focused
documentation contracts before opening a pull request:

```sh
node --test \
  test/production-readiness-audit-docs.test.mjs \
  test/release-evidence-index-workflow.test.mjs \
  test/cloud-production-qualification-workflow.test.mjs \
  test/external-qualification-runners-workflow.test.mjs
git diff --check
```

If the change affects an adapter example, also run its contract test:

```sh
node --test adapters/claude-code/test/adapter.test.mjs
node --test adapters/cursor/test/adapter.test.mjs
```
