# WebAuthn / unattended agent E2E qualification

This document defines the browser qualification child evidence for the
`webauthn` gate. It is an external-execution contract, not a claim that the
current checkout has passed the gate.

## What is qualified

The spec at
[`apps/web-console/e2e/webauthn-agent-unattended-qualification.spec.ts`](../../apps/web-console/e2e/webauthn-agent-unattended-qualification.spec.ts)
drives the deployed Console in a real browser execution using Chromium. A CDP WebAuthn
Authenticator is installed only to make the browser execute the WebAuthn
algorithm; the spec never fabricates an authenticator response or writes a
passing credential/assertion JSON fixture. The assertion and authenticator
data inspected by the test are produced by `navigator.credentials` during
that browser run.

The test covers the unattended agent enrollment path and keeps ceremony
material in the browser/request call frames. Enrollment credentials, private
keys, bearer tokens, raw assertions, and raw upstream responses are not typed
evidence and must not be attached, logged, or rendered.

## Binding checks

The qualification route harness rejects requests before an evidence check can
pass unless the same browser session carries the expected CSRF/session
context and the expected tenant is used for every ceremony and enrollment
request. The browser-produced assertion is decoded at runtime to verify:

| Check | Required observation |
| --- | --- |
| `authenticator_origin_rp` | `clientDataJSON` has the issued challenge and browser origin; `authenticatorData` starts with the SHA-256 hash of the issued RP ID; credential fields are browser-generated and non-empty |
| `durable_one_time_consumption` | tenant, session cookie, CSRF, operation, challenge, and enrollment request are correlated; the first recent-auth proof is consumed once |
| `replay_rejection` | the exact first enrollment request replayed in the same browser is rejected with `403` |
| `stale_context_rejection` | a real credential paired with a stale challenge and a cross-tenant options request are both rejected with `409`/`403` |
| `outage_fail_closed` | enrollment service unavailability returns `503`, the UI exposes no secret output, and no browser storage is populated |

The challenge value, credential bytes, session cookie, and enrollment secret
are only inputs to the in-memory browser exercise. They are never copied into
the evidence attachment.

## Typed evidence and external binding

When the test is executed by the protected qualification runner, it attaches
one `webauthn-agent-unattended-qualification.json` object. Its checks contain
only typed observations (boolean values) and a digest of each typed check. The
attachment is emitted as a passing result only when all five checks pass and
the runner supplies all of these bindings:

- `AGENTPASS_QUALIFICATION_RUNNER_ID` (must not identify a local, static,
  mocked, fixture, simulator, emulator, test, or `macos-latest` runner);
- `AGENTPASS_QUALIFICATION_RUN_ID`, `AGENTPASS_QUALIFICATION_JOB_ID`, and
  `AGENTPASS_QUALIFICATION_RUN_ATTEMPT`;
- `GITHUB_SHA` and independently obtained `AGENTPASS_SOURCE_TREE`; and
- `AGENTPASS_QUALIFICATION_ARTIFACT_SHA256`.

If any binding is absent or malformed, the spec emits no qualification
attachment. That is an incomplete external run, not a `passed` or
`qualified: true` result. Static tests, mocked API responses, a local
Playwright invocation, or a hand-authored JSON object cannot satisfy this
gate. Static-only execution cannot pass.

The attached child evidence must be retained with the exact Playwright run
and later incorporated into the aggregate evidence contract in
[`external-qualification-contract.md`](./external-qualification-contract.md).
The aggregate verifier must independently compare source commit/tree, run,
job, attempt, artifact digest, runner identity, and the exact five check IDs.

## Protected runner command

The repository command below is the only supported way to turn the Playwright
attachment into a retained child-evidence file:

```sh
npm run qualification:webauthn
```

The protected runner must provide `AGENTPASS_QUALIFICATION_RUNNER_ID`,
`AGENTPASS_QUALIFICATION_RUN_ID`, `AGENTPASS_QUALIFICATION_JOB_ID`,
`AGENTPASS_QUALIFICATION_RUN_ATTEMPT`, `GITHUB_SHA`,
`AGENTPASS_SOURCE_TREE`, `AGENTPASS_QUALIFICATION_ARTIFACT_SHA256`, and
`AGENTPASS_WEBAUTHN_QUALIFICATION_EVIDENCE_PATH`. The collector uses an
isolated Playwright output directory, requires exactly one attachment, checks
canonical JSON and every binding/check digest, then creates the destination
with `O_EXCL`. A missing binding, local runner marker, duplicate attachment,
non-canonical file, or pre-existing destination fails the command; it never
creates a `not_run` or synthetic pass result.

This command currently proves the browser/WebAuthn protocol contract through
the repository's deterministic route harness. It is not evidence that a
production deployment or a physical authenticator has passed. Production
qualification additionally requires the independently controlled deployment
and hardware runner described above and must be incorporated into the
aggregate external evidence envelope.

## Protected production adapter path

The production path is intentionally separate from the route-harness collector:

```sh
npm run qualification:webauthn:external
```

It requires an immutable adapter module plus SHA-256, a protected runner, the
exact canonical CI source/tree/run/attempt/job binding, the release artifact
digest, and the deployed WebAuthn environment/deployment digest. The adapter
must implement `qualify(binding)` and return the same five typed checks after
exercising the real origin/RP, authenticator, durable database path, and
failure cases. The runner validates every check and binding, rejects local or
simulated identities, rechecks adapter bytes, and writes the canonical result
with `O_EXCL`. A deterministic fixture or the existing route-harness report
cannot satisfy this adapter contract.

## GitHub Actions repository variables

The protected workflows read the following repository-level **Variables**.
They must be populated from the deployed environment and protected runner;
never use placeholders or values derived from a local checkout.

| Variable | Source of truth |
| --- | --- |
| `AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID` | Stable identity of the protected external qualification runner |
| `AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_MODULE` | Absolute path to the deployed-runner adapter module |
| `AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_SHA256` | SHA-256 of that adapter file, measured on the protected runner |
| `AGENTPASS_WEBAUTHN_QUALIFICATION_DEPLOYMENT_DIGEST` | Digest of the deployed WebAuthn/Console environment under test |
| `AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN` | Exact HTTPS origin served by that deployment |
| `AGENTPASS_WEBAUTHN_EXPECTED_RP_ID` | WebAuthn RP ID configured by that deployment |
| `AGENTPASS_WEBAUTHN_QUALIFICATION_ARTIFACT_SHA256` | SHA-256 of the immutable release artifact used by the canonical CI run |

The CI run supplies source commit/tree, run IDs, attempt, and job IDs itself.
The dedicated browser job fails closed before executing when any required
variable is absent, and the promotion workflow additionally requires the
signed aggregate, deployment, staging, hardware, and operator evidence
described in the release qualification matrix.
