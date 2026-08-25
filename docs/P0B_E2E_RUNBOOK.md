# P0-B trusted HTTPS/PostgreSQL E2E harness

This harness runs the Cloud API in `hosted` mode and the Web Console behind
short-lived HTTPS loopback proxies. It uses a disposable PostgreSQL database,
generates a private test CA and `localhost` certificate in a mode-0700 temp
directory, and removes all processes, database state, and keys on teardown.
No certificate, private key, bearer token, assertion, or database password is
stored in the repository or printed by the harness.

## Preconditions

- Node.js 20+ and the repository dependencies are installed.
- `openssl` is available for test-only certificate generation.
- A PostgreSQL administrator URL is available in
  `P0B_POSTGRES_ADMIN_URL` (or `AGENTPASS_TEST_POSTGRES_ADMIN_URL`). It must be
  `postgresql://user:password@host/database?sslmode=verify-full`; extra query
  parameters and non-TLS modes are rejected.
- Chromium is installed for Playwright (`npm --prefix apps/web-console run
  e2e:install`). The combined runner always rebuilds `apps/web-console/dist`
  from the current source before qualification and never reuses a stale build.

If `openssl` or the administrator URL is unavailable, the lane reports a
stable `P0-B` skip diagnostic. It does not fall back to HTTP, the file store,
an existing shared database, or an insecure PostgreSQL connection.

## Run the focused self-test

```bash
node scripts/p0b/self-test.mjs
```

The self-test never needs PostgreSQL. It checks HTTPS-only URL validation,
`sslmode=verify-full` validation, inherited-secret removal, temporary CA/key
permissions, and explicit external-dependency skip behavior.

## Run the browser and PostgreSQL qualification lanes

The browser lane uses Chromium's virtual platform authenticator to exercise a
real WebAuthn ceremony, owner/admin/auditor/viewer authorization behavior, all
six device synchronization states, keyboard operation, and the `accepted`,
`coalesced`, and `no_pending_refresh` wake outcomes:

```bash
npm --prefix apps/web-console run e2e:install
npm --prefix apps/web-console run e2e
```

The PostgreSQL lane runs migrations and proves manual wake through signed P-256
ACK convergence, exact retry, conflict, key-epoch, tenant/path/body
substitution, rollback, expiry, and the final Console read model:

```bash
AGENTPASS_TEST_DATABASE_URL='postgresql://…' npm run test:postgres:g4
```

CI runs both lanes. Browser traces are retained only on failure; the final CI
step scans the artifact directory and rejects cookies, CSRF/recent-auth data,
authorization material, nonces, private keys, enrollment material, and policy
bodies without echoing matched values.

## Run the harness

Run the complete cleanup-safe qualification (current Console build, real
Chromium/WebAuthn matrix, trusted HTTPS Cloud/Console, disposable PostgreSQL,
and signed-ACK convergence) with:

```bash
npm run test:p0b:live
```

The command treats any skipped browser or process lane as failure and always
removes the PostgreSQL container and temporary credentials. On success it
writes a private canonical report to `.agentpass/qualification/p0b.json` (or
the absolute `P0B_QUALIFICATION_OUTPUT`/`--report-output` path). The report
binds the clean source commit, Console build-tree digest, actual PostgreSQL
container image digest and TLS server version, Chromium version, and digested
results for the build, browser, and process gates. Verify it against the
current clean source with:

```bash
node scripts/p0b/qualification/verify.mjs "$PWD/.agentpass/qualification/p0b.json"
```

The reusable API is in `test/support/p0b/harness.mjs`. A test can call
`startP0BHarness()` and register `harness.close()` in its test teardown:

```js
import test from "node:test";
import { startP0BHarness } from "./support/p0b/harness.mjs";

test("P0-B flow", async (t) => {
  const harness = await startP0BHarness();
  t.after(() => harness.close());
  // Use harness.cloudUrl and harness.consoleUrl with the returned CA.
});
```

The harness creates a random database name using a locally generated safe
identifier, so user input is never interpolated into SQL. Child processes use
`shell: false`, fixed executable paths, a reduced environment, and detached
process groups. Teardown sends `SIGTERM`, escalates after three seconds, closes
TLS proxies, drops the database with `WITH (FORCE)`, and removes the temporary
directory.

Cloud readiness is checked through the HTTPS proxy at `/health/ready` with the
operational probe header. Console readiness is checked through its HTTPS proxy
at `/`. The CA is returned to the test process only as a file path; it is not
logged. The harness never enables `AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API`
and never sets evaluation/file-store variables.

## Environment and diagnostics

Set `P0B_DISABLE_EXTERNAL=true` for a deterministic skip in environments where
external services are not permitted. Do not put credentials in command-line
arguments or commit them. When a test is not runnable, consume `P0BSkip` and
report only its `code` and `diagnostic`; do not print child stderr or URLs with
credentials.

This is a test harness, not a production TLS termination design. Production
deployment still requires a managed certificate, trusted PostgreSQL CA and
secret injection policy.

The intercepted browser lane and the trusted HTTPS/PostgreSQL process harness
prove different boundaries. A passing browser lane does not claim a full
deployed Cloud/Console/TLS test, and the process harness does not replace a
physical-Mac Secure Enclave qualification.
