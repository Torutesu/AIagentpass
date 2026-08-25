# Organization mutation browser contracts

`e2e/p1-browser-organization-mutations.spec.ts` verifies the Console's organization mutation boundary in a real browser process while every API response is a deterministic Playwright mock.

The suite covers:

- member role change rejected by a stale `If-Match` version;
- organization rename rejected by a stale `If-Match` version;
- member revoke rejected by authorization;
- invitation revoke rejected by a stale version;
- invitation revoke rejected by an idempotency conflict;
- one-time invitation acceptance rejected as a replay;
- help modal `aria-modal`/label relationships, keyboard focus wrapping, `Escape`, and focus return.

Each mutation assertion checks the request method, organization-scoped path, CSRF header, origin, idempotency key, and version precondition where applicable. Failure responses must restore the pre-mutation UI state; a mocked error is never converted into a success or a durable state transition.

The visible recovery contract is deliberately human-readable:

- a stale version says that another administrator changed the resource and offers the latest-information refresh;
- an authorization failure says that the current role cannot perform the action;
- an idempotency conflict explains that the same idempotency key is already bound to another result and offers a latest-state check;
- an invitation replay says that the token was already used and offers an invitation refresh.

The organization panel exposes the current role next to the organization selector. Viewer and auditor sessions keep read-only content visible where allowed, while management controls are omitted and the panel explains that the operation is not available to the current permission state.

## Evidence boundary

These tests are browser contract tests, not production qualification. They do not prove that a deployed API, PostgreSQL transaction, WebAuthn verifier, session store, identity provider, or invitation store behaves the same way. They intentionally use mocked API routes and therefore must not be counted as staging or production success evidence.

Run the list-only check with:

```sh
npm run e2e:list -- --grep "role change|member revoke|stale invitation|idempotency conflict|invitation replay|help modal"
```

Run the suite only in an environment where the Playwright web server can bind its configured loopback port:

```sh
npm run e2e -- e2e/p1-browser-organization-mutations.spec.ts
```

If the environment rejects loopback binding (for example, `listen EPERM`), the result is **unverified**, not a successful browser E2E result.
