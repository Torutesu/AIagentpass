import assert from "node:assert/strict";
import test from "node:test";

import { createSessionAuthority, SessionAuthorityInvalidatedError } from "../app/session-authority.ts";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test("shares one bootstrap across concurrent Console consumers", async () => {
  const load = deferred();
  let calls = 0;
  const authority = createSessionAuthority(async () => {
    calls += 1;
    return load.promise;
  });

  const first = authority.get();
  const second = authority.get();
  const third = authority.get();
  await Promise.resolve();
  assert.equal(calls, 1);

  const session = { organizationId: "organization-1", csrfToken: "csrf-1" };
  load.resolve(session);
  const results = await Promise.all([first, second, third]);
  assert.ok(results.every((result) => result === session));
  assert.equal(Object.isFrozen(session), true);
  assert.equal(await authority.get(), session);
  assert.equal(calls, 1);
});

test("caller cancellation does not abort or duplicate the shared bootstrap", async () => {
  const load = deferred();
  let calls = 0;
  const authority = createSessionAuthority(async () => {
    calls += 1;
    return load.promise;
  });
  const controller = new AbortController();

  const cancelled = authority.get(controller.signal);
  const survivor = authority.get();
  await Promise.resolve();
  controller.abort();
  await assert.rejects(cancelled, (error) => error instanceof DOMException && error.name === "AbortError");

  const session = { generation: 1 };
  load.resolve(session);
  assert.equal(await survivor, session);
  assert.equal(await authority.get(), session);
  assert.equal(calls, 1);
});

test("invalidation rejects a stale completion and permits a new generation", async () => {
  const loads = [deferred(), deferred()];
  let calls = 0;
  const authority = createSessionAuthority(async () => loads[calls++].promise);

  const stale = authority.get();
  await Promise.resolve();
  authority.clear();
  const current = authority.get();
  await Promise.resolve();
  assert.equal(calls, 2);

  loads[0].resolve({ generation: 1 });
  await assert.rejects(stale, (error) => error instanceof SessionAuthorityInvalidatedError);
  const expected = { generation: 2 };
  loads[1].resolve(expected);
  assert.equal(await current, expected);
  assert.equal(await authority.get(), expected);
});

test("conditional invalidation cannot clear a newer session", async () => {
  let generation = 0;
  const authority = createSessionAuthority(async () => ({ generation: ++generation }));
  const first = await authority.get();

  authority.clear({ generation: 0 });
  assert.equal(await authority.get(), first);
  assert.equal(generation, 1);

  authority.clear(first);
  const second = await authority.get();
  assert.notEqual(second, first);
  assert.equal(second.generation, 2);
});
