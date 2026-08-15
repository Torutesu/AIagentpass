import assert from "node:assert/strict";
import test from "node:test";

import { loadOrganizationSwitcherOrganizations, OrganizationSwitcherError } from "../app/organization-switcher.ts";

const organization = (id) => Object.freeze({
  id,
  name: `Organization ${id}`,
  version: 1,
  createdAt: "2026-08-15T00:00:00Z",
  updatedAt: "2026-08-15T00:00:00Z",
});

test("loads every bounded organization page in server order", async () => {
  const calls = [];
  const first = organization("11111111-1111-4111-8111-111111111111");
  const second = organization("22222222-2222-4222-8222-222222222222");
  const result = await loadOrganizationSwitcherOrganizations({
    async listOrganizations(options) {
      calls.push(options);
      return options.cursor === undefined
        ? { items: [first], nextCursor: "next-page", requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }
        : { items: [second], nextCursor: null, requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
    },
  });

  assert.deepEqual(result, [first, second]);
  assert.deepEqual(calls.map(({ limit, cursor }) => ({ limit, cursor })), [
    { limit: 100, cursor: undefined },
    { limit: 100, cursor: "next-page" },
  ]);
  assert.equal(Object.isFrozen(result), true);
});

test("fails closed on duplicate organizations and cursor loops", async () => {
  const duplicate = organization("11111111-1111-4111-8111-111111111111");
  await assert.rejects(() => loadOrganizationSwitcherOrganizations({
    async listOrganizations(options) {
      return options.cursor === undefined
        ? { items: [duplicate], nextCursor: "next-page", requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }
        : { items: [duplicate], nextCursor: null, requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
    },
  }), OrganizationSwitcherError);

  await assert.rejects(() => loadOrganizationSwitcherOrganizations({
    async listOrganizations() {
      return { items: [], nextCursor: "same-page", requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
    },
  }), OrganizationSwitcherError);
});

test("fails closed when pagination exceeds the bounded tenant set", async () => {
  let page = 0;
  await assert.rejects(() => loadOrganizationSwitcherOrganizations({
    async listOrganizations() {
      page += 1;
      return { items: [], nextCursor: `page-${page}`, requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
    },
  }), /safe bound/);
  assert.equal(page, 10);
});
