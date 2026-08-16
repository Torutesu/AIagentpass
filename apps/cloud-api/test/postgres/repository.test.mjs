import assert from "node:assert/strict";
import test from "node:test";

import { createTenantRepository, TenantScopeError, withTransaction } from "../../src/postgres/index.mjs";
import { FakePgClient } from "./fake-client.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";

test("select always binds the repository tenant and shifts caller parameters", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });
  await repository.select({ table: "devices", columns: ["id", "label"], where: "status = $1", params: ["active"], orderBy: { column: "created_at", direction: "DESC" }, limit: 20 });
  const call = client.calls.at(-1);
  assert.match(call.text, /FROM "devices" WHERE organization_id = \$1 AND \(status = \$2\)/);
  assert.match(call.text, /ORDER BY "created_at" DESC, "id" DESC LIMIT 20/);
  assert.deepEqual(call.params, [organizationId, "active"]);
});

test("select groups caller predicates so OR cannot escape the repository tenant", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });
  await repository.select({
    table: "devices",
    where: "status = $1 OR organization_id = $2",
    params: ["active", "33333333-3333-4333-8333-333333333333"]
  });
  assert.match(client.calls[0].text, /WHERE organization_id = \$1 AND \(status = \$2 OR organization_id = \$3\)/);
  assert.deepEqual(client.calls[0].params, [organizationId, "active", "33333333-3333-4333-8333-333333333333"]);
});

test("insert and update cannot override tenant or version ownership", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });
  await repository.insert({ table: "devices", values: { id: deviceId, label: "Mac", key_algorithm: "p256-sha256", status: "pending" } });
  assert.deepEqual(client.calls.at(-1).params, [organizationId, deviceId, "p256-sha256", "Mac", "pending"]);
  await repository.updateById({ table: "devices", id: deviceId, values: { status: "active" }, expectedVersion: 1 });
  const call = client.calls.at(-1);
  assert.match(call.text, /WHERE organization_id = \$1 AND "id" = \$2 AND version = \$4/);
  assert.match(call.text, /version = version \+ 1/);
  assert.deepEqual(call.params, [organizationId, deviceId, "active", 1]);
  await assert.rejects(repository.insert({ table: "devices", values: { organization_id: "33333333-3333-4333-8333-333333333333", id: deviceId } }), TenantScopeError);
  await assert.rejects(repository.updateById({ table: "devices", id: deviceId, values: { version: 99 } }), TenantScopeError);
});

test("raw tenant primitive requires an explicit organization predicate", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });
  await repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1 AND status = $2", params: ["active"] });
  assert.deepEqual(client.calls.at(-1).params, [organizationId, "active"]);
  await assert.rejects(repository.queryTenant({ text: "SELECT * FROM devices", params: [] }), TenantScopeError);
});

test("tenant predicate cannot be rebound to caller input or a scope escape operator", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });

  await assert.rejects(
    repository.queryTenant({
      text: "SELECT * FROM devices WHERE organization_id = $2 AND status = $3",
      params: ["33333333-3333-4333-8333-333333333333", "active"],
      organizationPlaceholder: "$2"
    }),
    (error) => error instanceof TenantScopeError && error.message.includes("reserve $1")
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1 OR organization_id = $2", params: ["33333333-3333-4333-8333-333333333333"] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1 UNION ALL SELECT * FROM devices", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT 'organization_id = $1' FROM devices", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT organization_id = $1 AS belongs_to_tenant FROM devices", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE NOT organization_id = $1", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1 IS FALSE", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE TRUE ORDER BY organization_id = $1", params: [] }),
    TenantScopeError
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices d, devices other WHERE d.organization_id = $1", params: [] }),
    TenantScopeError
  );
  assert.equal(client.calls.length, 0, "cross-tenant candidates are rejected before PostgreSQL");
});

test("tenant query placeholders are contiguous after the immutable tenant parameter", async () => {
  const client = new FakePgClient();
  const repository = createTenantRepository({ client, organizationId });
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1 AND status = $3", params: ["active"] }),
    (error) => error.code === "ERR_QUERY"
  );
  await assert.rejects(
    repository.queryTenant({ text: "SELECT * FROM devices WHERE organization_id = $1; SELECT * FROM devices", params: [] }),
    (error) => error.code === "ERR_QUERY"
  );
  assert.equal(client.calls.length, 0);
});

test("rejects unapproved identifiers and missing tenant scope", async () => {
  const client = new FakePgClient();
  assert.throws(() => createTenantRepository({ client, organizationId: "org-1" }), TenantScopeError);
  const repository = createTenantRepository({ client, organizationId });
  await assert.rejects(repository.select({ table: "devices; DROP TABLE members", columns: ["id"] }), (error) => error.code === "ERR_TABLE");
  await assert.rejects(repository.select({ table: "capabilities", columns: ["id"] }), (error) => error.code === "ERR_TABLE");
  await assert.rejects(repository.select({ table: "devices", where: "status = $2", params: ["active"] }), (error) => error.code === "ERR_QUERY");
});

test("transaction commits on success and rolls back on failure", async () => {
  const client = new FakePgClient();
  await withTransaction(client, async (transactionClient) => {
    await transactionClient.query("SELECT 1", []);
  });
  assert.deepEqual(client.calls.slice(0, 3).map(({ text }) => text), ["BEGIN", "SELECT 1", "COMMIT"]);
  const failing = new FakePgClient();
  await assert.rejects(withTransaction(failing, async () => { throw new Error("boom"); }), /boom/);
  assert.equal(failing.calls.at(-1).text, "ROLLBACK");
});

test("transaction checks out exactly one pool client and releases it", async () => {
  const checkedOut = new FakePgClient();
  let connects = 0;
  let releases = 0;
  checkedOut.release = () => { releases += 1; };
  const pool = {
    query() { throw new Error("pool.query must not execute transaction statements"); },
    async connect() { connects += 1; return checkedOut; }
  };
  await withTransaction(pool, async (transactionClient) => {
    assert.equal(transactionClient, checkedOut);
    await transactionClient.query("SELECT 1", []);
  });
  assert.equal(connects, 1);
  assert.equal(releases, 1);
  assert.deepEqual(checkedOut.calls.map(({ text }) => text), ["BEGIN", "SELECT 1", "COMMIT"]);
});
