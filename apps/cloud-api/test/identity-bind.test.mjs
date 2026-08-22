import assert from "node:assert/strict";
import test from "node:test";
import { IdentityBindError, runIdentityBind } from "../src/identity-bind.mjs";

const ids = {
  member: "22222222-2222-4222-8222-222222222222",
  otherMember: "66666666-6666-4666-8666-666666666666",
  organization: "33333333-3333-4333-8333-333333333333"
};
const args = ["--provider", "chatgpt", "--subject", "subject-42", "--member-id", ids.member, "--organization-id", ids.organization];
const env = { AGENTPASS_IDENTITY_BIND_DATABASE_URL: "postgresql://agentpass_maintenance:secret@db.example.test/agentpass?sslmode=verify-full" };

class FakePool {
  static instances = [];

  constructor(options) {
    this.options = options;
    this.client = null;
    this.ended = false;
    FakePool.instances.push(this);
  }

  async connect() {
    return this.client;
  }

  async end() {
    this.ended = true;
  }
}

function usePool(queries) {
  FakePool.instances.length = 0;
  FakePool.prototype.client = undefined;
  class TestPool extends FakePool {
    constructor(options) {
      super(options);
      this.client = {
        calls: [],
        async query(text, params) {
          this.calls.push({ text, params });
          if (text.startsWith("SELECT set_config")) return { rowCount: 1, rows: [] };
          if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rowCount: 0, rows: [] };
          const next = queries.shift();
          if (next instanceof Error) throw next;
          return next ?? { rowCount: 0, rows: [] };
        },
        release(shouldDestroy) {
          this.released = shouldDestroy;
        }
      };
      this.client.release = this.client.release.bind(this.client);
    }
  }
  return TestPool;
}

test("creates an identity only after exact active membership verification", async () => {
  const PoolClass = usePool([{ rowCount: 1, rows: [{ result: "created" }] }]);
  const result = await runIdentityBind({ argv: args, env, PoolClass });
  assert.deepEqual(result, { ok: true, command: "identity-bind", result: "created", provider: "chatgpt", subject: "subject-42", member_id: ids.member, organization_id: ids.organization });
  const pool = FakePool.instances[0];
  assert.deepEqual(pool.client.calls[0].params, ["8000ms"]);
  assert.match(pool.client.calls[3].text, /agentpass_human_identity_bind/);
  assert.deepEqual(pool.client.calls[3].params, ["chatgpt", "subject-42", ids.member, ids.organization]);
  assert.equal(pool.client.calls.at(-1).text, "COMMIT");
  assert.equal(pool.client.released, false);
  assert.equal(pool.ended, true);
});

test("reports an idempotent repeat without changing the mapping", async () => {
  const PoolClass = usePool([{ rowCount: 1, rows: [{ result: "already_exists" }] }]);
  const result = await runIdentityBind({ argv: args, env, PoolClass });
  assert.equal(result.result, "already_exists");
  const pool = FakePool.instances[0];
  assert.match(pool.client.calls[3].text, /agentpass_human_identity_bind/);
  assert.equal(pool.client.calls.some(({ text }) => /^(UPDATE|DELETE)\s/.test(text)), false);
});

test("rejects a rebind and rolls back without emitting database details", async () => {
  const PoolClass = usePool([Object.assign(new Error("identity mapping conflict"), { code: "42501" })]);
  await assert.rejects(() => runIdentityBind({ argv: args, env, PoolClass }), (error) => error instanceof IdentityBindError && error.code === "identity_rebind_forbidden");
  const pool = FakePool.instances[0];
  assert.equal(pool.client.calls.at(-1).text, "ROLLBACK");
  assert.equal(pool.client.released, true);
});

test("fails closed when the exact membership is missing", async () => {
  const PoolClass = usePool([Object.assign(new Error("membership missing"), { code: "23503" })]);
  await assert.rejects(() => runIdentityBind({ argv: args, env, PoolClass }), { code: "membership_not_active" });
  const pool = FakePool.instances[0];
  assert.equal(pool.client.calls.at(-1).text, "ROLLBACK");
  assert.equal(pool.client.calls.some(({ text }) => text.startsWith("INSERT INTO upstream_identities")), false);
});

test("requires named arguments and verified PostgreSQL TLS configuration before opening a pool", async () => {
  class ExplodingPool {
    constructor() { throw new Error("must not connect"); }
  }
  await assert.rejects(() => runIdentityBind({ argv: ["--provider", "github"], env, PoolClass: ExplodingPool }), { code: "invalid_arguments" });
  await assert.rejects(() => runIdentityBind({ argv: args, env: { AGENTPASS_IDENTITY_BIND_DATABASE_URL: "postgresql://agentpass_maintenance:secret@db.example.test/agentpass?sslmode=require" }, PoolClass: ExplodingPool }), { code: "database_config_invalid" });
  await assert.rejects(() => runIdentityBind({ argv: args, env: { AGENTPASS_IDENTITY_BIND_DATABASE_URL: "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full" }, PoolClass: ExplodingPool }), { code: "database_config_invalid" });
});

test("uses the existing TLS runtime settings and help output contains no connection material", async () => {
  const result = await runIdentityBind({ argv: ["--help"], env: { AGENTPASS_IDENTITY_BIND_DATABASE_URL: "postgresql://agentpass_maintenance:secret@db.example.test/agentpass?sslmode=require" } });
  assert.deepEqual(result.required, ["--provider VALUE", "--subject VALUE", "--member-id VALUE", "--organization-id VALUE"]);

  const PoolClass = usePool([{ rowCount: 1, rows: [{ result: "created" }] }]);
  await runIdentityBind({ argv: ["--provider", "github", "--subject", "s", "--member-id", ids.member, "--organization-id", ids.organization], env, PoolClass });
  const poolOptions = FakePool.instances[0].options;
  assert.deepEqual(poolOptions.ssl, { rejectUnauthorized: true });
  assert.equal(poolOptions.connectionString.includes("secret"), true);
});
