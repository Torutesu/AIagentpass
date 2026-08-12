import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CapabilityAuthorityRepositoryError,
  createCapabilityAuthorityRepository
} from "../../src/postgres/capability-authority-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  capability: "33333333-3333-4333-8333-333333333333",
  capability2: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  device: "66666666-6666-4666-8666-666666666666"
};
const NOW = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-12T00:15:00.000Z";
const HASH = "a".repeat(64);
const TEST_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();

class FakeClient {
  constructor({ membership = { member_id: ids.member, role: "admin", version: 7 }, capabilities = [], existingCapability = undefined } = {}) {
    this.membership = membership;
    this.capabilities = capabilities;
    this.existingCapability = existingCapability;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.startsWith("SELECT member_id,role,version")) return this.membership ? { rows: [this.membership], rowCount: 1 } : { rows: [], rowCount: 0 };
    if (text.startsWith("INSERT INTO capabilities")) {
      if (this.existingCapability) return { rows: [], rowCount: 0 };
      const row = {
        organization_id: params[0], capability_id: params[1], agent_id: params[2], device_id: params[3],
        sequence: params[4], statement_hash: params[5], expires_at: params[6], revoked_at: null,
        issued_by_member_id: params[7], issued_membership_version: params[8]
      };
      return { rows: [row], rowCount: 1 };
    }
    if (text.startsWith("SELECT organization_id,id AS capability_id")) return this.existingCapability ? { rows: [this.existingCapability], rowCount: 1 } : { rows: [], rowCount: 0 };
    if (text.startsWith("UPDATE capabilities")) {
      const rows = this.capabilities.filter((row) => row.organization_id === params[0] && row.issued_by_member_id === params[1] && row.revoked_at === null).map((row) => ({ ...row, revoked_at: params[2] }));
      return { rows, rowCount: rows.length };
    }
    if (text.startsWith("SELECT id AS capability_id")) {
      const rows = this.capabilities
        .filter((row) => row.organization_id === params[0] && row.revoked_at !== null && Date.parse(row.expires_at) > Date.parse(params[1]))
        .sort((left, right) => left.capability_id.localeCompare(right.capability_id))
        .slice(0, params[2])
        .map((row) => ({ capability_id: row.capability_id }));
      return { rows, rowCount: rows.length };
    }
    throw new Error(`unexpected query: ${text}`);
  }
}

function issueInput(overrides = {}) {
  return {
    organization_id: ids.organization,
    capability_id: ids.capability,
    agent_id: ids.agent,
    device_id: ids.device,
    sequence: 3,
    statement_hash: HASH,
    expires_at: EXPIRES,
    issued_by_member_id: ids.member,
    ...overrides
  };
}

test("migration 0007 revokes unattributable legacy authority and requires attribution for active capabilities", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0007_capability_membership_authority.sql", import.meta.url), "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.match(sql, /ADD COLUMN issued_by_member_id uuid/);
  assert.match(sql, /ADD COLUMN issued_membership_version bigint/);
  assert.match(sql, /UPDATE capabilities\s+SET revoked_at = clock_timestamp\(\)\s+WHERE revoked_at IS NULL/);
  assert.doesNotMatch(sql, /WITH candidates AS|SET issued_by_member_id\s*=/);
  assert.match(sql, /capabilities_active_membership_authority_complete/);
  assert.match(sql, /revoked_at IS NOT NULL[\s\S]*issued_by_member_id IS NOT NULL[\s\S]*issued_membership_version IS NOT NULL/);
  assert.match(sql, /FOREIGN KEY \(issued_by_member_id\)\s+REFERENCES members \(id\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, issued_by_member_id\)\s+REFERENCES memberships \(organization_id, member_id\)/);
  assert.match(sql, /CREATE INDEX capabilities_issued_by_member_active_lookup[\s\S]*organization_id, issued_by_member_id/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/i);
});

test("exposes a frozen authority API and validates input before opening a transaction", async () => {
  const client = new FakeClient();
  const repository = createCapabilityAuthorityRepository({ client, now: () => NOW });
  assert.equal(Object.isFrozen(repository), true);
  assert.deepEqual(Object.keys(repository).sort(), ["issueCapabilityMetadata", "listRevokedCapabilityIds", "revokeActiveCapabilitiesForMember"].sort());
  await assert.rejects(repository.issueCapabilityMetadata(issueInput({ statement_hash: "not-a-hash" })), { code: "ERR_STATEMENT_HASH" });
  await assert.rejects(repository.revokeActiveCapabilitiesForMember({ organization_id: "not-a-uuid", member_id: ids.member }), { code: "ERR_TENANT_SCOPE" });
  assert.equal(client.calls.length, 0);
});

test("lists only unexpired durable revocations for ControlBundle generation and fails closed at capacity", async () => {
  const expired = "77777777-7777-4777-8777-777777777777";
  const client = new FakeClient({ capabilities: [
    { organization_id: ids.organization, capability_id: ids.capability2, expires_at: EXPIRES, revoked_at: NOW },
    { organization_id: ids.organization, capability_id: ids.capability, expires_at: EXPIRES, revoked_at: NOW },
    { organization_id: ids.organization, capability_id: expired, expires_at: NOW, revoked_at: NOW }
  ] });
  const repository = createCapabilityAuthorityRepository({ client, now: () => NOW });
  assert.deepEqual(await repository.listRevokedCapabilityIds({ organization_id: ids.organization }), [ids.capability, ids.capability2]);
  const query = client.calls.at(-1);
  assert.match(query.text, /revoked_at IS NOT NULL AND expires_at>\$2::timestamptz/);
  assert.match(query.text, /ORDER BY id ASC\s+LIMIT \$3/);
  assert.deepEqual(query.params, [ids.organization, NOW, 257]);

  const overflow = new FakeClient({ capabilities: Array.from({ length: 257 }, (_, index) => ({
    organization_id: ids.organization,
    capability_id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    expires_at: EXPIRES,
    revoked_at: NOW
  })) });
  await assert.rejects(createCapabilityAuthorityRepository({ client: overflow, now: () => NOW }).listRevokedCapabilityIds({ organization_id: ids.organization }), { code: "ERR_REVOCATION_CAPACITY" });
});

test("issues metadata from the locked active membership version and never trusts a stale caller version", async () => {
  const client = new FakeClient();
  const repository = createCapabilityAuthorityRepository({ client, now: () => NOW });
  const issued = await repository.issueCapabilityMetadata(issueInput());
  assert.deepEqual(issued, {
    organization_id: ids.organization,
    capability_id: ids.capability,
    agent_id: ids.agent,
    device_id: ids.device,
    sequence: 3,
    statement_hash: HASH,
    expires_at: EXPIRES,
    revoked_at: null,
    issued_by_member_id: ids.member,
    issued_membership_version: 7
  });
  assert.deepEqual(client.calls.slice(0, 4).map(({ text }) => text), ["BEGIN", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", "SELECT member_id,role,version\n        FROM memberships\n        WHERE organization_id=$1 AND member_id=$2 AND status='active'\n        FOR SHARE"]);
  assert.deepEqual(client.calls[1].params, [`agentpass:organization:${ids.organization}`]);
  assert.deepEqual(client.calls[2].params, [`agentpass:capability-authority:${ids.organization}:${ids.member}`]);
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO capabilities"));
  assert.deepEqual(insert.params, [ids.organization, ids.capability, ids.agent, ids.device, 3, HASH, EXPIRES, ids.member, 7]);

  const stale = new FakeClient({ membership: { member_id: ids.member, role: "admin", version: 8 } });
  await assert.rejects(createCapabilityAuthorityRepository({ client: stale, now: () => NOW }).issueCapabilityMetadata(issueInput({ issued_membership_version: 7 })), (error) => error instanceof CapabilityAuthorityRepositoryError && error.code === "ERR_MEMBERSHIP_VERSION");
  assert.equal(stale.calls.at(-1).text, "ROLLBACK");

  const inactive = new FakeClient({ membership: null });
  await assert.rejects(createCapabilityAuthorityRepository({ client: inactive, now: () => NOW }).issueCapabilityMetadata(issueInput()), { code: "ERR_MEMBER_NOT_ACTIVE" });
  assert.equal(inactive.calls.at(-1).text, "ROLLBACK");

  const viewer = new FakeClient({ membership: { member_id: ids.member, role: "viewer", version: 7 } });
  await assert.rejects(createCapabilityAuthorityRepository({ client: viewer, now: () => NOW }).issueCapabilityMetadata(issueInput()), { code: "ERR_MEMBER_NOT_ACTIVE" });
  assert.equal(viewer.calls.at(-1).text, "ROLLBACK");
});

test("same capability authority replays safely while a changed payload conflicts", async () => {
  const existing = {
    organization_id: ids.organization, capability_id: ids.capability, agent_id: ids.agent,
    device_id: ids.device, sequence: 3, statement_hash: HASH, expires_at: EXPIRES,
    revoked_at: null, issued_by_member_id: ids.member, issued_membership_version: 7
  };
  const replay = await createCapabilityAuthorityRepository({ client: new FakeClient({ existingCapability: existing }), now: () => NOW }).issueCapabilityMetadata(issueInput());
  assert.equal(replay.replayed, true);
  const conflictClient = new FakeClient({ existingCapability: { ...existing, statement_hash: "b".repeat(64) } });
  await assert.rejects(createCapabilityAuthorityRepository({ client: conflictClient, now: () => NOW }).issueCapabilityMetadata(issueInput()), { code: "ERR_CAPABILITY_CONFLICT" });
  assert.equal(conflictClient.calls.at(-1).text, "ROLLBACK");
});

test("revokeActiveCapabilitiesForMember atomically updates only unrevoked capabilities in the tenant", async () => {
  const client = new FakeClient({ capabilities: [
    { organization_id: ids.organization, capability_id: ids.capability, agent_id: ids.agent, device_id: ids.device, sequence: 1, statement_hash: HASH, expires_at: EXPIRES, revoked_at: null, issued_by_member_id: ids.member, issued_membership_version: 7 },
    { organization_id: ids.organization, capability_id: ids.capability2, agent_id: ids.agent, device_id: ids.device, sequence: 2, statement_hash: "b".repeat(64), expires_at: EXPIRES, revoked_at: NOW, issued_by_member_id: ids.member, issued_membership_version: 6 },
    { organization_id: "77777777-7777-4777-8777-777777777777", capability_id: ids.capability2, agent_id: ids.agent, device_id: ids.device, sequence: 1, statement_hash: HASH, expires_at: EXPIRES, revoked_at: null, issued_by_member_id: ids.member, issued_membership_version: 7 }
  ] });
  const result = await createCapabilityAuthorityRepository({ client, now: () => NOW, onAuthorityReduction: async () => ({ generation: 2 }) }).revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member });
  assert.equal(result.revoked_count, 1);
  assert.deepEqual(result.capability_ids, [ids.capability]);
  assert.equal(result.capabilities[0].revoked_at, NOW);
  const update = client.calls.find(({ text }) => text.startsWith("UPDATE capabilities"));
  assert.match(update.text, /organization_id=\$1 AND issued_by_member_id=\$2 AND revoked_at IS NULL/);
  assert.deepEqual(update.params, [ids.organization, ids.member, NOW]);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("couples authority reduction to the same transaction and skips it when nothing is revoked", async () => {
  const client = new FakeClient({ capabilities: [
    { organization_id: ids.organization, capability_id: ids.capability, agent_id: ids.agent, device_id: ids.device, sequence: 1, statement_hash: HASH, expires_at: EXPIRES, revoked_at: null, issued_by_member_id: ids.member, issued_membership_version: 7 }
  ] });
  const calls = [];
  const repository = createCapabilityAuthorityRepository({ client, now: () => NOW, onAuthorityReduction: async (input) => {
    calls.push(input);
    return { generation: 2 };
  } });
  await repository.revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].tx, client);
  assert.deepEqual(calls[0].capabilities.map(({ capability_id }) => capability_id), [ids.capability]);
  const noOp = new FakeClient({ capabilities: [{ ...client.capabilities[0], revoked_at: NOW }] });
  let noOpCalls = 0;
  await createCapabilityAuthorityRepository({ client: noOp, now: () => NOW, onAuthorityReduction: async () => { noOpCalls += 1; return { generation: 3 }; } })
    .revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member });
  assert.equal(noOpCalls, 0);
});

test("fails closed and rolls back when authority reduction propagation fails", async () => {
  const client = new FakeClient({ capabilities: [
    { organization_id: ids.organization, capability_id: ids.capability, agent_id: ids.agent, device_id: ids.device, sequence: 1, statement_hash: HASH, expires_at: EXPIRES, revoked_at: null, issued_by_member_id: ids.member, issued_membership_version: 7 }
  ] });
  await assert.rejects(
    createCapabilityAuthorityRepository({ client, now: () => NOW, onAuthorityReduction: async () => undefined })
      .revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member }),
    { code: "ERR_AUTHORITY_REDUCTION_UNAVAILABLE" }
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("revoke failure rolls back and does not leak database error details into the public error", async () => {
  const client = new FakeClient();
  const originalQuery = client.query.bind(client);
  client.query = async (text, params) => {
    if (text.startsWith("UPDATE capabilities")) throw new Error("statement contains secret internal detail");
    return originalQuery(text, params);
  };
  await assert.rejects(
    createCapabilityAuthorityRepository({ client, now: () => NOW }).revokeActiveCapabilitiesForMember({ organization_id: ids.organization, member_id: ids.member }),
    (error) => error.code === "ERR_DATABASE" && !error.message.includes("secret internal detail")
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("pins a pool-backed transaction to one released connection", async () => {
  const connected = new FakeClient();
  let released = false;
  const pool = {
    async query() { throw new Error("pool.query must not execute transaction statements"); },
    async connect() {
      connected.release = () => { released = true; };
      return connected;
    }
  };
  const issued = await createCapabilityAuthorityRepository({ client: pool, now: () => NOW }).issueCapabilityMetadata(issueInput());
  assert.equal(issued.issued_membership_version, 7);
  assert.equal(released, true);
  assert.equal(connected.calls.at(-1).text, "COMMIT");
});

test("real PostgreSQL capability authority behavior is exercised when AGENTPASS_TEST_DATABASE_URL is configured", async (t) => {
  const connectionString = process.env.AGENTPASS_TEST_DATABASE_URL;
  if (!connectionString) {
    t.skip("set AGENTPASS_TEST_DATABASE_URL to run the real PostgreSQL check");
    return;
  }
  const { default: pg } = await import("pg");
  const pool = new pg.Pool({ connectionString });
  try {
    const migrationClient = await pool.connect();
    try { await createMigrationRunner({ client: migrationClient, applicationVersion: "capability-authority-test" }).run(); }
    finally { migrationClient.release(); }
    const result = await pool.query("SELECT column_name,is_nullable FROM information_schema.columns WHERE table_name='capabilities' AND column_name IN ('issued_by_member_id','issued_membership_version') ORDER BY column_name");
    assert.deepEqual(result.rows, [
      { column_name: "issued_by_member_id", is_nullable: "YES" },
      { column_name: "issued_membership_version", is_nullable: "YES" }
    ]);

    const real = {
      organization: randomUUID(), member: randomUUID(), membership: randomUUID(),
      device: randomUUID(), agent: randomUUID(), capability: randomUUID()
    };
    await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Capability authority test')", [real.organization]);
    await pool.query("INSERT INTO members (id,github_subject) VALUES ($1,$2)", [real.member, `capability-${real.member}`]);
    await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [real.organization, real.membership, real.member]);
    await pool.query("INSERT INTO devices (organization_id,id,label,key_algorithm,status,public_key_pem) VALUES ($1,$2,'Test device','ed25519','active',$3)", [real.organization, real.device, TEST_PUBLIC_KEY]);
    await pool.query("INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status) VALUES ($1,$2,$3,'cli','Test agent',$4,'active')", [real.organization, real.agent, real.device, TEST_PUBLIC_KEY]);
    await assert.rejects(
      pool.query("INSERT INTO capabilities (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at) VALUES ($1,$2,$3,$4,1,$5,$6)", [real.organization, real.capability, real.agent, real.device, HASH, EXPIRES]),
      (error) => error.code === "23514" && error.constraint === "capabilities_active_membership_authority_complete"
    );
    const repository = createCapabilityAuthorityRepository({ client: pool, now: () => NOW, onAuthorityReduction: async () => ({ generation: 2 }) });
    const issued = await repository.issueCapabilityMetadata({
      organization_id: real.organization, capability_id: real.capability, agent_id: real.agent,
      device_id: real.device, sequence: 1, statement_hash: HASH, expires_at: EXPIRES,
      issued_by_member_id: real.member
    });
    assert.equal(issued.issued_by_member_id, real.member);
    assert.equal(issued.issued_membership_version, 1);
    await repository.revokeActiveCapabilitiesForMember({ organization_id: real.organization, member_id: real.member, revoked_at: NOW });
    assert.deepEqual(await repository.listRevokedCapabilityIds({ organization_id: real.organization, evaluated_at: NOW }), [real.capability]);
  } finally {
    await pool.end();
  }
});
