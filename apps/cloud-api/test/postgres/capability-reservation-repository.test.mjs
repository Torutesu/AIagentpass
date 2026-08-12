import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { CapabilityReservationRepositoryError, createPostgresCapabilityReservationRepository } from "../../src/postgres/capability-reservation-repository.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  agent: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444"
};
const NOW = "2026-08-13T00:00:00.000Z";
const SCOPE = { operations: ["git.commit.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } };

class FakeClient {
  constructor() { this.calls = []; this.records = new Map(); this.capability = null; }
  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result();
    if (text.startsWith("DELETE FROM idempotency_records")) return result();
    if (text.startsWith("INSERT INTO idempotency_records")) {
      const key = params.slice(0, 3).join("/");
      if (this.records.has(key)) return result();
      this.records.set(key, { request_hash: params[3], response_status: 102, response_json: {} });
      return result([], 1);
    }
    if (text.startsWith("SELECT request_hash,response_status,response_json")) return result([this.records.get(params.slice(0, 3).join("/"))]);
    if (text.startsWith("UPDATE idempotency_records")) {
      const row = this.records.get(params.slice(0, 3).join("/"));
      row.response_status = params[3]; row.response_json = JSON.parse(params[4]); return result([], 1);
    }
    if (text.includes("pg_advisory_xact_lock")) return result([{}]);
    if (text.startsWith("SELECT role,version FROM memberships")) return result([{ role: "owner", version: 7 }]);
    if (text.startsWith("SELECT a.id FROM agents")) return result([{ id: ids.agent }]);
    if (text.startsWith("INSERT INTO capabilities")) {
      this.capability = {
        organization_id: params[0], capability_id: params[1], agent_id: params[2], device_id: params[3], sequence: params[4],
        statement_hash: params[5], expires_at: params[6], issued_by_member_id: params[7], issued_membership_version: params[8],
        issuer: params[9], key_id: params[10], scope_json: JSON.parse(params[11]), not_before: params[12], revoked_at: null, version: 1
      };
      return result([this.capability]);
    }
    if (text.startsWith("SELECT organization_id,id AS capability_id")) return result(this.capability ? [this.capability] : []);
    throw new Error(`unexpected SQL: ${text}`);
  }
}

function repository(client = new FakeClient()) {
  return { client, repository: createPostgresCapabilityReservationRepository({ client, nonceSecret: Buffer.alloc(32, 0x51), now: () => NOW }) };
}

test("derives a stable cross-instance nonce while persisting only its digest and safe replay metadata", async () => {
  const { client, repository: repo } = repository();
  const input = { organization_id: ids.organization, principal_id: ids.member, created_by: ids.member, agent_id: ids.agent, device_id: ids.device, issuer: "agentpass-cloud", key_id: "control-v2", scope: SCOPE, sequence: 3, ttl_ms: 60_000, issued_at: NOW, idempotency_key: "capability-reserve-0001" };
  const first = await repo.reserveCapability(input);
  const second = await repo.reserveCapability({ ...input, issued_at: "2026-08-13T00:01:00.000Z" });
  assert.deepEqual(second, first);
  assert.match(first.capability_id, /^[0-9a-f-]{36}$/);
  assert.match(first.nonce, /^[A-Za-z0-9][A-Za-z0-9_-]{42}$/);
  const insertion = client.calls.find(({ text }) => text.startsWith("INSERT INTO capabilities"));
  assert.ok(Buffer.isBuffer(insertion.params[13]));
  assert.equal(insertion.params[13].length, 32);
  assert.equal(insertion.params.includes(first.nonce), false);
  const completed = client.calls.find(({ text }) => text.startsWith("UPDATE idempotency_records"));
  assert.equal(completed.params[4].includes(first.nonce), false);
  assert.equal(JSON.stringify(client.records).includes(first.nonce), false);
  const statement = { version: 1, capability_id: first.capability_id, nonce: first.nonce, issuer: first.issuer, key_id: first.key_id, audience: { agent_id: first.agent_id, device_id: first.device_id }, scope: first.scope, not_before: first.not_before, expires_at: first.expires_at, sequence: first.sequence };
  assert.equal(first.capability_hash, crypto.createHash("sha256").update(canonicalJson(statement)).digest("hex"));
  assert.equal(client.calls.filter(({ text }) => text.startsWith("INSERT INTO capabilities")).length, 1);
});

test("lists tenant capabilities without reconstructing or exposing bearer nonces", async () => {
  const { repository: repo } = repository();
  const input = { organization_id: ids.organization, principal_id: ids.member, created_by: ids.member, agent_id: ids.agent, device_id: ids.device, issuer: "agentpass-cloud", key_id: "control-v2", scope: SCOPE, sequence: 1, ttl_ms: 60_000, issued_at: NOW, idempotency_key: "capability-list-0001" };
  await repo.reserveCapability(input);
  const [listed] = await repo.listCapabilities({ organization_id: ids.organization });
  assert.equal(Object.hasOwn(listed, "nonce"), false);
  assert.equal(listed.organization_id, ids.organization);
  assert.equal(listed.status, "active");
});

test("rejects missing authority and hides database details", async () => {
  const { repository: repo } = repository();
  await assert.rejects(repo.reserveCapability({}), { code: "ERR_INPUT" });
  const broken = createPostgresCapabilityReservationRepository({ client: { async query() { throw new Error("password=do-not-leak"); } }, nonceSecret: Buffer.alloc(32), now: () => NOW });
  await assert.rejects(broken.listCapabilities({ organization_id: ids.organization }), (error) => error instanceof CapabilityReservationRepositoryError && error.code === "ERR_DATABASE" && !error.message.includes("do-not-leak"));
});

function result(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
