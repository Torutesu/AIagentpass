import assert from "node:assert/strict";
import test from "node:test";

import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  owner: "22222222-2222-4222-8222-222222222222",
  target: "33333333-3333-4333-8333-333333333333",
  membership: "44444444-4444-4444-8444-444444444444"
};
const NOW = "2026-08-14T00:00:00.000Z";
const ZERO_HASH = "0".repeat(64);

function result(rows = [], rowCount = rows.length) {
  return { rows, rowCount };
}

function membership(overrides = {}) {
  return {
    organization_id: ids.organization,
    membership_id: ids.membership,
    member_id: ids.target,
    role: "admin",
    status: "active",
    version: 1,
    created_at: NOW,
    updated_at: NOW,
    ...overrides
  };
}

class EpochMockClient {
  constructor({ targetRole = "admin", mutation = "role" } = {}) {
    this.targetRole = targetRole;
    this.mutation = mutation;
    this.calls = [];
    this.requestHash = null;
  }

  async query(text, params = []) {
    this.calls.push({ text, params });

    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return result();
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return result();
    if (text.startsWith("DELETE FROM idempotency_records") && text.includes("expires_at<=")) return result([], 0);
    if (text.startsWith("INSERT INTO idempotency_records")) {
      this.requestHash = params[3];
      return result([], 1);
    }
    if (text.startsWith("SELECT request_hash,response_status,response_json")) {
      return result([{ request_hash: this.requestHash, response_status: 200, response_json: {} }]);
    }
    if (text.startsWith("DELETE FROM idempotency_records")) return result([], 1);
    if (text.startsWith("UPDATE idempotency_records")) return result([], 1);

    if (text.startsWith("SELECT role,status")) return result([{ role: "owner", status: "active" }]);
    if (text.startsWith("SELECT organization_id,id AS membership_id")) return result([membership({ role: this.targetRole })]);
    if (text.startsWith("UPDATE memberships target")) {
      const role = this.mutation === "role" ? params[3] : this.targetRole;
      return result([membership({ role, status: this.mutation === "remove" ? "revoked" : "active", version: 2 })]);
    }
    if (text.startsWith("UPDATE webauthn_challenges")) return result([], 1);
    if (text.startsWith("UPDATE human_sessions")) return result([], 1);
    if (text.startsWith("UPDATE capabilities")) return result([], 1);
    if (text.startsWith("INSERT INTO admin_audit_heads")) return result([], 1);
    if (text.startsWith("SELECT sequence,event_hash FROM admin_audit_heads")) return result([{ sequence: 0, event_hash: ZERO_HASH }]);
    if (text.startsWith("INSERT INTO admin_audit_events")) return result([], 1);
    if (text.startsWith("UPDATE admin_audit_heads")) return result([], 1);
    if (text.startsWith("INSERT INTO outbox_events")) return result([], 1);

    throw new Error(`unexpected SQL in epoch test: ${text}`);
  }
}

function repository(client, onAuthorityReduction = async () => ({ generation: 2 })) {
  return createPostgresOrganizationRepository({ client, now: () => NOW, onAuthorityReduction });
}

function input(overrides = {}) {
  return {
    organization_id: ids.organization,
    actor_member_id: ids.owner,
    member_id: ids.target,
    expected_version: 1,
    idempotency_key: "epoch-test-1",
    ...overrides
  };
}

test("role reduction advances only the target session_epoch and preserves unrelated member sessions", async () => {
  const client = new EpochMockClient({ targetRole: "admin", mutation: "role" });
  const reductions = [];
  const response = await repository(client, async (authority) => {
    reductions.push(authority);
    return { generation: 3 };
  }).updateMemberRole(input({ role: "viewer" }));

  const membershipUpdate = client.calls.find(({ text }) => text.startsWith("UPDATE memberships target"));
  assert.doesNotMatch(membershipUpdate.text, /session_epoch/);
  assert.equal(client.calls.some(({ text }) => text.includes("agentpass_bump_organization_authority_epoch")), false);
  assert.equal(client.calls.at(-1).text, "COMMIT");
  assert.equal(reductions.length, 1);
  assert.equal(reductions[0].tx, client);
  assert.equal(Object.hasOwn(response, "session_epoch"), false);
  assert.equal(Object.hasOwn(response, "authority_epoch"), false);
  assert.doesNotMatch(membershipUpdate.text, /RETURNING[\s\S]*session_epoch/);
});

test("member removal advances only the target session_epoch", async () => {
  const client = new EpochMockClient({ targetRole: "viewer", mutation: "remove" });
  const response = await repository(client).removeMember(input({ removed_at: NOW, idempotency_key: "epoch-remove-1" }));

  const membershipUpdate = client.calls.find(({ text }) => text.startsWith("UPDATE memberships target"));
  assert.match(membershipUpdate.text, /status='revoked'/);
  assert.doesNotMatch(membershipUpdate.text, /session_epoch/);
  assert.equal(client.calls.some(({ text }) => text.includes("agentpass_bump_organization_authority_epoch")), false);
  assert.equal(client.calls.at(-1).text, "COMMIT");
  assert.equal(response.status, "revoked");
  assert.deepEqual(Object.keys(response).sort(), [
    "created_at", "member_id", "membership_id", "organization_id", "role", "status", "updated_at", "version"
  ]);
});

test("a role widening also advances the target session_epoch but does not advance organization authority", async () => {
  const client = new EpochMockClient({ targetRole: "viewer", mutation: "role" });
  await repository(client).updateMemberRole(input({ role: "admin", idempotency_key: "epoch-widen-1" }));

  const membershipUpdate = client.calls.find(({ text }) => text.startsWith("UPDATE memberships target"));
  assert.doesNotMatch(membershipUpdate.text, /session_epoch/);
  assert.equal(client.calls.some(({ text }) => text.startsWith("UPDATE organizations")), false);
  assert.equal(client.calls.some(({ text }) => text.startsWith("SELECT agentpass_bump_organization_authority_epoch")), false);
});
