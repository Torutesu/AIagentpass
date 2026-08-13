import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  CloudAgentAuditRepositoryError,
  createPostgresCloudAgentAuditRepository
} from "../src/postgres/cloud-agent-audit-repository.mjs";

const ids = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  grant: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  event: "66666666-6666-4666-8666-666666666666"
});
const NOW = "2026-08-13T00:00:00.000Z";
const CONSUMED = "2026-08-12T23:59:59.000Z";
const DIGESTS = Object.freeze({
  grant: "a".repeat(64), statement: "b".repeat(64), process: "c".repeat(64),
  ancestry: "d".repeat(64), worktree: "e".repeat(64)
});

class MockClient {
  constructor({ head = { sequence: 4, last_event_hash: "f".repeat(64) }, existing = undefined, authority = authorityRow() } = {}) {
    this.calls = [];
    this.head = head;
    this.existing = existing;
    this.authority = authority;
    this.inserted = undefined;
    this.updated = false;
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text.startsWith("INSERT INTO cloud_agent_audit_heads")) return { rows: [], rowCount: 1 };
    if (text.startsWith("SELECT sequence,last_event_hash")) return result([this.head]);
    if (text.startsWith("SELECT\n      g.organization_id")) return result([this.authority]);
    if (text.startsWith("SELECT organization_id,sequence,event_id")) return result(this.existing ? [this.existing] : []);
    if (text.startsWith("INSERT INTO cloud_agent_audit_events")) {
      this.inserted = eventFromParams(params);
      return result([this.inserted]);
    }
    throw new Error(`unexpected query ${text}`);
  }
}

test("appends a canonical consumed event on the caller-owned transaction", async () => {
  const client = new MockClient();
  const repository = createPostgresCloudAgentAuditRepository({ now: () => NOW });
  const event = await repository.appendAgentSessionGrantConsumedInTransaction({ tx: client, ...input() });

  assert.equal(event.event_type, "agent_session_grant.consumed");
  assert.equal(event.sequence, 5);
  assert.equal(event.previous_hash, "f".repeat(64));
  assert.equal(event.consumed_at, CONSUMED);
  assert.equal(event.recorded_at, NOW);
  assert.equal(Object.isFrozen(event), true);
  assert.deepEqual(Object.keys(event), [
    "organization_id", "sequence", "event_id", "event_type", "grant_id", "session_id", "device_id", "agent_id",
    "grant_hash", "statement_hash", "signer_key_id", "process_binding_sha256", "ancestry_binding_sha256",
    "worktree_binding_sha256", "control_sequence", "authority_generation", "consumed_at", "recorded_at",
    "previous_hash", "event_hash"
  ]);
  assert.equal(client.calls.some(({ text }) => /\b(?:BEGIN|COMMIT|ROLLBACK)\b/u.test(text)), false);
  assert.equal(client.updated, false, "the database trigger owns head advancement");
  assert.equal(client.inserted.event_hash, hashWithoutEventHash(client.inserted));
});

test("an exact retry verifies and returns the existing event without inserting or advancing the head", async () => {
  const firstClient = new MockClient();
  const repository = createPostgresCloudAgentAuditRepository({ now: () => NOW });
  const first = await repository.appendAgentSessionGrantConsumedInTransaction({ tx: firstClient, ...input() });
  const retryClient = new MockClient({ existing: first });

  const retried = await repository.appendAgentSessionGrantConsumedInTransaction({ tx: retryClient, ...input() });
  assert.deepEqual(retried, first);
  assert.equal(retryClient.calls.some(({ text }) => text.startsWith("INSERT INTO cloud_agent_audit_events")), false);
  assert.equal(retryClient.calls.some(({ text }) => text.startsWith("UPDATE cloud_agent_audit_heads")), false);
});

test("rejects a tenant or binding mismatch with opaque stable errors", async () => {
  const repository = createPostgresCloudAgentAuditRepository({ now: () => NOW });
  const tenantMismatch = new MockClient({ authority: authorityRow({ grant_organization_id: ids.device }) });
  await assert.rejects(
    repository.appendAgentSessionGrantConsumedInTransaction({ tx: tenantMismatch, ...input() }),
    (error) => error instanceof CloudAgentAuditRepositoryError && error.code === "ERR_TENANT_MISMATCH"
  );

  const bindingMismatch = new MockClient({ authority: authorityRow({ process_binding_sha256: "9".repeat(64) }) });
  await assert.rejects(
    repository.appendAgentSessionGrantConsumedInTransaction({ tx: bindingMismatch, ...input() }),
    (error) => error instanceof CloudAgentAuditRepositoryError && error.code === "ERR_BINDING_MISMATCH"
  );
});

test("rejects malformed database results without exposing database details", async () => {
  const repository = createPostgresCloudAgentAuditRepository({ now: () => NOW });
  const client = new MockClient({ head: { sequence: "not-a-sequence", last_event_hash: "password" } });
  await assert.rejects(
    repository.appendAgentSessionGrantConsumedInTransaction({ tx: client, ...input() }),
    (error) => error instanceof CloudAgentAuditRepositoryError
      && error.code === "ERR_DB_RESULT"
      && !error.message.includes("password")
  );
});

function input(overrides = {}) {
  return {
    organization_id: ids.organization,
    event_id: ids.event,
    grant_id: ids.grant,
    session_id: ids.session,
    device_id: ids.device,
    agent_id: ids.agent,
    grant_hash: DIGESTS.grant,
    statement_hash: DIGESTS.statement,
    signer_key_id: "grant-signer-v1",
    process_binding_sha256: DIGESTS.process,
    ancestry_binding_sha256: DIGESTS.ancestry,
    worktree_binding_sha256: DIGESTS.worktree,
    control_sequence: 12,
    authority_generation: 7,
    consumed_at: CONSUMED,
    recorded_at: NOW,
    ...overrides
  };
}

function authorityRow(overrides = {}) {
  return {
    grant_organization_id: ids.organization,
    grant_id: ids.grant,
    grant_device_id: ids.device,
    grant_agent_id: ids.agent,
    grant_hash: DIGESTS.grant,
    statement_hash: DIGESTS.statement,
    signer_key_id: "grant-signer-v1",
    grant_control_sequence: 12,
    grant_authority_generation: 7,
    consumed_at: CONSUMED,
    consumed_session_id: ids.session,
    session_organization_id: ids.organization,
    session_id: ids.session,
    session_device_id: ids.device,
    session_agent_id: ids.agent,
    session_grant_hash: DIGESTS.grant,
    process_binding_sha256: DIGESTS.process,
    ancestry_binding_sha256: DIGESTS.ancestry,
    worktree_binding_sha256: DIGESTS.worktree,
    session_control_sequence: 12,
    session_authority_generation: 7,
    ...overrides
  };
}

function eventFromParams(params) {
  return Object.fromEntries([
    "organization_id", "sequence", "event_id", "event_type", "grant_id", "session_id", "device_id", "agent_id",
    "grant_hash", "statement_hash", "signer_key_id", "process_binding_sha256", "ancestry_binding_sha256",
    "worktree_binding_sha256", "control_sequence", "authority_generation", "consumed_at", "recorded_at",
    "previous_hash", "event_hash"
  ].map((key, index) => [key, params[index]]));
}

function hashWithoutEventHash(event) {
  const preimage = { ...event };
  delete preimage.event_hash;
  return crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex");
}

function result(rows) {
  return { rows, rowCount: rows.length };
}
