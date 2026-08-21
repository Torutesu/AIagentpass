import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AgentSessionAuthorityRepositoryError,
  createAgentSessionAuthorityRepository
} from "../../src/postgres/agent-session-authority-repository.mjs";

const ids = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  otherOrganization: "99999999-9999-4999-8999-999999999999",
  grant: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  adapter: "66666666-6666-4666-8666-666666666666",
  member: "77777777-7777-4777-8777-777777777777"
});
const NOW = "2026-08-13T10:00:00.000Z";
const NOT_BEFORE = "2026-08-13T09:59:00.000Z";
const EXPIRES = "2026-08-13T10:14:00.000Z";
const PROCESS = "a".repeat(64);
const ANCESTRY = "b".repeat(64);
const SIGNATURE = Buffer.alloc(64, 7).toString("base64url");
const SCOPE = Object.freeze({
  operations: ["git.commit.sign"],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@example.test:project.git"], deny: [] }
});
const AGENT_SESSIONS_MIGRATION = readFileSync(new URL("../../../../contracts/postgres/0019_agent_sessions.sql", import.meta.url), "utf8");

class ContractClient {
  constructor(options = {}, shared = undefined) {
    this.options = options;
    this.shared = shared ?? { grants: [], sessions: [], lockTail: new Map() };
    this.shared.lockTail ??= new Map();
    this.calls = [];
    this.snapshot = undefined;
    this.inTransaction = false;
    this.commitApplied = false;
    this.commitThrown = false;
  }

  async query(text, params = []) {
    this.calls.push({ text, params: structuredClone(params) });
    if (text === "BEGIN") {
      this.inTransaction = true;
      this.snapshot = { grants: structuredClone(this.shared.grants), sessions: structuredClone(this.shared.sessions) };
      return result();
    }
    if (text === "COMMIT") {
      if (this.options.ambiguousCommit && !this.commitThrown) {
        this.commitThrown = true;
        this.commitApplied = true;
        throw new Error("commit response lost private key material");
      }
      this.releaseLocks();
      this.inTransaction = false;
      this.snapshot = undefined;
      return result();
    }
    if (text === "ROLLBACK") {
      if (!this.commitApplied && this.snapshot) {
        this.shared.grants = this.snapshot.grants;
        this.shared.sessions = this.snapshot.sessions;
      }
      this.releaseLocks();
      this.inTransaction = false;
      this.snapshot = undefined;
      return result();
    }
    if (text.startsWith("SELECT set_config")) {
      return result([{ organization_id: this.options.tenantDrift ? ids.otherOrganization : params[0] }]);
    }
    if (text.startsWith("SELECT current_setting")) {
      return result([{ organization_id: this.options.tenantDrift ? ids.otherOrganization : this.calls.findLast((call) => call.text.startsWith("SELECT set_config"))?.params[0] }]);
    }
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      const key = params[0];
      const previous = this.shared.lockTail.get(key) ?? Promise.resolve();
      let release;
      const held = new Promise((resolve) => { release = resolve; });
      const tail = previous.then(() => held);
      this.shared.lockTail.set(key, tail);
      await previous;
      this.locks ??= [];
      this.locks.push({ key, tail, release });
      return result([{ locked: true }]);
    }
    if (text.includes("agentpass_agent_session_grant_issue(")) return this.issueGrantFunction(params);
    if (text.includes("agentpass_agent_session_grant_get(")) return this.getGrantFunction(params);
    if (text.includes("agentpass_agent_session_consume(")) return this.consumeGrantFunction(params);
    if (/FROM agents a[\s\S]*JOIN control_plane_authority_generations/u.test(text)) return this.options.staleAuthority ? result() : result([{ "?column?": 1 }]);
    if (text.startsWith("INSERT INTO agent_session_grants")) return this.insertGrant(params);
    if (text.startsWith("SELECT organization_id,grant_id,device_id,agent_id,agent_kind")) return this.selectGrant(text, params);
    if (text.startsWith("INSERT INTO agent_sessions")) return this.insertSession(params);
    if (text.startsWith("SELECT organization_id,session_id,grant_id,device_id,agent_id,agent_kind")) return this.selectSession(params);
    throw new Error(`unexpected query: ${text}`);
  }

  releaseLocks() {
    for (const lock of this.locks ?? []) {
      lock.release();
      if (this.shared.lockTail.get(lock.key) === lock.tail) this.shared.lockTail.delete(lock.key);
    }
    this.locks = [];
  }

  insertGrant(params) {
    if (this.options.failGrantInsert) throw new Error("grant insert contains private key material");
    const existing = this.shared.grants.find((row) => row.organization_id === params[0] && row.grant_id === params[1]);
    if (existing) return result();
    const row = {
      organization_id: params[0], grant_id: params[1], device_id: params[2], agent_id: params[3], agent_kind: params[4],
      adapter_id: params[5], adapter_version: params[6], worktree_binding_sha256: params[7], process_binding_policy_id: params[8],
      scope_json: JSON.parse(params[9]), max_signatures: params[10], not_before: params[11], expires_at: params[12],
      control_sequence: params[13], authority_generation: params[14], issuer: params[15], signer_key_id: params[16], statement_hash: params[17],
      grant_hash: params[18], signature_base64url: params[19], status: params[20], issued_at: params[21],
      consumed_at: null, consumed_session_id: null, consumed_process_binding_sha256: null, created_by: params[22]
    };
    this.shared.grants.push(row);
    if (this.options.malformedGrantReturn) return result([{ organization_id: params[0], grant_id: params[1] }]);
    return result([row]);
  }

  issueGrantFunction(params) {
    if (this.options.failGrantInsert) throw new Error("grant insert contains private key material");
    const existing = this.shared.grants.find((row) => row.organization_id === params[0] && row.grant_id === params[1]);
    if (existing) return result([{ ...existing, inserted: false }]);
    const row = {
      organization_id: params[0], grant_id: params[1], device_id: params[2], agent_id: params[3], agent_kind: params[4],
      adapter_id: params[5], adapter_version: params[6], worktree_binding_sha256: params[7], process_binding_policy_id: params[8],
      scope_json: JSON.parse(params[9]), max_signatures: params[10], not_before: params[11], expires_at: params[12],
      control_sequence: params[13], authority_generation: params[14], issuer: params[15], signer_key_id: params[16], statement_hash: params[17],
      grant_hash: params[18], signature_base64url: params[19], status: "issued", issued_at: params[20],
      consumed_at: null, consumed_session_id: null, consumed_process_binding_sha256: null, created_by: params[21]
    };
    this.shared.grants.push(row);
    if (this.options.malformedGrantReturn) return result([{ organization_id: params[0], grant_id: params[1] }]);
    return result([{ ...row, inserted: true }]);
  }

  getGrantFunction(params) {
    const row = this.shared.grants.find((candidate) => candidate.organization_id === params[0] && candidate.grant_id === params[1]);
    if (!row) return result();
    return result([this.options.crossTenantRow ? { ...row, organization_id: ids.otherOrganization } : row]);
  }

  consumeGrantFunction(params) {
    const grant = this.shared.grants.find((row) => row.organization_id === params[0] && row.grant_id === params[1] && row.device_id === params[2]);
    if (!grant) {
      const error = new Error("grant not found");
      error.constraint = "agent_session_authority_grant_not_found";
      throw error;
    }
    if (this.options.crossTenantRow) {
      const error = new Error("tenant drift");
      error.constraint = "agent_session_authority_tenant";
      throw error;
    }
    if (grant.status === "consumed") {
      const existing = this.shared.sessions.find((row) => row.organization_id === params[0] && row.session_id === grant.consumed_session_id && row.grant_id === params[1]);
      if (!existing || !["challenge_pending", "active", "request_reserved", "signing_intent", "signed"].includes(existing.status)) {
        const error = new Error("session unavailable");
        error.constraint = "agent_session_authority_session_unavailable";
        throw error;
      }
      if (Date.parse(existing.expires_at) <= Date.parse(this.options.now ?? NOW)) {
        const error = new Error("session expired");
        error.constraint = "agent_session_authority_session_expired";
        throw error;
      }
      if (existing.process_binding_sha256 !== params[20] || existing.ancestry_binding_sha256 !== params[21]
        || (params[23] && params[22] !== existing.session_id)) {
        const error = new Error("binding conflict");
        error.constraint = "agent_session_authority_binding_conflict";
        throw error;
      }
      return result([{ ...existing, replayed: true }]);
    }
    if (grant.status !== "issued") {
      const error = new Error("grant unavailable");
      error.constraint = "agent_session_authority_grant_unavailable";
      throw error;
    }
    if (this.options.failAgentSessionGrantConsumeUpdate) throw new Error("grant consume update failed");
    if (Date.parse(this.options.now ?? NOW) < Date.parse(grant.not_before)) {
      const error = new Error("grant not yet valid");
      error.constraint = "agent_session_authority_grant_not_yet_valid";
      throw error;
    }
    if (Date.parse(this.options.now ?? NOW) >= Date.parse(grant.expires_at)) {
      const error = new Error("grant expired");
      error.constraint = "agent_session_authority_grant_expired";
      throw error;
    }
    if (params[22] === null || params[22] === undefined) {
      const error = new Error("session id required");
      error.constraint = "agent_session_authority_session_id_required";
      throw error;
    }
    const sessionParams = [
      params[0], params[22], params[1], params[2], params[3], params[4], params[5], params[6], params[8], params[18],
      params[20], params[21], params[7], params[13], params[14], params[10], NOW, params[11], params[12]
    ];
    const inserted = this.insertSession(sessionParams);
    grant.status = "consumed";
    grant.consumed_at = NOW;
    grant.consumed_session_id = params[22];
    grant.consumed_process_binding_sha256 = params[20];
    return result(inserted.rows.map((row) => ({ ...row, replayed: false })));
  }

  selectGrant(text, params) {
    const row = this.shared.grants.find((candidate) => candidate.organization_id === params[0]
      && candidate.grant_id === params[1]
      && (!text.includes("device_id=$3") || candidate.device_id === params[2]));
    if (!row) return result();
    if (this.options.crossTenantRow) return result([{ ...row, organization_id: ids.otherOrganization }]);
    return result([row]);
  }

  insertSession(params) {
    const grant = this.shared.grants.find((row) => row.organization_id === params[0] && row.grant_id === params[2]);
    const existing = this.shared.sessions.find((row) => row.organization_id === params[0] && row.session_id === params[1]);
    if (existing) return result([existing]);
    // This is the BEFORE INSERT agent_sessions_consume_grant trigger from
    // contracts/postgres/0019_agent_sessions.sql. Keep it explicit: the
    // repository intentionally does not issue a second UPDATE for the grant.
    if (!this.options.disableAgentSessionsConsumeGrantTrigger) {
      this.agentSessionsConsumeGrantTrigger(params, grant);
    }
    // The trigger runs before the base INSERT. A later INSERT failure must be
    // undone by the same transaction, just as PostgreSQL would do.
    if (this.options.failSessionInsert) throw new Error("session insert failed after grant trigger");
    const row = {
      organization_id: params[0], session_id: params[1], grant_id: params[2], device_id: params[3], agent_id: params[4],
      agent_kind: params[5], adapter_id: params[6], adapter_version: params[7], process_binding_policy_id: params[8],
      grant_hash: params[9], process_binding_sha256: params[10], ancestry_binding_sha256: params[11],
      worktree_binding_sha256: params[12], control_sequence: params[13], authority_generation: params[14], max_signatures: params[15],
      used_signatures: 0, reserved_signatures: 0, status: "challenge_pending", created_at: params[16], not_before: params[17], expires_at: params[18]
    };
    this.shared.sessions.push(row);
    return result([row]);
  }

  agentSessionsConsumeGrantTrigger(params, grant) {
    if (!grant || grant.status !== "issued") throw new Error("grant was consumed concurrently");
    if (this.options.failAgentSessionGrantConsumeUpdate) throw new Error("grant consume update failed");
    grant.status = "consumed";
    grant.consumed_at = NOW;
    grant.consumed_session_id = params[1];
    grant.consumed_process_binding_sha256 = params[10];
  }

  selectSession(params) {
    const row = this.shared.sessions.find((candidate) => candidate.organization_id === params[0]
      && candidate.session_id === params[1] && candidate.grant_id === params[2]);
    return row ? result([row]) : result();
  }
}

function result(rows = []) {
  return { rows, rowCount: rows.length };
}

function statement(overrides = {}) {
  return {
    version: 1,
    grant_id: ids.grant,
    organization_id: ids.organization,
    device_id: ids.device,
    agent_id: ids.agent,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "c".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: SCOPE,
    max_signatures: 2,
    not_before: NOT_BEFORE,
    expires_at: EXPIRES,
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud",
    key_id: "agent-session-2026-08",
    ...overrides
  };
}

function grant(overrides = {}) {
  const nextStatement = statement(overrides.statement ?? {});
  const envelope = {
    version: 1,
    type: "agentpass.agent-session-grant",
    statement: nextStatement,
    statement_hash: crypto.createHash("sha256").update(canonicalJson(nextStatement), "utf8").digest("hex"),
    signature: SIGNATURE
  };
  return { ...envelope, ...overrides, statement: nextStatement };
}

function issueInput(overrides = {}) {
  return {
    organization_id: ids.organization,
    created_by: ids.member,
    issued_at: NOW,
    grant: grant(),
    ...overrides
  };
}

function consumeInput(overrides = {}) {
  return {
    organization_id: ids.organization,
    device_id: ids.device,
    grant: grant(),
    process_binding_sha256: PROCESS,
    ancestry_binding_sha256: ANCESTRY,
    ...overrides
  };
}

function repository(client, options = {}) {
  return createAgentSessionAuthorityRepository({ client, now: () => NOW, uuid: () => ids.session, ...options });
}

test("persists a canonical grant and returns the exact committed data on retry", async () => {
  const client = new ContractClient();
  const repo = repository(client);
  const first = await repo.issueAgentSessionGrant(issueInput());
  const second = await repo.issueAgentSessionGrant(issueInput());

  assert.equal(first.replayed, false);
  assert.equal(second.replayed, true);
  assert.deepEqual(second.grant, first.grant);
  const issue = client.calls.find((call) => call.text.includes("agentpass_agent_session_grant_issue("));
  assert.match(issue.text, /SECURITY DEFINER|agentpass_agent_session_grant_issue/u);
  assert.equal(issue.params[0], ids.organization);
  assert.equal(issue.params[17], first.grant.statement_hash);
  assert.equal(client.calls.filter((call) => call.text === "BEGIN").length, 2);
});

test("rejects a changed canonical grant under the same grant identity", async () => {
  const client = new ContractClient();
  const repo = repository(client);
  await repo.issueAgentSessionGrant(issueInput());
  const changed = grant({ statement: { max_signatures: 1 } });
  await assert.rejects(repo.issueAgentSessionGrant(issueInput({ grant: changed })), (error) => error.code === "ERR_GRANT_CONFLICT");
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("consumes once, binds both process and ancestry, and replays the original lease", async () => {
  const client = new ContractClient();
  const issued = issueInput();
  const repo = repository(client);
  await repo.issueAgentSessionGrant(issued);
  const request = consumeInput({ grant: issued.grant });
  const first = await repo.consumeAgentSessionGrant(request);
  const retry = await repo.consumeAgentSessionGrant(request);

  assert.equal(first.replayed, false);
  assert.equal(retry.replayed, true);
  assert.deepEqual(retry.lease, first.lease);
  assert.equal(first.lease.not_before, NOT_BEFORE);
  const consume = client.calls.find((call) => call.text.includes("agentpass_agent_session_consume("));
  assert.match(consume.text, /agentpass_agent_session_consume/u);
  assert.equal(consume.params[20], PROCESS);
  assert.equal(consume.params[21], ANCESTRY);
  assert.equal(consume.params[11], NOT_BEFORE);
  assert.equal(consume.params[12], EXPIRES);
  assert.equal(client.shared.grants[0].status, "consumed");
  assert.equal(client.shared.grants[0].consumed_at, NOW);
  assert.equal(client.shared.grants[0].consumed_session_id, ids.session);
  assert.equal(client.shared.grants[0].consumed_process_binding_sha256, PROCESS);
  assert.doesNotMatch(consume.text, /UPDATE\s+agent_session_grants/iu);
  assert.equal(client.calls.some(({ text }) => /UPDATE\s+agent_session_grants/iu.test(text)), false);
  await assert.rejects(repo.consumeAgentSessionGrant({ ...request, process_binding_sha256: "e".repeat(64) }), { code: "ERR_BINDING_CONFLICT" });
  await assert.rejects(repo.consumeAgentSessionGrant({ ...request, ancestry_binding_sha256: "d".repeat(64) }), { code: "ERR_BINDING_CONFLICT" });
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("never replays a terminal or expired session as a usable Lease", async () => {
  const client = new ContractClient();
  const repo = repository(client);
  const issued = issueInput();
  await repo.issueAgentSessionGrant(issued);
  const request = consumeInput({ grant: issued.grant });
  await repo.consumeAgentSessionGrant(request);
  client.shared.sessions[0].status = "revoked";
  client.shared.sessions[0].revoked_at = NOW;
  await assert.rejects(repo.consumeAgentSessionGrant(request), { code: "ERR_GRANT_UNAVAILABLE" });
  client.shared.sessions[0].status = "challenge_pending";
  client.shared.sessions[0].revoked_at = null;
  client.options.now = EXPIRES;
  const expiredRepo = repository(client, { now: () => EXPIRES });
  await assert.rejects(expiredRepo.consumeAgentSessionGrant(request), { code: "ERR_GRANT_EXPIRED" });
});

test("pins the migration trigger as the only grant-consumption transition", () => {
  const migration = AGENT_SESSIONS_MIGRATION.replace(/--[^\n]*\n/g, " ").replace(/\s+/gu, " ");
  assert.match(migration, /CREATE FUNCTION agentpass_consume_agent_session_grant_for_session\(\)/u);
  assert.match(migration, /SELECT grant_record\.\* INTO grant_row FROM agent_session_grants AS grant_record/u);
  assert.match(migration, /FOR UPDATE; IF NOT FOUND THEN/u);
  assert.match(migration, /UPDATE agent_session_grants SET status = 'consumed', consumed_at = clock_timestamp\(\), consumed_session_id = NEW\.session_id, consumed_process_binding_sha256 = NEW\.process_binding_sha256 WHERE organization_id = grant_row\.organization_id AND grant_id = grant_row\.grant_id AND status = 'issued';/u);
  assert.match(migration, /GET DIAGNOSTICS changed = ROW_COUNT; IF changed <> 1 THEN/u);
  assert.match(migration, /CREATE TRIGGER agent_sessions_consume_grant BEFORE INSERT ON agent_sessions FOR EACH ROW EXECUTE FUNCTION agentpass_consume_agent_session_grant_for_session\(\);/u);
});

test("does not allow a caller to bypass the function-owned grant transition", async () => {
  const client = new ContractClient({ disableAgentSessionsConsumeGrantTrigger: true });
  const repo = repository(client);
  const issued = issueInput();
  await repo.issueAgentSessionGrant(issued);
  const request = consumeInput({ grant: issued.grant });
  const first = await repo.consumeAgentSessionGrant(request);
  assert.equal(first.replayed, false);
  assert.equal(client.shared.grants[0].status, "consumed");
  assert.equal(client.shared.grants[0].consumed_session_id, ids.session);

  const retry = await repo.consumeAgentSessionGrant(request);
  assert.equal(retry.replayed, true);
  assert.equal(client.shared.grants[0].status, "consumed");
});

test("rolls back when the migration trigger's grant update fails", async () => {
  const client = new ContractClient({ failAgentSessionGrantConsumeUpdate: true });
  const repo = repository(client);
  const issued = issueInput();
  await repo.issueAgentSessionGrant(issued);

  await assert.rejects(repo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant })), { code: "ERR_DATABASE" });
  assert.equal(client.shared.grants[0].status, "issued");
  assert.equal(client.shared.grants[0].consumed_at, null);
  assert.equal(client.shared.grants[0].consumed_session_id, null);
  assert.equal(client.shared.grants[0].consumed_process_binding_sha256, null);
  assert.equal(client.shared.sessions.length, 0);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("two competing consumption attempts converge on one committed lease", async () => {
  const shared = { grants: [], sessions: [], lockTail: new Map() };
  const firstClient = new ContractClient({}, shared);
  const secondClient = new ContractClient({}, shared);
  const firstRepo = repository(firstClient, { uuid: () => ids.session });
  const secondRepo = repository(secondClient, { uuid: () => "88888888-8888-4888-8888-888888888888" });
  const issued = issueInput();
  await firstRepo.issueAgentSessionGrant(issued);
  const [first, second] = await Promise.all([
    firstRepo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant })),
    secondRepo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant }))
  ]);
  assert.deepEqual(first.lease, second.lease);
  assert.equal(shared.sessions.length, 1);
  assert.equal(firstClient.calls.some((call) => call.text.includes("agentpass_agent_session_consume(")), true);
  assert.equal(secondClient.calls.some((call) => call.text.includes("agentpass_agent_session_consume(")), true);
});

test("recovers an ambiguous commit by reading the immutable consumed grant", async () => {
  const client = new ContractClient({ ambiguousCommit: false });
  const repo = repository(client);
  const issued = issueInput();
  await repo.issueAgentSessionGrant(issued);
  client.options.ambiguousCommit = true;
  await assert.rejects(repo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant })), { code: "ERR_DATABASE" });
  const retry = await repo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant }));
  assert.equal(retry.replayed, true);
  assert.equal(retry.lease.session_id, ids.session);
});

test("rolls back grant consumption when session persistence fails", async () => {
  const client = new ContractClient({ failSessionInsert: true });
  const repo = repository(client);
  const issued = issueInput();
  await repo.issueAgentSessionGrant(issued);
  await assert.rejects(repo.consumeAgentSessionGrant(consumeInput({ grant: issued.grant })), { code: "ERR_DATABASE" });
  assert.equal(client.shared.grants[0].status, "issued");
  assert.equal(client.shared.sessions.length, 0);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("fails closed on tenant context drift, cross-tenant rows, and malformed output", async () => {
  const drift = new ContractClient({ tenantDrift: true });
  await assert.rejects(repository(drift).issueAgentSessionGrant(issueInput()), { code: "ERR_TENANT_DRIFT" });
  assert.equal(drift.calls.at(-1).text, "ROLLBACK");

  const crossTenant = new ContractClient({ crossTenantRow: true });
  const crossRepo = repository(crossTenant);
  await crossRepo.issueAgentSessionGrant(issueInput());
  await assert.rejects(crossRepo.consumeAgentSessionGrant(consumeInput()), (error) => ["ERR_TENANT_DRIFT", "ERR_TENANT_SCOPE", "ERR_GRANT_NOT_FOUND"].includes(error.code));

  const malformed = new ContractClient({ malformedGrantReturn: true });
  await assert.rejects(repository(malformed).issueAgentSessionGrant(issueInput()), { code: "ERR_DB_RESULT" });
  assert.equal(malformed.calls.at(-1).text, "ROLLBACK");
});

test("maps database failures to bounded public errors without leaking query details", async () => {
  const client = new ContractClient({ failGrantInsert: true });
  const error = await repository(client).issueAgentSessionGrant(issueInput()).catch((value) => value);
  assert(error instanceof AgentSessionAuthorityRepositoryError);
  assert.equal(error.code, "ERR_DATABASE");
  assert.doesNotMatch(error.message, /private key material/u);
  assert.equal(error.cause, undefined);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("uses transaction-local tenant context before any authority query", async () => {
  const client = new ContractClient();
  await repository(client).issueAgentSessionGrant(issueInput());
  const firstQueries = client.calls.slice(0, 4).map((call) => call.text);
  assert.deepEqual(firstQueries, [
    "BEGIN",
    "SELECT set_config('agentpass.organization_id',$1,true) AS organization_id",
    "SELECT current_setting('agentpass.organization_id',true) AS organization_id",
    "SELECT * FROM public.agentpass_agent_session_grant_issue(\n        $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::text,$6::uuid,$7::text,$8::text,$9::text,\n        $10::jsonb,$11::integer,$12::timestamptz,$13::timestamptz,$14::bigint,$15::bigint,\n        $16::text,$17::text,$18::text,$19::text,$20::text,$21::timestamptz,$22::uuid)"
  ]);
  assert.deepEqual(client.calls[1].params, [ids.organization]);
});
