import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_CHAINS,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorStatementHash
} from "../../src/audit-anchor-statement.mjs";
import {
  AuditExportIssuanceRepositoryError,
  createPostgresAuditExportIssuanceRepository
} from "../../src/postgres/audit-export-issuance-repository.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const IDENTITY = Object.freeze({
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin",
  idempotency_key: "audit-export-request-0001"
});
const NOW = new Date("2026-08-15T00:00:00.000Z");
const RANGE = Object.freeze({
  from_audit_position: 1,
  to_audit_position: 2,
  previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
  root_digest: "a".repeat(64),
  record_count: 2
});
const PAYLOAD = Object.freeze({ events: { one: { id: "one" }, two: { id: "two" } } });
const KEY_ID = "audit-anchor-production-v1";

function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function requestDigest(identity, range, payloadDigest) {
  return digest(canonicalJson({ version: 1, ...identity, range, payload_digest: payloadDigest }));
}

function descriptor(overrides = {}) {
  return {
    range: RANGE,
    payload: PAYLOAD,
    key_id: KEY_ID,
    key_version: 7,
    lifecycle_version: 3,
    ...overrides
  };
}

function makeAnchor(authority, overrides = {}) {
  const statement = {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    organization_id: authority.organization_id,
    environment: authority.environment,
    chain: authority.chain,
    export_id: authority.export_id,
    audit_position: authority.range.to_audit_position,
    previous_audit_position: authority.range.from_audit_position - 1,
    root_digest: authority.range.root_digest,
    previous_root_digest: authority.range.previous_root_digest,
    export_digest: authority.payload_digest,
    record_count: authority.range.record_count,
    purpose: AUDIT_ANCHOR_PURPOSE,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    lifecycle_version: authority.lifecycle_version,
    key_id: authority.key_id,
    key_version: authority.key_version,
    issued_at: authority.issued_at,
    expires_at: authority.expires_at
  };
  return {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    statement,
    statement_hash: auditAnchorStatementHash(statement),
    signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
    signer_key_fingerprint: `SHA256:${"f".repeat(43)}`,
    signature: Buffer.alloc(64, 7).toString("base64url"),
    ...overrides
  };
}

function rowFromInsert(params) {
  const issuedAt = NOW.toISOString();
  const expiresAt = new Date(NOW.getTime() + params[12]).toISOString();
  return {
    organization_id: params[0], export_id: params[1], environment: params[2], chain: params[3], idempotency_key: params[4], state: "reserved",
    from_audit_position: params[5], to_audit_position: params[6], previous_root_digest: params[7], root_digest: params[8], record_count: params[9],
    payload_digest: params[10], request_digest: params[11], issued_at: issuedAt, expires_at: expiresAt,
    claim_expires_at: new Date(NOW.getTime() + params[13]).toISOString(), key_id: params[14], key_version: params[15],
    lifecycle_version: params[16], claim_token_digest: params[17], audit_anchor: null, uncertain_reason: null
  };
}

function harness({ reader = descriptor, raceInsert = false, commitResponseLost = false } = {}) {
  const rows = new Map();
  const queries = [];
  const readerCalls = [];
  let now = NOW;
  let raced = false;
  const key = (identity) => [identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key].join("|");
  const tx = {
    async query(sql, params = []) {
      queries.push({ sql: String(sql), params: [...params] });
      if (/^BEGIN|^COMMIT|^ROLLBACK/u.test(String(sql))) return result([]);
      if (/set_config\('agentpass\.organization_id'/u.test(sql)) return result([{ organization_id: params[0] }]);
      if (/current_setting\('agentpass\.organization_id'/u.test(sql)) return result([{ organization_id: ORGANIZATION_ID }]);
      if (/pg_advisory_xact_lock/u.test(sql)) return result([{ locked: null }]);
      if (/SELECT clock_timestamp\(\)/u.test(sql)) return result([{ now }]);
      if (/FROM audit_export_issuances/u.test(sql) && /state='committed'/u.test(sql) && /ORDER BY to_audit_position/u.test(sql)) {
        const committed = [...rows.values()].filter((row) => row.state === "committed" && row.organization_id === params[0] && row.environment === params[1] && row.chain === params[2]).sort((a, b) => b.to_audit_position - a.to_audit_position);
        return result(committed.slice(0, 1));
      }
      if (/FROM audit_export_issuances/u.test(sql) && /environment=\$2 AND chain=\$3/u.test(sql)) {
        const open = [...rows.values()].filter((row) => row.organization_id === params[0] && row.environment === params[1] && row.chain === params[2]
          && (row.state === "uncertain" || (row.state === "reserved" && Date.parse(row.claim_expires_at) > now.getTime())));
        return result(open.slice(0, 1));
      }
      if (/FROM audit_export_issuances/u.test(sql)) return result(rows.has(params.join("|")) ? [rows.get(params.join("|"))] : []);
      if (/^INSERT INTO audit_export_issuances/u.test(sql)) {
        const identityKey = params.slice(0, 5).join("|");
        if (raceInsert && !raced) {
          raced = true;
          const racedRow = rowFromInsert(params);
          racedRow.claim_token_digest = digest("another-racer-token");
          rows.set(identityKey, racedRow);
          return result([]);
        }
        if (!rows.has(identityKey)) rows.set(identityKey, rowFromInsert(params));
        return result([]);
      }
      if (/SET claim_token_digest=\$6/u.test(sql)) {
        const row = rows.get(params.slice(0, 5).join("|"));
        row.claim_token_digest = params[5];
        row.claim_expires_at = new Date(now.getTime() + params[6]).toISOString();
        return result([row]);
      }
      if (/SET state='committed'/u.test(sql)) {
        const identityKey = params.slice(0, 5).join("|");
        const row = rows.get(identityKey);
        row.state = "committed";
        row.claim_token_digest = null;
        row.claim_expires_at = null;
        row.audit_anchor = JSON.parse(params[5]);
        if (commitResponseLost) throw new Error("response lost; provider_diagnostics=private");
        return result([row]);
      }
      if (/SET state='uncertain'/u.test(sql)) {
        const row = rows.get(params.slice(0, 5).join("|"));
        row.state = "uncertain";
        row.claim_token_digest = null;
        row.claim_expires_at = null;
        row.uncertain_reason = params[5];
        return result([row]);
      }
      throw new Error(`unexpected SQL: ${String(sql).slice(0, 100)}`);
    }
  };
  const client = tx;
  const repository = createPostgresAuditExportIssuanceRepository({
    client,
    evidenceTtlMs: 120_000,
    claimLeaseMs: 30_000,
    async snapshotReader(readerTx, identity, previousBoundary) {
      assert.equal(readerTx, tx);
      readerCalls.push({ identity, previousBoundary });
      return reader === descriptor ? reader() : reader(identity, previousBoundary);
    }
  });
  return { repository, rows, queries, readerCalls, setNow(value) { now = value; } };
}

function result(rows) { return { rowCount: rows.length, rows }; }

test("reserves from a strict reader, sets tenant context, locks the chain, and stores only a token digest", async () => {
  const fixture = harness();
  const reserved = await fixture.repository.reserveAuditExport(IDENTITY);
  assert.equal(reserved.state, "reserved");
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(fixture.rows.values().next().value.claim_token_digest, reserved.claim_token);
  assert.equal(fixture.readerCalls.length, 1);
  assert.deepEqual(fixture.readerCalls[0].previousBoundary, { to_audit_position: 0, root_digest: AUDIT_ANCHOR_ZERO_DIGEST });
  assert.match(fixture.queries.find(({ sql }) => /INSERT INTO audit_export_issuances/u.test(sql)).sql, /ON CONFLICT \(organization_id,export_id,environment,chain,idempotency_key\) DO NOTHING/u);
  assert.match(fixture.queries[1].sql, /SELECT set_config\('agentpass\.organization_id'/u);
  assert.match(fixture.queries[3].sql, /pg_advisory_xact_lock/u);
});

test("serializes same-chain races and refuses to create a second open export", async () => {
  const raced = harness({ raceInsert: true });
  const first = await raced.repository.reserveAuditExport(IDENTITY);
  assert.equal(first.state, "in_progress");
  assert.equal(raced.readerCalls.length, 1);
  const second = harness();
  const firstReservation = await second.repository.reserveAuditExport(IDENTITY);
  const secondReservation = await second.repository.reserveAuditExport({ ...IDENTITY, export_id: "33333333-3333-4333-8333-333333333333", idempotency_key: "audit-export-request-0002" });
  assert.equal(firstReservation.state, "reserved");
  assert.deepEqual(secondReservation, { state: "in_progress" });
  assert.equal(second.readerCalls.length, 1);
});

test("enforces previous committed boundary and exact commit binding", async () => {
  const fixture = harness({ reader: (_identity, previous) => descriptor({ range: { ...RANGE, from_audit_position: previous.to_audit_position + 1, to_audit_position: previous.to_audit_position + 2, previous_root_digest: previous.root_digest } }) });
  const reserved = await fixture.repository.reserveAuditExport(IDENTITY);
  const authority = { ...reserved };
  delete authority.state;
  delete authority.claim_token;
  const anchor = makeAnchor(authority);
  await assert.rejects(fixture.repository.commitAuditExport({ ...authority, claim_token: reserved.claim_token, audit_anchor: makeAnchor(authority, { statement_hash: "0".repeat(64) }) }), (error) => error instanceof AuditExportIssuanceRepositoryError && error.code.includes("BINDING"));
  const committed = await fixture.repository.commitAuditExport({ ...authority, claim_token: reserved.claim_token, audit_anchor: anchor });
  assert.equal(committed.state, "committed");
  assert.equal(Object.hasOwn(committed, "claim_token"), false);
});

test("claim loss and lease expiry are fenced without exposing token material", async () => {
  const fixture = harness();
  const reserved = await fixture.repository.reserveAuditExport(IDENTITY);
  const authority = { ...reserved };
  delete authority.state;
  delete authority.claim_token;
  await assert.rejects(fixture.repository.commitAuditExport({ ...authority, claim_token: "A".repeat(43), audit_anchor: makeAnchor(authority) }), (error) => error.code.includes("CLAIM"));
  fixture.setNow(new Date("2026-08-15T00:02:00.000Z"));
  await assert.rejects(fixture.repository.markAuditExportUncertain({ ...authority, claim_token: reserved.claim_token, reason: "commit_failure" }), (error) => error.code.includes("CLAIM"));
  assert.equal(JSON.stringify(fixture.rows).includes(reserved.claim_token), false);
});

test("reclaims an expired claim with immutable evidence authority and releases claim material by state", async () => {
  const fixture = harness();
  const first = await fixture.repository.reserveAuditExport(IDENTITY);
  const storedBefore = structuredClone(fixture.rows.values().next().value);
  fixture.setNow(new Date("2026-08-15T00:00:45.000Z"));
  const reclaimed = await fixture.repository.reserveAuditExport(IDENTITY);
  const storedAfter = fixture.rows.values().next().value;
  assert.equal(reclaimed.state, "reserved");
  assert.notEqual(reclaimed.claim_token, first.claim_token);
  assert.equal(fixture.readerCalls.length, 1);
  assert.equal(storedAfter.issued_at, storedBefore.issued_at);
  assert.equal(storedAfter.expires_at, storedBefore.expires_at);
  assert.equal(storedAfter.from_audit_position, storedBefore.from_audit_position);
  assert.equal(Buffer.from(storedAfter.payload_digest).toString("hex"), Buffer.from(storedBefore.payload_digest).toString("hex"));
  const reclaimSql = fixture.queries.find(({ sql }) => /SET claim_token_digest=\$6/u.test(sql));
  assert.match(reclaimSql.sql, /claim_expires_at=clock_timestamp\(\)/u);
  assert.equal(/\b(?:issued_at|expires_at)\s*=/u.test(reclaimSql.sql), false);

  const uncertainFixture = harness();
  const uncertainReservation = await uncertainFixture.repository.reserveAuditExport(IDENTITY);
  const authority = { ...uncertainReservation };
  delete authority.state;
  delete authority.claim_token;
  const uncertain = await uncertainFixture.repository.markAuditExportUncertain({
    ...authority, claim_token: uncertainReservation.claim_token, reason: "signer_failure"
  });
  assert.deepEqual(uncertain, { state: "uncertain" });
  const uncertainRow = uncertainFixture.rows.values().next().value;
  assert.equal(uncertainRow.claim_token_digest, null);
  assert.equal(uncertainRow.claim_expires_at, null);
});

test("response loss is replayable and committed DTOs/errors are redacted", async () => {
  const fixture = harness({ commitResponseLost: true });
  const reserved = await fixture.repository.reserveAuditExport(IDENTITY);
  const authority = { ...reserved };
  delete authority.state;
  delete authority.claim_token;
  await assert.rejects(fixture.repository.commitAuditExport({ ...authority, claim_token: reserved.claim_token, audit_anchor: makeAnchor(authority) }), (error) => {
    assert.equal(error.message, "audit export issuance storage is unavailable");
    assert.equal(error.message.includes(reserved.claim_token), false);
    assert.equal(error.message.includes("private"), false);
    return true;
  });
  const replay = await fixture.repository.replayAuditExport(IDENTITY);
  assert.equal(replay.state, "committed");
  assert.equal(JSON.stringify(replay).includes("claim_token"), false);
  assert.equal(JSON.stringify(replay).includes("provider_diagnostics"), false);
});

test("rejects caller-supplied snapshot data and noncanonical/private anchor trees", async () => {
  const fixture = harness();
  await assert.rejects(fixture.repository.reserveAuditExport({ ...IDENTITY, range: RANGE }), { code: "ERR_AUDIT_EXPORT_ISSUANCE_INPUT" });
  await fixture.repository.reserveAuditExport(IDENTITY);
  assert.deepEqual(await fixture.repository.reserveAuditExport(IDENTITY), { state: "in_progress" });
});

void AUDIT_ANCHOR_CHAINS;
void AUDIT_ANCHOR_SIGNATURE_DOMAIN;
