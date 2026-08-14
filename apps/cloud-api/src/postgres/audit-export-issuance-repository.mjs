import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_MAX_TTL_MS,
  AUDIT_ANCHOR_ZERO_DIGEST,
  normalizeAuditAnchor
} from "../audit-anchor-statement.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CLAIM_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const STATES = new Set(["reserved", "committed", "uncertain"]);
const CHAINS = new Set(["admin", "device", "cloud_agent"]);
const ENVIRONMENTS = new Set(["staging", "production"]);
const UNCERTAINTY_REASONS = new Set(["signer_failure", "stale_lifecycle", "signer_output", "commit_failure"]);
const MAX_DESCRIPTOR_BYTES = 256 * 1024;
const MAX_TREE_DEPTH = 16;
const MAX_TREE_ITEMS = 4096;
const MAX_TREE_STRING_BYTES = 16 * 1024;
const PRIVATE_MATERIAL = /(?:-----BEGIN [^-]*PRIVATE KEY-----|private[_ -]?key|secret|credential|provider[_ -]?diagnostic|claim[_ -]?token|signing[_ -]?bytes)/iu;
const PRIVATE_VALUE = /(?:-----BEGIN [^-]*PRIVATE KEY-----|(?:^|\s)Bearer\s+[A-Za-z0-9._~+/-]+=*(?:\s|$))/iu;

const IDENTITY_KEYS = Object.freeze([
  "organization_id", "export_id", "environment", "chain", "idempotency_key"
]);
const RETRIEVAL_KEYS = Object.freeze([
  "organization_id", "export_id", "environment", "chain"
]);
const RANGE_KEYS = Object.freeze([
  "from_audit_position", "to_audit_position", "previous_root_digest", "root_digest", "record_count"
]);
const DESCRIPTOR_KEYS = Object.freeze([
  "range", "payload", "key_id", "key_version", "lifecycle_version"
]);
const AUTHORITY_KEYS = Object.freeze([
  ...IDENTITY_KEYS, "range", "payload_digest", "request_digest", "issued_at", "expires_at",
  "key_id", "key_version", "lifecycle_version"
]);
const COMMIT_KEYS = Object.freeze([...AUTHORITY_KEYS, "claim_token", "audit_anchor"]);
const UNCERTAIN_KEYS = Object.freeze([...AUTHORITY_KEYS, "claim_token", "reason"]);
const ROW_COLUMNS = Object.freeze([
  "organization_id", "export_id", "environment", "chain", "idempotency_key", "state",
  "from_audit_position", "to_audit_position", "previous_root_digest", "root_digest", "record_count",
  "payload_digest", "request_digest", "issued_at", "expires_at", "claim_expires_at", "key_id", "key_version",
  "lifecycle_version", "claim_token_digest", "audit_anchor", "uncertain_reason"
]);
const ROW_SELECT = `organization_id,export_id,environment,chain,idempotency_key,state,
  from_audit_position,to_audit_position,encode(previous_root_digest,'hex') AS previous_root_digest,
  encode(root_digest,'hex') AS root_digest,record_count,encode(payload_digest,'hex') AS payload_digest,
  encode(request_digest,'hex') AS request_digest,issued_at,expires_at,claim_expires_at,key_id,key_version,
  lifecycle_version,encode(claim_token_digest,'hex') AS claim_token_digest,audit_anchor,uncertain_reason`;
const PK_WHERE = "organization_id=$1 AND export_id=$2 AND environment=$3 AND chain=$4 AND idempotency_key=$5";
const PAYLOAD_SELECT = `payload_bytes,payload_json,encode(payload_digest,'hex') AS payload_digest`;

const MESSAGES = Object.freeze({
  ERR_INPUT: "audit export issuance input is invalid",
  ERR_CONFIG: "audit export issuance repository configuration is invalid",
  ERR_CONFLICT: "audit export issuance conflicts with an existing request",
  ERR_IN_PROGRESS: "audit export issuance is already in progress",
  ERR_UNCERTAIN: "audit export signing outcome is uncertain",
  ERR_NOT_FOUND: "audit export issuance was not found",
  ERR_CLAIM: "audit export issuance claim is invalid",
  ERR_BINDING: "audit export issuance binding is invalid",
  ERR_SNAPSHOT: "audit export audit snapshot is unavailable",
  ERR_DATABASE: "audit export issuance storage is unavailable"
});

export class AuditExportIssuanceRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES.ERR_DATABASE);
    this.name = "AuditExportIssuanceRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code) ? `ERR_AUDIT_EXPORT_ISSUANCE_${code.slice(4)}` : "ERR_AUDIT_EXPORT_ISSUANCE_DATABASE";
  }
}

/**
 * PostgreSQL repository for audit export issuance.
 *
 * `snapshotReader` is deliberately the only source-audit dependency. It is
 * called as `snapshotReader(tx, identity, previousBoundary)` and must return
 * exactly `{ range, payload, key_id, key_version, lifecycle_version }`.
 * The reader must use `tx`; callers cannot provide a range or payload.
 */
export function createPostgresAuditExportIssuanceRepository({
  client,
  snapshotReader,
  evidenceTtlMs = AUDIT_ANCHOR_MAX_TTL_MS,
  claimLeaseMs = 60_000
} = {}) {
  assertClient(client);
  if (typeof snapshotReader !== "function") throw new AuditExportIssuanceRepositoryError("ERR_CONFIG");
  if (!Number.isSafeInteger(evidenceTtlMs) || evidenceTtlMs < 1_000 || evidenceTtlMs > AUDIT_ANCHOR_MAX_TTL_MS
    || !Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs > evidenceTtlMs) {
    throw new AuditExportIssuanceRepositoryError("ERR_CONFIG");
  }

  async function reserveAuditExport(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, identity.organization_id);
        await lockChain(tx, identity);

        const existing = await selectIssuance(tx, identity, true);
        const existingRow = existing === undefined ? undefined : normalizeStoredRow(existing);
        if (existingRow?.state === "committed") return committedOutcome(existingRow);
        if (existingRow?.state === "uncertain") return { state: "uncertain" };
        if (existingRow?.state === "reserved" && existingRow.claim_expires_at_ms > await databaseNowMs(tx)) return { state: "in_progress" };

        const open = await selectOpenChainIssuance(tx, identity);
        if (open !== undefined) return open.state === "uncertain" ? { state: "uncertain" } : { state: "in_progress" };

        if (existingRow?.state === "reserved") {
          await selectAndVerifyPayload(tx, identity, existingRow.payload_digest, false);
          const token = newClaimToken();
          const reissued = await tx.query(`UPDATE audit_export_issuances
            SET claim_token_digest=$6, claim_expires_at=clock_timestamp()+($7 * interval '1 millisecond')
            WHERE ${PK_WHERE} AND state='reserved' AND claim_expires_at<=clock_timestamp()
            RETURNING ${ROW_SELECT}`, [
            identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key,
            digestBytes(token), claimLeaseMs
          ]);
          if (rowCount(reissued) !== 1) throw repoError("ERR_IN_PROGRESS");
          const stored = normalizeStoredRow(reissued.rows[0]);
          return reservedOutcome(stored, token);
        }

        const previousBoundary = await selectPreviousBoundary(tx, identity);
        const descriptor = await readSnapshot(tx, identity, previousBoundary, snapshotReader);
        const authority = authorityFromSnapshot(identity, descriptor);
        const token = newClaimToken();
        const tokenDigest = digest(token);

        const inserted = await tx.query(`INSERT INTO audit_export_issuances
          (organization_id,export_id,environment,chain,idempotency_key,state,
           from_audit_position,to_audit_position,previous_root_digest,root_digest,record_count,
           payload_digest,request_digest,issued_at,expires_at,claim_expires_at,key_id,key_version,lifecycle_version,
           claim_token_digest,audit_anchor,uncertain_reason)
          VALUES ($1,$2,$3,$4,$5,'reserved',$6,$7,$8,$9,$10,$11,$12,
                  clock_timestamp(),clock_timestamp()+($13 * interval '1 millisecond'),
                  clock_timestamp()+($14 * interval '1 millisecond'),$15,$16,$17,$18,NULL,NULL)
          ON CONFLICT (organization_id,export_id,environment,chain,idempotency_key) DO NOTHING`, [
          identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key,
          authority.range.from_audit_position, authority.range.to_audit_position, hexBytes(authority.range.previous_root_digest),
          hexBytes(authority.range.root_digest), authority.range.record_count, hexBytes(authority.payload_digest), hexBytes(authority.request_digest),
          evidenceTtlMs, claimLeaseMs, authority.key_id, authority.key_version, authority.lifecycle_version, digestBytes(token)
        ]);
        if (rowCount(inserted) > 1) throw repoError("ERR_DATABASE");
        if (rowCount(inserted) === 1) {
          const payloadInserted = await tx.query(`INSERT INTO audit_export_payloads
            (organization_id,export_id,environment,chain,idempotency_key,payload_bytes,payload_json,payload_digest)
            VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, [
            identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key,
            authority.payload_bytes, authority.payload_json, hexBytes(authority.payload_digest)
          ]);
          if (rowCount(payloadInserted) !== 1) throw repoError("ERR_DATABASE");
        }

        const locked = await selectIssuance(tx, identity, true);
        if (locked === undefined) throw repoError("ERR_DATABASE");
        const row = normalizeStoredRow(locked);
        if (row.request_digest !== authority.request_digest) throw repoError("ERR_CONFLICT");
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") return { state: "uncertain" };
        if (row.state !== "reserved") throw repoError("ERR_DATABASE");
        await selectAndVerifyPayload(tx, identity, row.payload_digest, false);
        if (row.claim_token_digest !== tokenDigest) return { state: "in_progress" };
        return reservedOutcome(row, token);
      });
    } catch (error) {
      throw publicError(error);
    }
  }

  async function replayAuditExport(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, identity.organization_id);
        const result = await selectIssuance(tx, identity, true);
        if (result === undefined) return { state: "absent" };
        const row = normalizeStoredRow(result);
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") return { state: "uncertain" };
        if (row.claim_expires_at_ms > await databaseNowMs(tx)) return { state: "in_progress" };
        return { state: "absent" };
      });
    } catch (error) {
      throw publicError(error);
    }
  }

  async function commitAuditExport(input = {}) {
    const values = normalizeAuthorityInput(input, COMMIT_KEYS);
    let anchor;
    try { anchor = normalizeCanonicalAnchor(input.audit_anchor); }
    catch { throw repoError("ERR_BINDING"); }
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, values.organization_id);
        const result = await selectIssuance(tx, values, true);
        if (result === undefined) throw repoError("ERR_NOT_FOUND");
        const row = normalizeStoredRow(result);
        assertAuthorityMatches(values, row);
        if (row.state === "committed") {
          if (row.audit_anchor === null || canonicalJson(row.audit_anchor) !== canonicalJson(anchor)) throw repoError("ERR_CONFLICT");
          assertAnchorBinding(anchor, row);
          return committedOutcome({ ...row, audit_anchor: anchor });
        }
        if (row.state === "uncertain") throw repoError("ERR_UNCERTAIN");
        if (row.state !== "reserved") throw repoError("ERR_DATABASE");
        await assertClaimAndLease(tx, row, values.claim_token);
        assertAnchorBinding(anchor, row);
        const updated = await tx.query(`UPDATE audit_export_issuances
          SET state='committed',audit_anchor=$6::jsonb,claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason=NULL
          WHERE ${PK_WHERE} AND state='reserved' AND claim_token_digest=$7
            AND claim_expires_at>clock_timestamp()
          RETURNING ${ROW_SELECT}`, [
          values.organization_id, values.export_id, values.environment, values.chain, values.idempotency_key,
          JSON.stringify(anchor), digestBytes(values.claim_token)
        ]);
        // The claim digest is deliberately a separate parameter in the SQL above;
        // keep the update bind count explicit for drivers which reject extras.
        if (rowCount(updated) !== 1) throw repoError("ERR_CLAIM");
        const stored = normalizeStoredRow(updated.rows[0]);
        assertAnchorBinding(stored.audit_anchor, stored);
        return committedOutcome(stored);
      });
    } catch (error) {
      throw publicError(error, "ERR_COMMIT");
    }
  }

  async function markAuditExportUncertain(input = {}) {
    const values = normalizeAuthorityInput(input, UNCERTAIN_KEYS);
    if (!UNCERTAINTY_REASONS.has(values.reason)) throw repoError("ERR_INPUT");
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, values.organization_id);
        const result = await selectIssuance(tx, values, true);
        if (result === undefined) throw repoError("ERR_NOT_FOUND");
        const row = normalizeStoredRow(result);
        assertAuthorityMatches(values, row);
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") return { state: "uncertain" };
        if (row.state !== "reserved") throw repoError("ERR_DATABASE");
        await assertClaimAndLease(tx, row, values.claim_token);
        const updated = await tx.query(`UPDATE audit_export_issuances
          SET state='uncertain',claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason=$6
          WHERE ${PK_WHERE} AND state='reserved' AND claim_token_digest=$7
            AND claim_expires_at>clock_timestamp()
          RETURNING ${ROW_SELECT}`, [
          values.organization_id, values.export_id, values.environment, values.chain, values.idempotency_key,
          values.reason, digestBytes(values.claim_token)
        ]);
        if (rowCount(updated) !== 1) throw repoError("ERR_CLAIM");
        return { state: "uncertain" };
      });
    } catch (error) {
      throw publicError(error);
    }
  }

  async function getAuditExportPayload(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, identity.organization_id);
        return selectAndVerifyPayload(tx, identity, undefined, true);
      });
    } catch (error) {
      throw publicError(error);
    }
  }

  async function getCommittedAuditExport(input = {}) {
    const retrieval = normalizeRetrieval(input);
    try {
      return await withTransaction(client, async (tx) => {
        await establishTenantContext(tx, retrieval.organization_id);
        const result = await tx.query(`SELECT ${ROW_SELECT}
          FROM audit_export_issuances
          WHERE organization_id=$1 AND export_id=$2 AND environment=$3 AND chain=$4 AND state='committed'`, [
          retrieval.organization_id, retrieval.export_id, retrieval.environment, retrieval.chain
        ]);
        if (rowCount(result) === 0) throw repoError("ERR_NOT_FOUND");
        if (rowCount(result) !== 1) throw repoError("ERR_DATABASE");
        const row = normalizeStoredRow(result.rows[0]);
        if (row.state !== "committed") throw repoError("ERR_NOT_FOUND");
        const payload = await selectAndVerifyPayload(tx, row, row.payload_digest, true);
        return deepFreeze({ ...committedOutcome(row), payload });
      });
    } catch (error) {
      throw publicError(error);
    }
  }

  return Object.freeze({ reserveAuditExport, commitAuditExport, replayAuditExport, markAuditExportUncertain, getAuditExportPayload, getCommittedAuditExport });
}

export const createAuditExportIssuanceRepository = createPostgresAuditExportIssuanceRepository;
export default createPostgresAuditExportIssuanceRepository;

async function establishTenantContext(tx, organizationId) {
  const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) throw repoError("ERR_DATABASE");
  const verified = await tx.query("SELECT current_setting('agentpass.organization_id',true) AS organization_id", []);
  if (rowCount(verified) !== 1 || verified.rows[0]?.organization_id !== organizationId) throw repoError("ERR_DATABASE");
}

async function lockChain(tx, identity) {
  const key = `agentpass:audit-export:${identity.organization_id}:${identity.environment}:${identity.chain}`;
  const result = await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [key]);
  if (rowCount(result) !== 1) throw repoError("ERR_DATABASE");
}

async function selectIssuance(tx, identity, forUpdate) {
  const result = await tx.query(`SELECT ${ROW_SELECT}
    FROM audit_export_issuances
    WHERE ${PK_WHERE}${forUpdate ? " FOR UPDATE" : ""}`, [
    identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key
  ]);
  if (rowCount(result) > 1) throw repoError("ERR_DATABASE");
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectOpenChainIssuance(tx, identity) {
  const result = await tx.query(`SELECT ${ROW_SELECT}
    FROM audit_export_issuances
    WHERE organization_id=$1 AND environment=$2 AND chain=$3
      AND state IN ('reserved','uncertain')
      AND NOT (export_id=$4 AND idempotency_key=$5)
    ORDER BY CASE WHEN state='uncertain' THEN 0 ELSE 1 END,issued_at ASC
    LIMIT 1 FOR UPDATE`, [identity.organization_id, identity.environment, identity.chain, identity.export_id, identity.idempotency_key]);
  if (rowCount(result) > 1) throw repoError("ERR_DATABASE");
  return rowCount(result) === 1 ? normalizeStoredRow(result.rows[0]) : undefined;
}

async function selectPreviousBoundary(tx, identity) {
  const result = await tx.query(`SELECT from_audit_position,to_audit_position,
      encode(previous_root_digest,'hex') AS previous_root_digest,
      encode(root_digest,'hex') AS root_digest,record_count
    FROM audit_export_issuances
    WHERE organization_id=$1 AND environment=$2 AND chain=$3 AND state='committed'
    ORDER BY to_audit_position DESC
    LIMIT 1 FOR SHARE`, [identity.organization_id, identity.environment, identity.chain]);
  if (rowCount(result) > 1) throw repoError("ERR_DATABASE");
  if (rowCount(result) === 0) return Object.freeze({ to_audit_position: 0, root_digest: AUDIT_ANCHOR_ZERO_DIGEST });
  const row = result.rows[0];
  const from = positiveInteger(row.from_audit_position);
  const to = positiveInteger(row.to_audit_position);
  const previousRoot = requiredDigest(row.previous_root_digest, true);
  const root = requiredDigest(row.root_digest, false);
  if (from > to || (to === 0 && from !== 0)) throw repoError("ERR_DATABASE");
  if ((from === 1 && previousRoot !== AUDIT_ANCHOR_ZERO_DIGEST)
    || (from > 1 && previousRoot === AUDIT_ANCHOR_ZERO_DIGEST)) throw repoError("ERR_DATABASE");
  return Object.freeze({ from_audit_position: from, to_audit_position: to, root_digest: root });
}

async function readSnapshot(tx, identity, previousBoundary, snapshotReader) {
  let value;
  try {
    value = await snapshotReader(tx, Object.freeze({ ...identity }), previousBoundary);
  } catch {
    throw repoError("ERR_SNAPSHOT");
  }
  return normalizeDescriptor(value, previousBoundary);
}

function authorityFromSnapshot(identity, descriptor) {
  const payloadJson = canonicalJson(descriptor.payload);
  const payloadDigest = digest(payloadJson);
  if (payloadDigest === AUDIT_ANCHOR_ZERO_DIGEST) throw repoError("ERR_SNAPSHOT");
  const range = descriptor.range;
  const requestDigest = digest(canonicalJson({
    version: 1,
    organization_id: identity.organization_id,
    export_id: identity.export_id,
    environment: identity.environment,
    chain: identity.chain,
    idempotency_key: identity.idempotency_key,
    range,
    payload_digest: payloadDigest
  }));
  return Object.freeze({ ...identity, range, payload_digest: payloadDigest, request_digest: requestDigest,
    payload_bytes: Buffer.from(payloadJson, "utf8"), payload_json: payloadJson,
    key_id: descriptor.key_id, key_version: descriptor.key_version, lifecycle_version: descriptor.lifecycle_version });
}

async function selectAndVerifyPayload(tx, identity, expectedDigest, committedOnly) {
  const source = committedOnly ? "audit_export_committed_payloads" : "audit_export_payloads";
  const result = await tx.query(`SELECT ${PAYLOAD_SELECT}
    FROM ${source}
    WHERE ${PK_WHERE}`, [
    identity.organization_id, identity.export_id, identity.environment, identity.chain, identity.idempotency_key
  ]);
  if (rowCount(result) === 0) throw repoError(committedOnly ? "ERR_NOT_FOUND" : "ERR_DATABASE");
  if (rowCount(result) !== 1) throw repoError("ERR_DATABASE");
  return normalizeStoredPayload(result.rows[0], expectedDigest);
}

function normalizeStoredPayload(row, expectedDigest) {
  try {
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("payload row");
    const bytes = row.payload_bytes;
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new Error("payload bytes");
    const payloadBytes = Buffer.from(bytes);
    if (payloadBytes.length < 1 || payloadBytes.length > MAX_DESCRIPTOR_BYTES) throw new Error("payload size");
    const storedDigest = requiredDigest(row.payload_digest, false);
    if (expectedDigest !== undefined && storedDigest !== expectedDigest) throw new Error("payload authority");
    const payload = row.payload_json;
    assertPlainDataTree(payload);
    const canonical = canonicalJson(payload);
    if (!payloadBytes.equals(Buffer.from(canonical, "utf8")) || digest(canonical) !== storedDigest) throw new Error("payload binding");
    return deepFreeze(structuredClone(payload));
  } catch (error) {
    if (error instanceof AuditExportIssuanceRepositoryError) throw error;
    throw repoError("ERR_DATABASE");
  }
}

function normalizeDescriptor(value, previousBoundary) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, DESCRIPTOR_KEYS);
    const range = normalizeRange(value.range);
    const previousTo = previousBoundary.to_audit_position;
    const previousRoot = previousBoundary.root_digest;
    if (range.from_audit_position !== previousTo + 1 || range.previous_root_digest !== previousRoot) throw new Error("boundary");
    if (!Number.isSafeInteger(value.key_version) || value.key_version < 1
      || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1
      || typeof value.key_id !== "string" || !IDENTIFIER.test(value.key_id)) throw new Error("key");
    const serializedPayload = canonicalJson(value.payload);
    if (Buffer.byteLength(serializedPayload, "utf8") > MAX_DESCRIPTOR_BYTES) throw new Error("payload");
    return deepFreeze({ range, payload: structuredClone(value.payload), key_id: value.key_id,
      key_version: value.key_version, lifecycle_version: value.lifecycle_version });
  } catch {
    throw repoError("ERR_SNAPSHOT");
  }
}

function normalizeIdentity(value) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, IDENTITY_KEYS);
    return deepFreeze({
      organization_id: uuid(value.organization_id), export_id: uuid(value.export_id),
      environment: enumeration(value.environment, ENVIRONMENTS), chain: enumeration(value.chain, CHAINS),
      idempotency_key: idempotency(value.idempotency_key)
    });
  } catch (error) {
    if (error instanceof AuditExportIssuanceRepositoryError) throw error;
    throw repoError("ERR_INPUT");
  }
}

function normalizeRetrieval(value) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, RETRIEVAL_KEYS);
    return deepFreeze({
      organization_id: uuid(value.organization_id), export_id: uuid(value.export_id),
      environment: enumeration(value.environment, ENVIRONMENTS), chain: enumeration(value.chain, CHAINS)
    });
  } catch (error) {
    if (error instanceof AuditExportIssuanceRepositoryError) throw error;
    throw repoError("ERR_INPUT");
  }
}

function normalizeAuthorityInput(value, keys) {
  try {
    assertPlainDataTree(value, new Set(), 0, true);
    assertExactKeys(value, keys);
    const identity = normalizeIdentity(Object.fromEntries(IDENTITY_KEYS.map((key) => [key, value[key]])));
    const range = normalizeRange(value.range);
    const payloadDigest = requiredDigest(value.payload_digest, false);
    const requestDigest = requiredDigest(value.request_digest, false);
    const issuedAt = timestamp(value.issued_at);
    const expiresAt = timestamp(value.expires_at);
    const keyId = identifier(value.key_id);
    const keyVersion = positiveInteger(value.key_version);
    const lifecycleVersion = positiveInteger(value.lifecycle_version);
    if (Date.parse(expiresAt) <= Date.parse(issuedAt) || Date.parse(expiresAt) - Date.parse(issuedAt) > AUDIT_ANCHOR_MAX_TTL_MS) throw new Error("ttl");
    const expected = digest(canonicalJson({ version: 1, ...identity, range, payload_digest: payloadDigest }));
    if (expected !== requestDigest) throw repoError("ERR_BINDING");
    return Object.freeze({ ...identity, range, payload_digest: payloadDigest, request_digest: requestDigest,
      issued_at: issuedAt, expires_at: expiresAt, key_id: keyId, key_version: keyVersion,
      lifecycle_version: lifecycleVersion, ...(Object.hasOwn(value, "claim_token") ? { claim_token: claim(value.claim_token) } : {}),
      ...(Object.hasOwn(value, "reason") ? { reason: value.reason } : {}) });
  } catch (error) {
    if (error instanceof AuditExportIssuanceRepositoryError) throw error;
    throw repoError("ERR_INPUT");
  }
}

function normalizeStoredRow(row) {
  try {
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("row");
    const identity = {
      organization_id: uuid(row.organization_id), export_id: uuid(row.export_id),
      environment: enumeration(row.environment, ENVIRONMENTS), chain: enumeration(row.chain, CHAINS),
      idempotency_key: idempotency(row.idempotency_key)
    };
    const range = normalizeRange({
      from_audit_position: row.from_audit_position, to_audit_position: row.to_audit_position,
      previous_root_digest: requiredDigest(row.previous_root_digest, true),
      root_digest: requiredDigest(row.root_digest, false), record_count: row.record_count
    });
    const payloadDigest = requiredDigest(row.payload_digest, false);
    const requestDigest = requiredDigest(row.request_digest, false);
    const issuedAt = timestamp(row.issued_at);
    const expiresAt = timestamp(row.expires_at);
    const keyId = identifier(row.key_id);
    const keyVersion = positiveInteger(row.key_version);
    const lifecycleVersion = positiveInteger(row.lifecycle_version);
    const state = enumeration(row.state, STATES);
    let claimDigest = null;
    let claimExpiresAt = null;
    if (state === "reserved") {
      claimDigest = requiredDigest(row.claim_token_digest, false);
      claimExpiresAt = timestamp(row.claim_expires_at);
      if (Date.parse(claimExpiresAt) <= Date.parse(issuedAt)) throw new Error("claim lease");
    } else if ((row.claim_token_digest !== null && row.claim_token_digest !== undefined)
      || (row.claim_expires_at !== null && row.claim_expires_at !== undefined)) {
      throw new Error("released claim");
    }
    const expected = digest(canonicalJson({ version: 1, ...identity, range, payload_digest: payloadDigest }));
    if (expected !== requestDigest || Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(issuedAt) > AUDIT_ANCHOR_MAX_TTL_MS) throw new Error("row binding");
    let anchor = null;
    if (state === "committed") anchor = normalizeCanonicalAnchor(row.audit_anchor);
    else if (row.audit_anchor !== null && row.audit_anchor !== undefined) throw new Error("state anchor");
    if (state === "uncertain" && !UNCERTAINTY_REASONS.has(row.uncertain_reason)) throw new Error("reason");
    if (state !== "uncertain" && row.uncertain_reason !== null && row.uncertain_reason !== undefined) throw new Error("reason");
    return Object.freeze({ ...identity, range, payload_digest: payloadDigest, request_digest: requestDigest,
      issued_at: issuedAt, expires_at: expiresAt, key_id: keyId, key_version: keyVersion,
      lifecycle_version: lifecycleVersion, claim_token_digest: claimDigest, claim_expires_at: claimExpiresAt,
      state, audit_anchor: anchor, uncertain_reason: row.uncertain_reason ?? null,
      issued_at_ms: Date.parse(issuedAt), expires_at_ms: Date.parse(expiresAt),
      claim_expires_at_ms: claimExpiresAt === null ? null : Date.parse(claimExpiresAt) });
  } catch (error) {
    if (error instanceof AuditExportIssuanceRepositoryError) throw error;
    throw repoError("ERR_DATABASE");
  }
}

function assertAuthorityMatches(input, row) {
  for (const key of AUTHORITY_KEYS) {
    if (key === "range") {
      if (canonicalJson(input.range) !== canonicalJson(row.range)) throw repoError("ERR_BINDING");
    } else if (input[key] !== row[key]) throw repoError("ERR_BINDING");
  }
}

async function assertClaimAndLease(tx, row, claimToken) {
  if (!CLAIM_TOKEN.test(claimToken) || digest(claimToken) !== row.claim_token_digest) throw repoError("ERR_CLAIM");
  if (row.claim_expires_at_ms <= await databaseNowMs(tx)) throw repoError("ERR_CLAIM");
}

async function databaseNowMs(tx) {
  const result = await tx.query("SELECT clock_timestamp() AS now", []);
  if (rowCount(result) !== 1) throw repoError("ERR_DATABASE");
  const value = result.rows[0]?.now instanceof Date ? result.rows[0].now : new Date(result.rows[0]?.now);
  if (!Number.isFinite(value.getTime())) throw repoError("ERR_DATABASE");
  return value.getTime();
}

function assertAnchorBinding(anchor, row) {
  const statement = anchor?.statement;
  if (!statement || statement.organization_id !== row.organization_id || statement.export_id !== row.export_id
    || statement.environment !== row.environment || statement.chain !== row.chain
    || statement.previous_audit_position !== row.range.from_audit_position - 1
    || statement.audit_position !== row.range.to_audit_position
    || statement.previous_root_digest !== row.range.previous_root_digest
    || statement.root_digest !== row.range.root_digest
    || statement.record_count !== row.range.record_count || statement.export_digest !== row.payload_digest
    || statement.issued_at !== row.issued_at || statement.expires_at !== row.expires_at
    || statement.key_id !== row.key_id || statement.key_version !== row.key_version
    || statement.lifecycle_version !== row.lifecycle_version) throw repoError("ERR_BINDING");
}

function normalizeCanonicalAnchor(value) {
  assertPlainDataTree(value);
  const normalized = normalizeAuditAnchor(value, { allowExpired: true, allowFuture: true, maxTtlMs: AUDIT_ANCHOR_MAX_TTL_MS });
  if (canonicalJson(normalized) !== canonicalJson(value)) throw new Error("noncanonical");
  return deepFreeze(normalized);
}

function reservedOutcome(row, claimToken) {
  return deepFreeze({ state: "reserved", ...authorityDto(row), claim_token: claimToken });
}

function committedOutcome(row) {
  if (!row.audit_anchor) throw repoError("ERR_DATABASE");
  return deepFreeze({ state: "committed", ...authorityDto(row), audit_anchor: row.audit_anchor });
}

function authorityDto(row) {
  return {
    organization_id: row.organization_id, export_id: row.export_id, environment: row.environment,
    chain: row.chain, idempotency_key: row.idempotency_key, range: row.range,
    payload_digest: row.payload_digest, request_digest: row.request_digest, issued_at: row.issued_at,
    expires_at: row.expires_at, key_id: row.key_id, key_version: row.key_version,
    lifecycle_version: row.lifecycle_version
  };
}

function newClaimToken() { return crypto.randomBytes(32).toString("base64url"); }
function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function digestBytes(value) { return Buffer.from(digest(value), "hex"); }
function hexBytes(value) { return Buffer.from(value, "hex"); }
function claim(value) { if (typeof value !== "string" || !CLAIM_TOKEN.test(value)) throw new Error("claim"); return value; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new Error("uuid"); return value.toLowerCase(); }
function identifier(value) { if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new Error("identifier"); return value; }
function idempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new Error("idempotency"); return value; }
function enumeration(value, allowed) { if (typeof value !== "string" || !allowed.has(value)) throw new Error("enum"); return value; }
function requiredDigest(value, allowZero) {
  const normalized = Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value).toString("hex") : value;
  if (typeof normalized !== "string" || !DIGEST.test(normalized) || (!allowZero && normalized === AUDIT_ANCHOR_ZERO_DIGEST)) throw new Error("digest");
  return normalized;
}
function positiveInteger(value) { const result = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 1) throw new Error("integer"); return result; }
function timestamp(value) { const date = value instanceof Date ? value : new Date(value); const output = date.toISOString(); if (!TIMESTAMP.test(output)) throw new Error("timestamp"); return output; }

function normalizeRange(value) {
  assertPlainDataTree(value);
  assertExactKeys(value, RANGE_KEYS);
  const from = positiveInteger(value.from_audit_position);
  const to = positiveInteger(value.to_audit_position);
  const previous = requiredDigest(value.previous_root_digest, true);
  const root = requiredDigest(value.root_digest, false);
  const count = positiveInteger(value.record_count);
  if (to < from || count !== to - from + 1 || (from === 1 && previous !== AUDIT_ANCHOR_ZERO_DIGEST)
    || (from > 1 && previous === AUDIT_ANCHOR_ZERO_DIGEST)) throw new Error("range");
  return Object.freeze({ from_audit_position: from, to_audit_position: to, previous_root_digest: previous, root_digest: root, record_count: count });
}

function assertPlainDataTree(value, seen = new Set(), depth = 0, allowClaimTokenKey = false) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && (Buffer.byteLength(value, "utf8") > MAX_TREE_STRING_BYTES || PRIVATE_VALUE.test(value))) throw new Error("sensitive tree");
    return;
  }
  if (depth > MAX_TREE_DEPTH || seen.has(value) || (!isObject(value) && !Array.isArray(value))) throw new Error("data tree");
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_TREE_ITEMS || Reflect.ownKeys(value).length !== value.length + 1) throw new Error("tree size");
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("tree descriptor");
      assertPlainDataTree(descriptor.value, seen, depth + 1, false);
    }
    seen.delete(value);
    return;
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_TREE_ITEMS) throw new Error("tree size");
  for (const key of keys) {
    if (typeof key !== "string" || key === "__proto__" || key === "constructor" || key === "prototype"
      || (PRIVATE_MATERIAL.test(key) && !(allowClaimTokenKey && depth === 0 && key === "claim_token"))) throw new Error("tree key");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("tree descriptor");
    assertPlainDataTree(descriptor.value, seen, depth + 1, false);
  }
  seen.delete(value);
}

function assertExactKeys(value, keys) {
  if (!isObject(value)) throw new Error("object");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new Error("keys");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("descriptor");
  }
}

function isObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return value;
}

function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new AuditExportIssuanceRepositoryError("ERR_CONFIG"); }
function repoError(code) { return new AuditExportIssuanceRepositoryError(code); }
function publicError(error, fallback = "ERR_DATABASE") {
  if (error instanceof AuditExportIssuanceRepositoryError) return error;
  return repoError(fallback === "ERR_COMMIT" ? "ERR_DATABASE" : fallback);
}
