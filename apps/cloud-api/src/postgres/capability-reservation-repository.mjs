import crypto from "node:crypto";

import { canonicalJson, normalizeScope } from "../../../../packages/protocol/src/index.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const MAX_TTL_MS = 15 * 60 * 1000;

export class CapabilityReservationRepositoryError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "CapabilityReservationRepositoryError";
    this.code = code;
  }
}

/**
 * Reserves a complete capability statement without storing its bearer nonce.
 * A purpose-separated shared HMAC secret deterministically derives both an
 * omitted capability id and its nonce from tenant/principal/idempotency
 * identity. PostgreSQL stores only nonce_digest and statement_hash, allowing
 * retries on another instance to reproduce the same statement safely.
 */
export function createPostgresCapabilityReservationRepository({ client, nonceSecret, now = () => new Date().toISOString() } = {}) {
  assertClient(client);
  const secret = normalizeSecret(nonceSecret);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const controls = createSharedControlRepository({ client });

  async function reserveCapability(input = {}) {
    const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
    const principalId = uuid(input.principalId ?? input.principal_id ?? input.createdBy ?? input.created_by, "principal_id");
    const issuedByMemberId = uuid(input.createdBy ?? input.created_by ?? input.actorId ?? input.actor_id ?? principalId, "issued_by_member_id");
    const idempotencyKey = idempotency(input.idempotencyKey ?? input.idempotency_key);
    const requestedCapabilityId = optionalUuid(input.capabilityId ?? input.capability_id, "capability_id");
    const capabilityId = requestedCapabilityId ?? derivedUuid(secret, canonicalJson({ version: 1, organization_id: organizationId, principal_id: principalId, idempotency_key: idempotencyKey }));
    const issuer = identifier(input.issuer, "issuer");
    const keyId = identifier(input.keyId ?? input.key_id, "key_id");
    const agentId = uuid(input.agentId ?? input.agent_id, "agent_id");
    const deviceId = uuid(input.deviceId ?? input.device_id, "device_id");
    const scope = normalizedScope(input.scope);
    const sequence = positiveInteger(input.sequence, "sequence");
    const ttlMs = boundedTtl(input.ttlMs ?? input.ttl_ms);
    const requestIdentity = { version: 1, organization_id: organizationId, capability_id: capabilityId, issuer, key_id: keyId, agent_id: agentId, device_id: deviceId, scope, sequence, ttl_ms: ttlMs, issued_by_member_id: issuedByMemberId };
    const requestHash = digestHex(canonicalJson(requestIdentity));
    const nonce = derivedNonce(secret, canonicalJson({ version: 1, organization_id: organizationId, capability_id: capabilityId, request_hash: requestHash }));

    try {
      const outcome = await controls.runIdempotent({
        organizationId,
        principalId,
        idempotencyKey,
        requestHash,
        operation: async (tx) => {
          await installTenantContext(tx, organizationId);
          const notBefore = timestamp(input.issuedAt ?? input.issued_at ?? now(), "issued_at");
          const expiresAt = new Date(Date.parse(notBefore) + ttlMs).toISOString();
          const statement = capabilityStatement({ capabilityId, nonce, issuer, keyId, agentId, deviceId, scope, notBefore, expiresAt, sequence });
          const statementHash = digestHex(canonicalJson(statement));
          const issued = await tx.query(`SELECT public.agentpass_capability_reservation_issue(
            $1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9,$10,$11::jsonb,$12::timestamptz,$13::bytea
          ) AS result`, [
            organizationId, capabilityId, agentId, deviceId, sequence, statementHash, expiresAt,
            issuedByMemberId, issuer, keyId, JSON.stringify(scope), notBefore, digestBuffer(nonce)
          ]);
          const record = functionResult(issued);
          if (record.state === "member_not_active") throw new CapabilityReservationRepositoryError("ERR_MEMBER_NOT_ACTIVE", "capability issuer is not an active organization administrator");
          if (record.state === "audience_absent") throw new CapabilityReservationRepositoryError("ERR_AUDIENCE", "capability audience is unavailable");
          if (record.state === "conflict") throw new CapabilityReservationRepositoryError("ERR_CAPABILITY_CONFLICT", "capability identity already exists");
          if (record.state !== "issued" || !record.capability) throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability authority returned an invalid result");
          return { responseStatus: 201, response: publicReservation(record.capability) };
        }
      });
      if (outcome.state === "conflict") throw new CapabilityReservationRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key conflicts with another capability request");
      if (outcome.state === "in_progress") throw new CapabilityReservationRepositoryError("ERR_IDEMPOTENCY_IN_PROGRESS", "capability reservation is already in progress");
      return Object.freeze({ ...outcome.response, nonce });
    } catch (error) {
      if (error instanceof CapabilityReservationRepositoryError) throw error;
      throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability reservation storage is unavailable", error);
    }
  }

  async function listCapabilities(input = {}) {
    const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
    try {
      return await transaction(client, async (tx) => {
        await installTenantContext(tx, organizationId);
        const result = await tx.query("SELECT public.agentpass_capability_reservation_list($1,$2) AS result", [organizationId, 1001]);
        const record = functionResult(result);
        if (record.state !== "listed" || !Array.isArray(record.capabilities)) throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability authority returned an invalid result");
        if (record.capabilities.length > 1000) throw new CapabilityReservationRepositoryError("ERR_LIMIT", "capability result exceeds the supported limit");
        return Object.freeze(record.capabilities.map(publicReservation));
      });
    } catch (error) {
      if (error instanceof CapabilityReservationRepositoryError) throw error;
      throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability reservation storage is unavailable", error);
    }
  }

  return Object.freeze({ reserveCapability, listCapabilities });
}

function capabilityStatement({ capabilityId, nonce, issuer, keyId, agentId, deviceId, scope, notBefore, expiresAt, sequence }) {
  return Object.freeze({ version: 1, capability_id: capabilityId, nonce, issuer, key_id: keyId, audience: { agent_id: agentId, device_id: deviceId }, scope, not_before: notBefore, expires_at: expiresAt, sequence });
}

function publicReservation(row) {
  const scope = normalizedScope(row.scope_json ?? row.scope);
  const revokedAt = row.revoked_at === null || row.revoked_at === undefined ? null : timestamp(row.revoked_at, "revoked_at");
  return Object.freeze({
    capability_id: uuid(row.capability_id ?? row.id, "capability_id"),
    organization_id: uuid(row.organization_id, "organization_id"),
    issuer: identifier(row.issuer, "issuer"),
    key_id: identifier(row.key_id, "key_id"),
    agent_id: uuid(row.agent_id, "agent_id"),
    device_id: uuid(row.device_id, "device_id"),
    operations: Object.freeze([...scope.operations]),
    scope,
    not_before: timestamp(row.not_before, "not_before"),
    expires_at: timestamp(row.expires_at, "expires_at"),
    sequence: positiveInteger(row.sequence, "sequence"),
    capability_hash: digest(row.statement_hash, "statement_hash"),
    issued_at: timestamp(row.not_before, "issued_at"),
    status: revokedAt === null ? "active" : "revoked",
    version: positiveInteger(row.version, "version"),
    issued_by_member_id: uuid(row.issued_by_member_id, "issued_by_member_id"),
    issued_membership_version: positiveInteger(row.issued_membership_version, "issued_membership_version"),
    ...(revokedAt === null ? {} : { revoked_at: revokedAt })
  });
}

function derivedUuid(secret, identity) { const bytes = crypto.createHmac("sha256", secret).update("AgentPass-Capability-Id-v1\0").update(identity).digest().subarray(0, 16); bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80; const hex = bytes.toString("hex"); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; }
function derivedNonce(secret, identity) { const encoded = crypto.createHmac("sha256", secret).update("AgentPass-Capability-Nonce-v1\0").update(identity).digest("base64url"); return /^[A-Za-z0-9]/u.test(encoded) ? encoded : `A${encoded.slice(1)}`; }
function digestBuffer(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function digestHex(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function normalizeSecret(value) { let bytes = value; if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value)) bytes = Buffer.from(value, "base64url"); if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw new TypeError("capability nonce secret must contain exactly 32 bytes"); return Buffer.from(bytes); }
function normalizedScope(value) { try { return normalizeScope(value); } catch (error) { throw new CapabilityReservationRepositoryError("ERR_SCOPE", "capability scope is invalid", error); } }
function boundedTtl(value) { if (!Number.isSafeInteger(value) || value < 1000 || value > MAX_TTL_MS) throw new CapabilityReservationRepositoryError("ERR_TTL", "capability ttl is invalid"); return value; }
function idempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new CapabilityReservationRepositoryError("ERR_IDEMPOTENCY", "capability idempotency key is invalid"); return value; }
function identifier(value, field) { if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new CapabilityReservationRepositoryError("ERR_INPUT", `${field} is invalid`); return value; }
function uuid(value, field) { const result = optionalUuid(value, field); if (result === undefined) throw new CapabilityReservationRepositoryError("ERR_INPUT", `${field} is invalid`); return result; }
function optionalUuid(value, field) { if (value === undefined || value === null) return undefined; if (typeof value !== "string" || !UUID.test(value)) throw new CapabilityReservationRepositoryError("ERR_INPUT", `${field} is invalid`); return value.toLowerCase(); }
function positiveInteger(value, field) { const result = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 1) throw new CapabilityReservationRepositoryError("ERR_INPUT", `${field} is invalid`); return result; }
function digest(value, field) { if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new CapabilityReservationRepositoryError("ERR_DATABASE", `${field} is invalid`); return value; }
function timestamp(value, field) { const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw new CapabilityReservationRepositoryError("ERR_INPUT", `${field} is invalid`); return date.toISOString(); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function functionResult(result) { const value = rowCount(result) === 1 ? result.rows?.[0]?.result : undefined; if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.state !== "string") throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability authority returned an invalid result"); return value; }
async function installTenantContext(tx, organizationId) { const result = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]); if (rowCount(result) !== 1 || result.rows?.[0]?.organization_id !== organizationId) throw new CapabilityReservationRepositoryError("ERR_DATABASE", "capability tenant context is unavailable"); }
async function transaction(client, operation) { const tx = typeof client.connect === "function" ? await client.connect() : client; try { return await withTransaction(tx, operation); } finally { if (tx !== client) tx.release?.(); } }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }

export default createPostgresCapabilityReservationRepository;
