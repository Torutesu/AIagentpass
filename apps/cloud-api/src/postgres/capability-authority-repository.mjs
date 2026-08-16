import { assertTenantId, PostgresRepositoryError, withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_CONTROL_BUNDLE_REVOCATIONS = 256;

export class CapabilityAuthorityRepositoryError extends PostgresRepositoryError {
  constructor(code, message, details = undefined, cause = undefined) {
    super(code, message, details, cause);
    this.name = "CapabilityAuthorityRepositoryError";
  }
}

/**
 * PostgreSQL boundary for capability membership authority.
 *
 * The issue and revoke operations use the same organization/member advisory
 * lock.  A membership role update can therefore serialize its capability
 * cleanup with a concurrent issue once it calls revokeActiveCapabilitiesForMember.
 * The repository never accepts a caller-supplied membership version as the
 * source of truth: it records the locked active membership's current version.
 */
export function createCapabilityAuthorityRepository({ client, now = () => new Date().toISOString(), onAuthorityReduction } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new CapabilityAuthorityRepositoryError("ERR_CLOCK", "now must be a function");
  if (onAuthorityReduction !== undefined && typeof onAuthorityReduction !== "function") throw new CapabilityAuthorityRepositoryError("ERR_AUTHORITY_REDUCTION_HOOK", "onAuthorityReduction must be a function");

  async function issueCapabilityMetadata(input = {}) {
    const values = normalizeIssueInput(input, now);
    return operation(async () => transaction(async (tx) => {
      await installTenantContext(tx, values.organizationId);
      const result = await tx.query(`SELECT public.agentpass_capability_authority_issue(
        $1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9
      ) AS result`, [
        values.organizationId,
        values.capabilityId,
        values.agentId,
        values.deviceId,
        values.sequence,
        values.statementHash,
        values.expiresAt,
        values.issuedByMemberId,
        values.expectedMembershipVersion ?? null
      ]);
      const record = functionResult(result);
      if (record.state === "member_not_active") throw new CapabilityAuthorityRepositoryError("ERR_MEMBER_NOT_ACTIVE", "capability issuer is not an active organization administrator");
      if (record.state === "membership_version_conflict") throw new CapabilityAuthorityRepositoryError("ERR_MEMBERSHIP_VERSION", "capability issuer membership version is stale");
      if (record.state === "conflict") throw new CapabilityAuthorityRepositoryError("ERR_CAPABILITY_CONFLICT", "capability identity conflicts with another request");
      if (!["issued", "replayed"].includes(record.state) || !record.capability) throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability authority returned an invalid issue result");
      return Object.freeze({ ...publicCapabilityRow(record.capability), ...(record.state === "replayed" ? { replayed: true } : {}) });
    }));
  }

  async function revokeActiveCapabilitiesForMember(input = {}) {
    const values = normalizeRevokeInput(input, now);
    return operation(async () => transaction(async (tx) => {
      await installTenantContext(tx, values.organizationId);
      const result = await tx.query(`SELECT public.agentpass_capability_authority_revoke_member(
        $1,$2,$3::timestamptz
      ) AS result`, [
        values.organizationId,
        values.memberId,
        values.revokedAt
      ]);
      const record = functionResult(result);
      if (record.state !== "revoked" || !Array.isArray(record.capabilities)) throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability authority returned an invalid revoke result");
      const capabilities = record.capabilities.map(publicCapabilityRow);
      if (capabilities.length > 0) {
        if (!onAuthorityReduction) {
          throw new CapabilityAuthorityRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable");
        }
        let authority;
        try {
          authority = await onAuthorityReduction(Object.freeze({
            tx,
            organization_id: values.organizationId,
            member_id: values.memberId,
            actor_member_id: values.actorMemberId,
            occurred_at: values.revokedAt,
            capabilities: Object.freeze(capabilities)
          }));
        } catch (error) {
          if (error instanceof CapabilityAuthorityRepositoryError) throw error;
          throw new CapabilityAuthorityRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable", undefined, error);
        }
        if (!authority || typeof authority !== "object" || !Number.isSafeInteger(authority.generation) || authority.generation < 1) {
          throw new CapabilityAuthorityRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable");
        }
      }
      return Object.freeze({
        organization_id: values.organizationId,
        member_id: values.memberId,
        revoked_at: values.revokedAt,
        revoked_count: capabilities.length,
        capability_ids: Object.freeze(capabilities.map(({ capability_id }) => capability_id)),
        capabilities: Object.freeze(capabilities)
      });
    }));
  }

  async function listRevokedCapabilityIds(input = {}) {
    const organizationId = tenant(input.organization_id ?? input.organizationId);
    const evaluatedAt = timestamp(input.evaluated_at ?? input.evaluatedAt ?? now(), "evaluated_at");
    return operation(async () => transaction(async (tx) => {
      await installTenantContext(tx, organizationId);
      const result = await tx.query(`SELECT public.agentpass_capability_authority_list_revoked(
        $1,$2::timestamptz,$3
      ) AS result`, [organizationId, evaluatedAt, MAX_CONTROL_BUNDLE_REVOCATIONS + 1]);
      const record = functionResult(result);
      if (record.state !== "listed" || !Array.isArray(record.capability_ids)) throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability authority returned an invalid revocation list");
      if (record.capability_ids.length > MAX_CONTROL_BUNDLE_REVOCATIONS) {
        throw new CapabilityAuthorityRepositoryError("ERR_REVOCATION_CAPACITY", "active capability revocations exceed the ControlBundle limit");
      }
      return Object.freeze(record.capability_ids.map((id) => uuid(id, "capability_id")));
    }));
  }

  async function operation(callback) {
    try { return await callback(); }
    catch (error) {
      if (error instanceof CapabilityAuthorityRepositoryError) throw error;
      throw new CapabilityAuthorityRepositoryError("ERR_DATABASE", "capability authority storage is unavailable");
    }
  }

  async function transaction(operation) {
    // `pg.Pool#query` may choose a different connection for each statement.
    // Pin a pool-backed transaction to one client; a connected pg client or a
    // test double is already transaction-capable and is used directly.
    const transactionClient = typeof client.connect === "function" ? await client.connect() : client;
    try {
      return await withTransaction(transactionClient, operation);
    } finally {
      if (transactionClient !== client) transactionClient.release?.();
    }
  }

  return Object.freeze({ issueCapabilityMetadata, revokeActiveCapabilitiesForMember, listRevokedCapabilityIds });
}

function normalizeIssueInput(input, now) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new CapabilityAuthorityRepositoryError("ERR_INPUT", "capability metadata input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const capabilityId = uuid(input.capability_id ?? input.capabilityId, "capability_id");
  const agentId = uuid(input.agent_id ?? input.agentId, "agent_id");
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const issuedByMemberId = uuid(input.issued_by_member_id ?? input.issuedByMemberId ?? input.member_id ?? input.memberId, "issued_by_member_id");
  const sequence = positiveInteger(input.sequence, "sequence");
  const statementHash = hash(input.statement_hash ?? input.statementHash);
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt, "expires_at");
  const evaluatedAt = timestamp(now(), "now");
  if (Date.parse(expiresAt) <= Date.parse(evaluatedAt)) throw new CapabilityAuthorityRepositoryError("ERR_EXPIRED", "capability expires_at must be in the future");
  const expectedValue = input.issued_membership_version ?? input.issuedMembershipVersion;
  const expectedMembershipVersion = expectedValue === undefined ? undefined : positiveInteger(expectedValue, "issued_membership_version");
  return { organizationId, capabilityId, agentId, deviceId, issuedByMemberId, sequence, statementHash, expiresAt, expectedMembershipVersion };
}

function normalizeRevokeInput(input, now) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new CapabilityAuthorityRepositoryError("ERR_INPUT", "capability revocation input must be an object");
  const organizationId = tenant(input.organization_id ?? input.organizationId);
  const memberId = uuid(input.member_id ?? input.memberId ?? input.issued_by_member_id ?? input.issuedByMemberId, "member_id");
  const actorMemberId = uuid(input.actor_member_id ?? input.actorMemberId ?? memberId, "actor_member_id");
  const revokedAt = timestamp(input.revoked_at ?? input.revokedAt ?? now(), "revoked_at");
  return { organizationId, memberId, actorMemberId, revokedAt };
}

async function installTenantContext(tx, organizationId) {
  const result = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(result) !== 1 || result.rows?.[0]?.organization_id !== organizationId) {
    throw new CapabilityAuthorityRepositoryError("ERR_TENANT_SCOPE", "capability tenant context could not be installed");
  }
}

function publicCapabilityRow(row) {
  if (!row || typeof row !== "object") throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability query returned an invalid row");
  return Object.freeze({
    organization_id: row.organization_id,
    capability_id: row.capability_id ?? row.id,
    agent_id: row.agent_id,
    device_id: row.device_id,
    sequence: positiveInteger(row.sequence, "sequence"),
    statement_hash: row.statement_hash,
    expires_at: timestamp(row.expires_at, "expires_at"),
    revoked_at: row.revoked_at === null || row.revoked_at === undefined ? null : timestamp(row.revoked_at, "revoked_at"),
    issued_by_member_id: row.issued_by_member_id,
    issued_membership_version: positiveInteger(row.issued_membership_version, "issued_membership_version")
  });
}

function functionResult(result) {
  if (rowCount(result) !== 1) throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability authority returned an invalid function result");
  const value = result.rows?.[0]?.result;
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.state !== "string") {
    throw new CapabilityAuthorityRepositoryError("ERR_DB_RESULT", "capability authority returned an invalid function result");
  }
  return value;
}

function tenant(value) {
  try { return assertTenantId(value); }
  catch (error) { throw new CapabilityAuthorityRepositoryError(error.code ?? "ERR_TENANT_SCOPE", error.message, error.details, error); }
}

function uuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new CapabilityAuthorityRepositoryError("ERR_UUID", `${field} must be a UUID`);
  return value;
}

function hash(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new CapabilityAuthorityRepositoryError("ERR_STATEMENT_HASH", "statement_hash must be a lowercase SHA-256 hex digest");
  return value;
}

function positiveInteger(value, field) {
  const number = typeof value === "string" && /^[0-9]+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 1) throw new CapabilityAuthorityRepositoryError("ERR_INTEGER", `${field} must be a positive safe integer`);
  return number;
}

function timestamp(value, field) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new CapabilityAuthorityRepositoryError("ERR_TIMESTAMP", `${field} must be a valid timestamp`);
  return date.toISOString();
}

function rowCount(result) {
  return Number(result?.rowCount ?? result?.rows?.length ?? 0);
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new CapabilityAuthorityRepositoryError("ERR_DB_CLIENT", "database client must provide query(text, params)");
}
