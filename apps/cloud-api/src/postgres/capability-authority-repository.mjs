import { assertTenantId, PostgresRepositoryError, withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const LOCK_PREFIX = "agentpass:capability-authority:";
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
      await lockOrganization(tx, values.organizationId);
      await lockAuthority(tx, values.organizationId, values.issuedByMemberId);
      const membership = await tx.query(`SELECT member_id,role,version
        FROM memberships
        WHERE organization_id=$1 AND member_id=$2 AND status='active'
        FOR SHARE`, [values.organizationId, values.issuedByMemberId]);
      if (rowCount(membership) !== 1 || !["owner", "admin"].includes(membership.rows[0].role)) {
        throw new CapabilityAuthorityRepositoryError("ERR_MEMBER_NOT_ACTIVE", "capability issuer is not an active organization administrator");
      }

      const membershipVersion = positiveInteger(membership.rows[0].version, "membership version");
      if (values.expectedMembershipVersion !== undefined && values.expectedMembershipVersion !== membershipVersion) {
        throw new CapabilityAuthorityRepositoryError("ERR_MEMBERSHIP_VERSION", "capability issuer membership version is stale", {
          expected: values.expectedMembershipVersion,
          actual: membershipVersion
        });
      }

      let result = await tx.query(`INSERT INTO capabilities
        (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
        VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9)
        ON CONFLICT (organization_id,id) DO NOTHING
        RETURNING organization_id,id AS capability_id,agent_id,device_id,sequence,statement_hash,
          expires_at,revoked_at,issued_by_member_id,issued_membership_version`, [
        values.organizationId,
        values.capabilityId,
        values.agentId,
        values.deviceId,
        values.sequence,
        values.statementHash,
        values.expiresAt,
        values.issuedByMemberId,
        membershipVersion
      ]);
      let replayed = false;
      if (rowCount(result) !== 1) {
        result = await tx.query(`SELECT organization_id,id AS capability_id,agent_id,device_id,sequence,statement_hash,
          expires_at,revoked_at,issued_by_member_id,issued_membership_version
          FROM capabilities WHERE organization_id=$1 AND id=$2 FOR UPDATE`, [values.organizationId, values.capabilityId]);
        if (rowCount(result) !== 1 || !sameCapabilityAuthority(result.rows[0], values, membershipVersion)) {
          throw new CapabilityAuthorityRepositoryError("ERR_CAPABILITY_CONFLICT", "capability identity conflicts with another request");
        }
        replayed = true;
      }
      return Object.freeze({ ...publicCapabilityRow(result.rows[0]), ...(replayed ? { replayed: true } : {}) });
    }));
  }

  async function revokeActiveCapabilitiesForMember(input = {}) {
    const values = normalizeRevokeInput(input, now);
    return operation(async () => transaction(async (tx) => {
      await lockOrganization(tx, values.organizationId);
      await lockAuthority(tx, values.organizationId, values.memberId);
      const result = await tx.query(`UPDATE capabilities
        SET revoked_at=$3::timestamptz
        WHERE organization_id=$1 AND issued_by_member_id=$2 AND revoked_at IS NULL
        RETURNING organization_id,id AS capability_id,agent_id,device_id,sequence,statement_hash,
          expires_at,revoked_at,issued_by_member_id,issued_membership_version`, [
        values.organizationId,
        values.memberId,
        values.revokedAt
      ]);
      const capabilities = (result.rows ?? []).map(publicCapabilityRow);
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
    return operation(async () => {
      const result = await client.query(`SELECT id AS capability_id
        FROM capabilities
        WHERE organization_id=$1 AND revoked_at IS NOT NULL AND expires_at>$2::timestamptz
        ORDER BY id ASC
        LIMIT $3`, [organizationId, evaluatedAt, MAX_CONTROL_BUNDLE_REVOCATIONS + 1]);
      const rows = result.rows ?? [];
      if (rows.length > MAX_CONTROL_BUNDLE_REVOCATIONS) {
        throw new CapabilityAuthorityRepositoryError("ERR_REVOCATION_CAPACITY", "active capability revocations exceed the ControlBundle limit");
      }
      return Object.freeze(rows.map((row) => uuid(row.capability_id ?? row.id, "capability_id")));
    });
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
  const revokedAt = timestamp(input.revoked_at ?? input.revokedAt ?? now(), "revoked_at");
  return { organizationId, memberId, revokedAt };
}

async function lockAuthority(tx, organizationId, memberId) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${LOCK_PREFIX}${organizationId}:${memberId}`]);
}

async function lockOrganization(tx, organizationId) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
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

function sameCapabilityAuthority(row, values, membershipVersion) {
  return row.organization_id === values.organizationId
    && (row.capability_id ?? row.id) === values.capabilityId
    && row.agent_id === values.agentId
    && row.device_id === values.deviceId
    && Number(row.sequence) === values.sequence
    && row.statement_hash === values.statementHash
    && timestamp(row.expires_at, "expires_at") === values.expiresAt
    && row.issued_by_member_id === values.issuedByMemberId
    && Number(row.issued_membership_version) === membershipVersion;
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
