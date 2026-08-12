import { createHash, randomUUID } from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/i;
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const INVITABLE_ROLES = new Set(["admin", "auditor", "viewer"]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const ZERO_HASH = "0".repeat(64);

const READ_MEMBER_COLUMNS = `m.id AS member_id,m.github_subject,m.display_name,m.created_at AS member_created_at,
  ms.organization_id,ms.id AS membership_id,ms.role,ms.status,ms.version,ms.created_at,ms.updated_at`;
const SAFE_INVITATION_COLUMNS = `i.organization_id,i.id AS invitation_id,i.role,i.created_at,i.expires_at,
  i.consumed_at,i.revoked_at,i.version,i.created_by`;

export class OrganizationRepositoryError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "OrganizationRepositoryError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * PostgreSQL repository for organization administration. The repository is
 * deliberately stateless: callers supply the actor and tenant on every call.
 * This prevents a repository instance from accidentally becoming a tenant
 * boundary that outlives a request.
 */
export function createPostgresOrganizationRepository({ client, now = () => new Date().toISOString() } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function listOrganizationsForMember(input = {}) {
    const memberId = uuid(input.member_id ?? input.memberId);
    const result = await client.query(`SELECT o.id AS organization_id,o.name,o.version,o.created_at,o.updated_at,
      m.id AS membership_id,m.role,m.status,m.version AS membership_version,m.created_at AS membership_created_at,
      m.updated_at AS membership_updated_at
      FROM memberships m JOIN organizations o ON o.id=m.organization_id
      WHERE m.member_id=$1 AND m.status='active'
      ORDER BY o.created_at ASC,o.id ASC LIMIT 128`, [memberId]);
    return (result.rows ?? []).map(safeOrganizationMembershipRow);
  }

  async function listMembers(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const result = await client.query(`SELECT ${READ_MEMBER_COLUMNS}
      FROM memberships ms JOIN members m ON m.id=ms.member_id
      WHERE ms.organization_id=$1 AND ms.status IN ('active','revoked')
        AND EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$2 AND actor.status='active'
            AND actor.role IN ('owner','admin','auditor'))
      ORDER BY m.created_at ASC,m.id ASC LIMIT 512`, [organizationId, actorId]);
    return (result.rows ?? []).map(safeMemberRow);
  }

  async function createOrganizationWithOwner(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? randomUUID());
    const ownerId = uuid(input.owner_member_id ?? input.ownerMemberId ?? input.member_id ?? input.memberId ?? input.actor?.member_id);
    const actorId = input.actor_member_id ?? input.actorMemberId ?? input.actor?.member_id;
    if (actorId !== undefined && uuid(actorId) !== ownerId) throw new OrganizationRepositoryError("ERR_ACTOR", "actor must be the organization owner");
    const name = text(input.name, 128, "name");
    const createdAt = input.created_at ?? input.createdAt;
    if (createdAt !== undefined) timestamp(createdAt, "created_at");
    return mutate(organizationId, async (tx) => {
      const organization = await tx.query(`INSERT INTO organizations (id,name,created_at,updated_at)
        VALUES ($1,$2,COALESCE($3,clock_timestamp()),COALESCE($3,clock_timestamp()))
        RETURNING id AS organization_id,name,version,created_at,updated_at`, [organizationId, name, createdAt ?? null]);
      if ((organization.rowCount ?? organization.rows?.length ?? 0) !== 1) return null;

      const membership = await tx.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
        VALUES ($1,$2,$3,'owner','active')
        RETURNING organization_id,id AS membership_id,member_id,role,status,version,created_at,updated_at`, [organizationId, randomUUID(), ownerId]);
      if ((membership.rowCount ?? membership.rows?.length ?? 0) !== 1) return null;
      const org = safeOrganizationRow(organization.rows[0]);
      const member = safeMembershipRow(membership.rows[0]);
      await appendMutationEvents(tx, {
        organizationId,
        actorId: ownerId,
        action: "organization.created",
        targetType: "organization",
        targetId: organizationId,
        details: { name, owner_member_id: ownerId }
      });
      return { ...org, owner: member };
    });
  }

  async function renameOrganization(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const name = text(input.name, 128, "name");
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    return mutate(organizationId, async (tx) => {
      const result = await tx.query(`UPDATE organizations o SET name=$2,version=o.version+1,updated_at=clock_timestamp()
        WHERE o.id=$1 AND o.version=$3
          AND EXISTS (SELECT 1 FROM memberships actor
            WHERE actor.organization_id=$1 AND actor.member_id=$4 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING o.id AS organization_id,o.name,o.version,o.created_at,o.updated_at`, [organizationId, name, expectedVersion, actorId]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeOrganizationRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "organization.renamed", targetType: "organization", targetId: organizationId, details: { name, version: row.version } });
      return row;
    });
  }

  async function updateMemberRole(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const memberId = uuid(input.target_member_id ?? input.targetMemberId ?? input.member_id ?? input.memberId);
    const roleValue = input.role;
    const role = memberRole(roleValue);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    return mutate(organizationId, async (tx) => {
      const result = await tx.query(`UPDATE memberships target SET role=$4,version=target.version+1,updated_at=clock_timestamp()
        FROM memberships actor
        WHERE target.organization_id=$1 AND target.member_id=$2 AND target.version=$3
          AND target.status='active'
          AND actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active'
          AND actor.role IN ('owner','admin')
          AND (target.role <> 'owner' OR actor.role='owner')
          AND ( $4 <> 'owner' OR actor.role='owner')
        RETURNING target.organization_id,target.id AS membership_id,target.member_id,target.role,target.status,
          target.version,target.created_at,target.updated_at`, [organizationId, memberId, expectedVersion, role, actorId]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeMembershipRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "membership.role_updated", targetType: "membership", targetId: row.membership_id, details: { member_id: row.member_id, role, version: row.version } });
      return row;
    });
  }

  async function removeMember(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const memberId = uuid(input.target_member_id ?? input.targetMemberId ?? input.member_id ?? input.memberId);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    const removedAt = input.removed_at ?? input.removedAt ?? now();
    timestamp(removedAt, "removed_at");
    return mutate(organizationId, async (tx) => {
      const result = await tx.query(`UPDATE memberships target SET status='revoked',version=target.version+1,updated_at=$4
        FROM memberships actor
        WHERE target.organization_id=$1 AND target.member_id=$2 AND target.version=$3 AND target.status='active'
          AND actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active'
          AND actor.role IN ('owner','admin')
          AND (target.role <> 'owner' OR actor.role='owner')
        RETURNING target.organization_id,target.id AS membership_id,target.member_id,target.role,target.status,
          target.version,target.created_at,target.updated_at`, [organizationId, memberId, expectedVersion, removedAt, actorId]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeMembershipRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "membership.removed", targetType: "membership", targetId: row.membership_id, details: { member_id: row.member_id, version: row.version, removed_at: removedAt } });
      return row;
    });
  }

  async function createInvitation(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const invitationId = uuid(input.invitation_id ?? input.invitationId ?? randomUUID());
    const role = invitationRole(input.role);
    const tokenHash = digest(input.token_hash ?? input.tokenHash);
    const expiresAt = timestamp(input.expires_at ?? input.expiresAt, "expires_at");
    const createdAtValue = input.created_at ?? input.createdAt;
    if (createdAtValue !== undefined) timestamp(createdAtValue, "created_at");
    return mutate(organizationId, async (tx) => {
      const result = await tx.query(`INSERT INTO organization_invitations
        (organization_id,id,token_hash,role,created_by,created_at,expires_at)
        SELECT $1,$2,$3,$4,$5,COALESCE($6,clock_timestamp()),$7
        WHERE EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, invitationId, tokenHash, role, actorId, createdAtValue ?? null, expiresAt]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeInvitationRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "invitation.created", targetType: "invitation", targetId: invitationId, details: { role, expires_at: expiresAt, version: row.version } });
      return row;
    });
  }

  async function listInvitations(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const result = await client.query(`SELECT ${SAFE_INVITATION_COLUMNS}
      FROM organization_invitations i
      WHERE i.organization_id=$1
        AND EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$2 AND actor.status='active'
            AND actor.role IN ('owner','admin','auditor'))
      ORDER BY i.created_at ASC,i.id ASC LIMIT 512`, [organizationId, actorId]);
    return (result.rows ?? []).map(safeInvitationRow);
  }

  async function revokeInvitation(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const invitationId = uuid(input.invitation_id ?? input.invitationId);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    const revokedAt = input.revoked_at ?? input.revokedAt ?? now();
    timestamp(revokedAt, "revoked_at");
    const revokeReason = text(input.revoke_reason ?? input.revokeReason ?? "revoked_by_operator", 256, "revoke_reason");
    return mutate(organizationId, async (tx) => {
      const result = await tx.query(`UPDATE organization_invitations i SET revoked_by=$5,revoked_at=$4,revoke_reason=$6,version=i.version+1,updated_at=clock_timestamp()
        WHERE i.organization_id=$1 AND i.id=$2 AND i.version=$3 AND i.revoked_at IS NULL AND i.consumed_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships actor
            WHERE actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, invitationId, expectedVersion, revokedAt, actorId, revokeReason]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeInvitationRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "invitation.revoked", targetType: "invitation", targetId: invitationId, details: { version: row.version, revoked_at: revokedAt } });
      return row;
    });
  }

  async function acceptInvitation(input = {}) {
    const tokenHash = digest(input.token_hash ?? input.tokenHash);
    const actorId = actorMemberId(input);
    const acceptedAt = input.accepted_at ?? input.acceptedAt ?? now();
    timestamp(acceptedAt, "accepted_at");
    return transaction(async (tx) => {
      // The token is the only invitation selector. The member is the
      // authenticated actor; role always comes from this locked invitation.
      const invitation = await tx.query(`SELECT ${SAFE_INVITATION_COLUMNS}
        FROM organization_invitations i
        WHERE i.token_hash=$1 AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at>$2
        FOR UPDATE`, [tokenHash, acceptedAt]);
      if ((invitation.rowCount ?? invitation.rows?.length ?? 0) !== 1) return null;
      const stored = invitation.rows[0];
      const organizationId = uuid(stored.organization_id);
      const invitedMemberId = actorId;
      const role = memberRole(stored.role);
      await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
      const membership = await tx.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
        VALUES ($1,$2,$3,$4,'active')
        ON CONFLICT (organization_id,member_id) DO UPDATE SET role=EXCLUDED.role,status='active',version=memberships.version+1,updated_at=clock_timestamp()
        RETURNING organization_id,id AS membership_id,member_id,role,status,version,created_at,updated_at`, [organizationId, randomUUID(), invitedMemberId, role]);
      if ((membership.rowCount ?? membership.rows?.length ?? 0) !== 1) return null;
      const row = safeMembershipRow(membership.rows[0]);
      const consumed = await tx.query(`UPDATE organization_invitations i SET consumed_by=$3,consumed_at=$4,version=i.version+1,updated_at=clock_timestamp()
        WHERE i.organization_id=$1 AND i.id=$2 AND i.token_hash=$5 AND i.revoked_at IS NULL AND i.consumed_at IS NULL
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, uuid(stored.invitation_id ?? stored.id), invitedMemberId, acceptedAt, tokenHash]);
      if ((consumed.rowCount ?? consumed.rows?.length ?? 0) !== 1) return null;
      await appendMutationEvents(tx, { organizationId, actorId: invitedMemberId, action: "invitation.accepted", targetType: "invitation", targetId: uuid(stored.invitation_id ?? stored.id), details: { member_id: row.member_id, role: row.role, membership_id: row.membership_id, accepted_at: acceptedAt } });
      return row;
    });
  }

  async function mutate(organizationId, operation) {
    return transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
      return operation(tx);
    });
  }

  async function transaction(operation) {
    const tx = typeof client.connect === "function" ? await client.connect() : client;
    let began = false;
    try {
      await tx.query("BEGIN", []);
      began = true;
      const result = await operation(tx);
      await tx.query("COMMIT", []);
      began = false;
      return result;
    } catch (error) {
      if (began) {
        try { await tx.query("ROLLBACK", []); }
        catch (rollbackError) { throw new OrganizationRepositoryError("ERR_ROLLBACK", "transaction rollback failed", { cause: rollbackError.message }); }
      }
      throw error;
    } finally {
      if (tx !== client) tx.release?.();
    }
  }

  return Object.freeze({
    listOrganizationsForMember,
    listMembers,
    createOrganizationWithOwner,
    renameOrganization,
    updateMemberRole,
    removeMember,
    createInvitation,
    listInvitations,
    revokeInvitation,
    acceptInvitation
  });

  async function appendMutationEvents(tx, { organizationId, actorId, action, targetType, targetId, details = {} }) {
    const auditId = randomUUID();
    const headInsert = await tx.query(`INSERT INTO admin_audit_heads (organization_id,sequence,event_hash)
      VALUES ($1,0,$2) ON CONFLICT (organization_id) DO NOTHING`, [organizationId, ZERO_HASH]);
    void headInsert;
    const head = await tx.query(`SELECT sequence,event_hash FROM admin_audit_heads WHERE organization_id=$1 FOR UPDATE`, [organizationId]);
    const previousHash = head.rows?.[0]?.event_hash ?? ZERO_HASH;
    const sequence = returnedSequence(head.rows?.[0]?.sequence ?? 0) + 1;
    digest(previousHash);
    const event = canonicalAuditEvent({
      audit_event_id: auditId,
      organization_id: organizationId,
      actor_id: actorId,
      action,
      target_type: targetType,
      target_id: targetId,
      details,
      previous_hash: previousHash,
      sequence
    });
    const eventHash = sha256Hex(JSON.stringify(event));
    await tx.query(`INSERT INTO admin_audit_events
      (organization_id,id,actor_id,action,target_type,target_id,previous_hash,event_hash,sequence,event_json)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`, [organizationId, auditId, actorId, action, targetType, targetId, previousHash, eventHash, sequence, JSON.stringify(event)]);
    await tx.query(`UPDATE admin_audit_heads SET sequence=$2,event_hash=$3,updated_at=clock_timestamp() WHERE organization_id=$1`, [organizationId, sequence, eventHash]);
    const outboxId = randomUUID();
    const payload = canonicalOutboxPayload(event, eventHash);
    await tx.query(`INSERT INTO outbox_events
      (organization_id,id,aggregate,action,payload)
      VALUES ($1,$2,$3,$4,$5::jsonb)`, [organizationId, outboxId, targetType, action, JSON.stringify(payload)]);
  }
}

export const createOrganizationRepository = createPostgresOrganizationRepository;

export function canonicalAuditEvent(input) {
  const event = {
    version: 1,
    audit_event_id: uuid(input.audit_event_id),
    organization_id: uuid(input.organization_id),
    actor_id: uuid(input.actor_id),
    action: text(input.action, 128, "action"),
    target_type: text(input.target_type, 64, "target_type"),
    target_id: input.target_id === null ? null : uuid(input.target_id),
    details: canonicalDetails(input.details),
    previous_hash: digestHex(input.previous_hash, "previous_hash"),
    sequence: version(input.sequence ?? 1)
  };
  return Object.freeze(event);
}

export function sha256Hex(value) {
  if (typeof value !== "string") throw new TypeError("hash input must be text");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonicalOutboxPayload(event, eventHash) {
  return { version: 1, audit_event_id: event.audit_event_id, action: event.action, target_type: event.target_type, target_id: event.target_id, event_hash: eventHash, details: event.details };
}

function canonicalDetails(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("audit details must be an object");
  const allowed = new Set(["name", "owner_member_id", "member_id", "role", "version", "expires_at", "removed_at", "revoked_at", "accepted_at", "membership_id"]);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key))) throw new TypeError("audit details contain an unsupported field");
  const result = {};
  for (const key of keys.sort()) {
    const item = value[key];
    if (item === null || typeof item === "string" || (Number.isSafeInteger(item) && item > 0)) result[key] = item;
    else throw new TypeError("audit detail value is invalid");
  }
  for (const key of ["owner_member_id", "member_id", "membership_id"]) if (result[key] !== undefined) result[key] = uuid(result[key]);
  for (const key of ["expires_at", "removed_at", "revoked_at", "accepted_at"]) if (result[key] !== undefined) result[key] = timestamp(result[key], key);
  if (result.role !== undefined) result.role = memberRole(result.role);
  if (result.name !== undefined) result.name = text(result.name, 128, "name");
  if (result.version !== undefined) result.version = version(result.version);
  return result;
}

function safeOrganizationRow(row = {}) {
  return { organization_id: uuid(String(row.organization_id ?? row.id)), name: text(String(row.name), 128, "name"), version: returnedVersion(row.version), created_at: returnedTimestamp(row.created_at), updated_at: returnedTimestamp(row.updated_at) };
}

function safeOrganizationMembershipRow(row = {}) {
  return { ...safeOrganizationRow(row), membership_id: uuid(String(row.membership_id)), role: memberRole(row.role), membership_status: "active", membership_version: returnedVersion(row.membership_version), membership_created_at: returnedTimestamp(row.membership_created_at), membership_updated_at: returnedTimestamp(row.membership_updated_at) };
}

function safeMembershipRow(row = {}) {
  return { organization_id: uuid(String(row.organization_id)), membership_id: uuid(String(row.membership_id ?? row.id)), member_id: uuid(String(row.member_id)), role: memberRole(row.role), status: membershipStatus(row.status), version: returnedVersion(row.version), created_at: returnedTimestamp(row.created_at), updated_at: returnedTimestamp(row.updated_at) };
}

function safeMemberRow(row = {}) {
  return { member_id: uuid(String(row.member_id ?? row.id)), github_subject: text(String(row.github_subject), 255, "github_subject"), display_name: row.display_name === null || row.display_name === undefined ? null : text(String(row.display_name), 128, "display_name"), member_created_at: returnedTimestamp(row.member_created_at), organization_id: uuid(String(row.organization_id)), membership_id: uuid(String(row.membership_id)), role: memberRole(row.role), status: membershipStatus(row.status), version: returnedVersion(row.version), created_at: returnedTimestamp(row.created_at), updated_at: returnedTimestamp(row.updated_at) };
}

function safeInvitationRow(row = {}) {
  const expiresAt = returnedTimestamp(row.expires_at);
  const consumedAt = nullableReturnedTimestamp(row.consumed_at);
  const revokedAt = nullableReturnedTimestamp(row.revoked_at);
  return { organization_id: uuid(String(row.organization_id)), invitation_id: uuid(String(row.invitation_id ?? row.id)), role: memberRole(row.role), created_by: uuid(String(row.created_by)), created_at: returnedTimestamp(row.created_at), expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt, status: invitationStatus({ expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt }), version: returnedVersion(row.version) };
}

function membershipStatus(value) { if (value !== "active" && value !== "revoked") throw new TypeError("membership status is invalid"); return value; }
function invitationStatus({ expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt }) { if (consumedAt !== null) return "accepted"; if (revokedAt !== null) return "revoked"; if (Date.parse(expiresAt) <= Date.now()) return "expired"; return "pending"; }
function memberRole(value) { if (typeof value !== "string" || !ROLES.has(value)) throw new TypeError("membership role is invalid"); return value; }
function invitationRole(value) { if (typeof value !== "string" || !INVITABLE_ROLES.has(value)) throw new TypeError("invitation role is invalid"); return value; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("UUID is invalid"); return value.toLowerCase(); }
function text(value, max, field) { if (typeof value !== "string" || value.length < 1 || value.length > max || CONTROL_CHARACTERS.test(value)) throw new TypeError(`${field} is invalid`); return value; }
function version(value) { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError("version is invalid"); return value; }
function timestamp(value, field) { if (typeof value !== "string" || !RFC3339.test(value)) throw new TypeError(`${field} is invalid`); const date = new Date(value); if (!Number.isFinite(date.getTime())) throw new TypeError(`${field} is invalid`); return value; }
function nullableTimestamp(value, field) { return value === null || value === undefined ? null : timestamp(value, field); }
function returnedVersion(value) { const result = typeof value === "bigint" ? Number(value) : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; return version(result); }
function returnedSequence(value) { const result = typeof value === "bigint" ? Number(value) : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 0) throw new TypeError("audit sequence is invalid"); return result; }
function returnedTimestamp(value) { if (value instanceof Date) { if (!Number.isFinite(value.getTime())) throw new TypeError("timestamp is invalid"); return value.toISOString(); } return timestamp(value, "timestamp"); }
function nullableReturnedTimestamp(value) { return value === null || value === undefined ? null : returnedTimestamp(value); }
function digest(value) { return Buffer.from(digestHex(value, "digest"), "hex"); }
function digestHex(value, field) { if (Buffer.isBuffer(value) || value instanceof Uint8Array) { if (value.byteLength !== 32) throw new TypeError(`${field} is invalid`); return Buffer.from(value).toString("hex"); } if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError(`${field} is invalid`); return value.toLowerCase(); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid"); }
function actorMemberId(input) { return uuid(input.actor_member_id ?? input.actorMemberId ?? input.actor?.member_id ?? input.member_id ?? input.memberId); }

export default createPostgresOrganizationRepository;
