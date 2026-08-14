import { createHash, randomUUID } from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/i;
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const ROLE_AUTHORITY = Object.freeze({ owner: 4, admin: 3, auditor: 2, viewer: 1 });
const INVITABLE_ROLES = new Set(["admin", "auditor", "viewer"]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const ZERO_HASH = "0".repeat(64);
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/;
const IDEMPOTENCY_TTL = "24 hours";
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;

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
export function createPostgresOrganizationRepository({ client, now = () => new Date().toISOString(), onAuthorityReduction } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (onAuthorityReduction !== undefined && typeof onAuthorityReduction !== "function") throw new TypeError("onAuthorityReduction must be a function");

  async function getOrganization(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    try {
      const result = await client.query(`SELECT id AS organization_id,name,version,created_at,updated_at
        FROM organizations WHERE id=$1 LIMIT 1`, [organizationId]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      return safeOrganizationRow(result.rows[0]);
    } catch (error) {
      if (error instanceof OrganizationRepositoryError) throw error;
      throw new OrganizationRepositoryError("ERR_DATABASE", "organization storage is unavailable");
    }
  }

  async function listOrganizationsForMember(input = {}) {
    const memberId = uuid(input.member_id ?? input.memberId);
    const hasPaging = input.limit !== undefined || input.after_created_at !== undefined || input.after_id !== undefined;
    if (!hasPaging) {
      const result = await client.query(`SELECT o.id AS organization_id,o.name,o.version,o.created_at,o.updated_at,
        m.id AS membership_id,m.role,m.status,m.version AS membership_version,m.created_at AS membership_created_at,
        m.updated_at AS membership_updated_at
        FROM memberships m JOIN organizations o ON o.id=m.organization_id
        WHERE m.member_id=$1 AND m.status='active'
        ORDER BY o.created_at ASC,o.id ASC LIMIT 128`, [memberId]);
      return (result.rows ?? []).map(safeOrganizationMembershipRow);
    }
    const limit = input.limit === undefined ? DEFAULT_PAGE_SIZE : pageLimit(input.limit);
    const hasAfterCreatedAt = input.after_created_at !== undefined;
    const hasAfterId = input.after_id !== undefined;
    if (hasAfterCreatedAt !== hasAfterId) throw new TypeError("organization cursor position is incomplete");
    const params = [memberId];
    // node-postgres materializes timestamptz values as millisecond-precision
    // Date objects. Compare and sort at that same precision so a row with
    // PostgreSQL-only microseconds cannot reappear after a cursor round-trip.
    const after = hasAfterCreatedAt ? ` AND (date_trunc('milliseconds',o.created_at),o.id) > ($2,$3)` : "";
    if (hasAfterCreatedAt) {
      params.push(timestamp(input.after_created_at, "after_created_at"));
      params.push(uuid(input.after_id));
    }
    params.push(limit + 1);
    const limitParameter = `$${params.length}`;
    const result = await client.query(`SELECT o.id AS organization_id,o.name,o.version,o.created_at,o.updated_at,
      m.id AS membership_id,m.role,m.status,m.version AS membership_version,m.created_at AS membership_created_at,
      m.updated_at AS membership_updated_at
      FROM memberships m JOIN organizations o ON o.id=m.organization_id
      WHERE m.member_id=$1 AND m.status='active'${after}
      ORDER BY date_trunc('milliseconds',o.created_at) ASC,o.id ASC LIMIT ${limitParameter}`, params);
    return (result.rows ?? []).map(safeOrganizationMembershipRow);
  }

  async function listMembers(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const paging = keysetPagination(input, "member");
    const params = [organizationId, actorId];
    const after = paging.after ? ` AND (date_trunc('milliseconds',ms.created_at),ms.id) > ($3,$4)` : "";
    if (paging.after) params.push(paging.after.createdAt, paging.after.id);
    params.push(paging.limit + 1);
    const result = await client.query(`SELECT ${READ_MEMBER_COLUMNS}
      FROM memberships ms JOIN members m ON m.id=ms.member_id
      WHERE ms.organization_id=$1 AND ms.status IN ('active','revoked')
        AND EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$2 AND actor.status='active'
            AND actor.role IN ('owner','admin','auditor'))${after}
      ORDER BY date_trunc('milliseconds',ms.created_at) ASC,ms.id ASC LIMIT $${params.length}`, params);
    return (result.rows ?? []).map(safeMemberRow);
  }

  async function createOrganizationWithOwner(input = {}) {
    const ownerId = uuid(input.owner_member_id ?? input.ownerMemberId ?? input.member_id ?? input.memberId ?? input.actor?.member_id);
    const actorId = input.actor_member_id ?? input.actorMemberId ?? input.actor?.member_id;
    if (actorId !== undefined && uuid(actorId) !== ownerId) throw new OrganizationRepositoryError("ERR_ACTOR", "actor must be the organization owner");
    const name = text(input.name, 128, "name");
    const createdAt = input.created_at ?? input.createdAt;
    if (createdAt !== undefined) timestamp(createdAt, "created_at");
    const idempotencyKey = requireIdempotencyKey(input);
    const actorPrincipal = principalId(input, ownerId);
    const requestedOrganizationId = input.organization_id ?? input.organizationId;
    const organizationId = uuid(requestedOrganizationId ?? deterministicOrganizationId(actorPrincipal, idempotencyKey));
    const requestHash = organizationMutationRequestHash("organization.create", {
      organization_id: requestedOrganizationId === undefined ? null : organizationId,
      actor_id: ownerId, actor_principal: actorPrincipal, name
    });
    return transaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      // idempotency_records has an FK to organizations, so establish the
      // tenant row before acquiring the record. Both statements are still
      // protected by the same transaction and organization lock.
      const organization = await tx.query(`INSERT INTO organizations (id,name,created_at,updated_at)
        VALUES ($1,$2,COALESCE($3,clock_timestamp()),COALESCE($3,clock_timestamp()))
        ON CONFLICT (id) DO NOTHING
        RETURNING id AS organization_id,name,version,created_at,updated_at`, [organizationId, name, createdAt ?? null]);
      const idempotency = await acquireIdempotency(tx, {
        organizationId, actorPrincipal, idempotencyKey, requestHash
      });
      if (idempotency.replayed) return idempotency.response;
      if ((organization.rowCount ?? organization.rows?.length ?? 0) !== 1) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }

      const membership = await tx.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
        VALUES ($1,$2,$3,'owner','active')
        RETURNING organization_id,id AS membership_id,member_id,role,status,version,created_at,updated_at`, [organizationId, randomUUID(), ownerId]);
      if ((membership.rowCount ?? membership.rows?.length ?? 0) !== 1) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }
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
      const result = { ...org, owner: member };
      await completeIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash, response: result, responseStatus: 201 });
      return result;
    });
  }

  async function renameOrganization(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const name = text(input.name, 128, "name");
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    return mutate(organizationId, input, "organization.rename", { organization_id: organizationId, actor_id: actorId, name, expected_version: expectedVersion }, async (tx) => {
      const result = await tx.query(`UPDATE organizations o SET name=$2,version=o.version+1,updated_at=clock_timestamp()
        WHERE o.id=$1 AND o.version=$3
          AND EXISTS (SELECT 1 FROM memberships actor
            WHERE actor.organization_id=$1 AND actor.member_id=$4 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING o.id AS organization_id,o.name,o.version,o.created_at,o.updated_at`, [organizationId, name, expectedVersion, actorId]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeOrganizationRow(result.rows[0]);
      await appendMutationEvents(tx, { organizationId, actorId, action: "organization.renamed", targetType: "organization", targetId: organizationId, details: { name, version: row.version } });
      return row;
    }, 200, mutationAuthorization(input));
  }

  async function updateMemberRole(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const memberId = uuid(input.target_member_id ?? input.targetMemberId ?? input.member_id ?? input.memberId);
    const roleValue = input.role;
    const role = memberRole(roleValue);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    const sessionsRevokedAt = input.revoked_at ?? input.revokedAt ?? now();
    timestamp(sessionsRevokedAt, "revoked_at");
    return mutate(organizationId, input, "membership.role_update", { organization_id: organizationId, actor_id: actorId, member_id: memberId, role, expected_version: expectedVersion }, async (tx) => {
      const actor = await requireMembershipMutationActor(tx, organizationId, actorId);
      const target = await requireActiveTargetMembership(tx, organizationId, memberId, expectedVersion);
      if (target.role === "owner" && actor.role !== "owner") throw new OrganizationRepositoryError("ERR_FORBIDDEN", "membership operation is not allowed");
      if (role === "owner" && actor.role !== "owner") throw new OrganizationRepositoryError("ERR_FORBIDDEN", "membership operation is not allowed");
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
      await revokeMemberSessions(tx, { organizationId, memberId, revokedAt: sessionsRevokedAt, reason: "membership_role_changed" });
      if (ROLE_AUTHORITY[role] < ROLE_AUTHORITY[target.role]) {
        await notifyAuthorityReduction(tx, { organizationId, actorId, memberId, eventType: "membership.role_reduced", occurredAt: sessionsRevokedAt });
      }
      await appendMutationEvents(tx, { organizationId, actorId, action: "membership.role_updated", targetType: "membership", targetId: row.membership_id, details: { member_id: row.member_id, role, version: row.version } });
      return row;
    }, 200, mutationAuthorization(input));
  }

  async function removeMember(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const memberId = uuid(input.target_member_id ?? input.targetMemberId ?? input.member_id ?? input.memberId);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    const removedAt = input.removed_at ?? input.removedAt ?? now();
    timestamp(removedAt, "removed_at");
    return mutate(organizationId, input, "membership.remove", { organization_id: organizationId, actor_id: actorId, member_id: memberId, expected_version: expectedVersion }, async (tx) => {
      const actor = await requireMembershipMutationActor(tx, organizationId, actorId);
      const target = await requireActiveTargetMembership(tx, organizationId, memberId, expectedVersion);
      if (target.role === "owner" && actor.role !== "owner") throw new OrganizationRepositoryError("ERR_FORBIDDEN", "membership operation is not allowed");
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
      await revokeMemberSessions(tx, { organizationId, memberId, revokedAt: removedAt, reason: "membership_removed" });
      await notifyAuthorityReduction(tx, { organizationId, actorId, memberId, eventType: "membership.removed", occurredAt: removedAt });
      await appendMutationEvents(tx, { organizationId, actorId, action: "membership.removed", targetType: "membership", targetId: row.membership_id, details: { member_id: row.member_id, version: row.version, removed_at: removedAt } });
      return row;
    }, 200, mutationAuthorization(input));
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
    const evaluatedAt = timestamp(createdAtValue ?? now(), "evaluated_at");
    return mutate(organizationId, input, "invitation.create", { organization_id: organizationId, actor_id: actorId, role, expires_at: expiresAt }, async (tx) => {
      const result = await tx.query(`INSERT INTO organization_invitations AS i
        (organization_id,id,token_hash,role,created_by,created_at,expires_at)
        SELECT $1,$2,$3,$4,$5,COALESCE($6,clock_timestamp()),$7
        WHERE EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, invitationId, tokenHash, role, actorId, createdAtValue ?? null, expiresAt]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeInvitationRow(result.rows[0], evaluatedAt);
      await appendMutationEvents(tx, { organizationId, actorId, action: "invitation.created", targetType: "invitation", targetId: invitationId, details: { role, expires_at: expiresAt, version: row.version } });
      return row;
    }, 201, mutationAuthorization(input));
  }

  async function listInvitations(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const paging = keysetPagination(input, "invitation");
    const params = [organizationId, actorId];
    const after = paging.after ? ` AND (date_trunc('milliseconds',i.created_at),i.id) > ($3,$4)` : "";
    if (paging.after) params.push(paging.after.createdAt, paging.after.id);
    params.push(paging.limit + 1);
    const result = await client.query(`SELECT ${SAFE_INVITATION_COLUMNS}
      FROM organization_invitations i
      WHERE i.organization_id=$1
        AND EXISTS (SELECT 1 FROM memberships actor
          WHERE actor.organization_id=$1 AND actor.member_id=$2 AND actor.status='active'
            AND actor.role IN ('owner','admin','auditor'))${after}
      ORDER BY date_trunc('milliseconds',i.created_at) ASC,i.id ASC LIMIT $${params.length}`, params);
    const evaluatedAt = timestamp(now(), "evaluated_at");
    return (result.rows ?? []).map((row) => safeInvitationRow(row, evaluatedAt));
  }

  async function revokeInvitation(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId ?? input.actor?.organization_id);
    const actorId = actorMemberId(input);
    const invitationId = uuid(input.invitation_id ?? input.invitationId);
    const expectedVersion = version(input.expected_version ?? input.expectedVersion);
    const revokedAt = input.revoked_at ?? input.revokedAt ?? now();
    timestamp(revokedAt, "revoked_at");
    const revokeReason = text(input.revoke_reason ?? input.revokeReason ?? "revoked_by_operator", 256, "revoke_reason");
    return mutate(organizationId, input, "invitation.revoke", { organization_id: organizationId, actor_id: actorId, invitation_id: invitationId, expected_version: expectedVersion, revoke_reason: revokeReason }, async (tx) => {
      const result = await tx.query(`UPDATE organization_invitations i SET revoked_by=$5,revoked_at=$4,revoke_reason=$6,version=i.version+1,updated_at=clock_timestamp()
        WHERE i.organization_id=$1 AND i.id=$2 AND i.version=$3 AND i.revoked_at IS NULL AND i.consumed_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships actor
            WHERE actor.organization_id=$1 AND actor.member_id=$5 AND actor.status='active' AND actor.role IN ('owner','admin'))
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, invitationId, expectedVersion, revokedAt, actorId, revokeReason]);
      if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) return null;
      const row = safeInvitationRow(result.rows[0], revokedAt);
      await appendMutationEvents(tx, { organizationId, actorId, action: "invitation.revoked", targetType: "invitation", targetId: invitationId, details: { version: row.version, revoked_at: revokedAt } });
      return row;
    }, 200, mutationAuthorization(input));
  }

  async function acceptInvitation(input = {}) {
    const tokenHash = digest(input.token_hash ?? input.tokenHash);
    const actorId = actorMemberId(input);
    const acceptedAt = input.accepted_at ?? input.acceptedAt ?? now();
    timestamp(acceptedAt, "accepted_at");
    const idempotencyKey = requireIdempotencyKey(input);
    const actorPrincipal = principalId(input, actorId);
    return transaction(async (tx) => {
      // The token is the only invitation selector. The member is the
      // authenticated actor; role always comes from this locked invitation.
      const invitation = await tx.query(`SELECT ${SAFE_INVITATION_COLUMNS}
        FROM organization_invitations i
        WHERE i.token_hash=$1
        FOR UPDATE`, [tokenHash]);
      if ((invitation.rowCount ?? invitation.rows?.length ?? 0) !== 1) return null;
      const stored = invitation.rows[0];
      const organizationId = uuid(stored.organization_id);
      await lockOrganization(tx, organizationId);
      const requestHash = organizationMutationRequestHash("invitation.accept", {
        organization_id: organizationId, actor_id: actorId, actor_principal: actorPrincipal,
        token_hash: tokenHash.toString("hex")
      });
      const idempotency = await acquireIdempotency(tx, {
        organizationId, actorPrincipal, idempotencyKey, requestHash
      });
      if (idempotency.replayed) return idempotency.response;

      const active = stored.revoked_at === null && stored.consumed_at === null && Date.parse(returnedTimestamp(stored.expires_at)) > Date.parse(acceptedAt);
      if (!active) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }
      const invitedMemberId = actorId;
      const role = memberRole(stored.role);
      const membership = await tx.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
        VALUES ($1,$2,$3,$4,'active')
        ON CONFLICT (organization_id,member_id) DO UPDATE SET role=EXCLUDED.role,status='active',version=memberships.version+1,updated_at=clock_timestamp()
        RETURNING organization_id,id AS membership_id,member_id,role,status,version,created_at,updated_at`, [organizationId, randomUUID(), invitedMemberId, role]);
      if ((membership.rowCount ?? membership.rows?.length ?? 0) !== 1) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }
      const row = safeMembershipRow(membership.rows[0]);
      const consumed = await tx.query(`UPDATE organization_invitations i SET consumed_by=$3,consumed_at=$4,version=i.version+1,updated_at=clock_timestamp()
        WHERE i.organization_id=$1 AND i.id=$2 AND i.token_hash=$5 AND i.revoked_at IS NULL AND i.consumed_at IS NULL
        RETURNING ${SAFE_INVITATION_COLUMNS}`, [organizationId, uuid(stored.invitation_id ?? stored.id), invitedMemberId, acceptedAt, tokenHash]);
      if ((consumed.rowCount ?? consumed.rows?.length ?? 0) !== 1) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }
      await appendMutationEvents(tx, { organizationId, actorId: invitedMemberId, action: "invitation.accepted", targetType: "invitation", targetId: uuid(stored.invitation_id ?? stored.id), details: { member_id: row.member_id, role: row.role, membership_id: row.membership_id, accepted_at: acceptedAt } });
      await completeIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash, response: row, responseStatus: 200 });
      return row;
    });
  }

  async function mutate(organizationId, input, operationName, request, operation, responseStatus, authorization = undefined) {
    const idempotencyKey = requireIdempotencyKey(input);
    const actorPrincipal = principalId(input, request.actor_id);
    const requestHash = organizationMutationRequestHash(operationName, { ...request, actor_principal: actorPrincipal });
    return transaction(async (tx) => {
      await lockOrganization(tx, organizationId);
      if (authorization) await requireMutationAuthorization(tx, { organizationId, actorId: request.actor_id, authorization });
      const idempotency = await acquireIdempotency(tx, {
        organizationId, actorPrincipal, idempotencyKey, requestHash
      });
      if (idempotency.replayed) return idempotency.response;
      const result = await operation(tx);
      if (result === null) {
        await abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash });
        return null;
      }
      await completeIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash, response: result, responseStatus });
      return result;
    });
  }

  async function lockOrganization(tx, organizationId) {
    await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
  }

  async function requireMutationAuthorization(tx, { organizationId, actorId, authorization }) {
    const params = [authorization.session_id, actorId, organizationId];
    let recentAuthPredicate = "";
    if (authorization.challenge_id !== undefined) {
      params.push(authorization.challenge_id, authorization.operation);
      recentAuthPredicate = `
        AND s.recent_auth_challenge_id=$4
        AND s.recent_auth_operation=$5
        AND s.recent_auth_consumed_at IS NOT NULL`;
    }
    const result = await tx.query(`SELECT s.id AS session_id,s.member_id,s.organization_id,s.membership_id,s.role,
        s.organization_authority_epoch,s.membership_session_epoch,o.authority_epoch,m.session_epoch
      FROM human_sessions s
      JOIN memberships m
        ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
      JOIN organizations o ON o.id=s.organization_id
      WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3
        AND s.revoked_at IS NULL
        AND s.expires_at>clock_timestamp()
        AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp())
        AND m.status='active'
        AND m.role=s.role
        AND m.role IN ('owner','admin')
        AND s.organization_authority_epoch=o.authority_epoch
        AND s.membership_session_epoch=m.session_epoch${recentAuthPredicate}
      FOR UPDATE OF s,m,o`, params);
    if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) {
      throw new OrganizationRepositoryError("ERR_STALE_SESSION", "the actor session is no longer current");
    }
    return result.rows[0];
  }

  async function requireMembershipMutationActor(tx, organizationId, actorId) {
    const result = await tx.query(`SELECT role,status
      FROM memberships
      WHERE organization_id=$1 AND member_id=$2
      FOR UPDATE`, [organizationId, actorId]);
    const row = result.rows?.[0];
    if ((result.rowCount ?? result.rows?.length ?? 0) !== 1 || row.status !== "active" || !["owner", "admin"].includes(row.role)) {
      throw new OrganizationRepositoryError("ERR_FORBIDDEN", "membership operation is not allowed");
    }
    return { role: memberRole(row.role) };
  }

  async function requireActiveTargetMembership(tx, organizationId, memberId, expectedVersion) {
    const result = await tx.query(`SELECT organization_id,id AS membership_id,member_id,role,status,version,created_at,updated_at
      FROM memberships
      WHERE organization_id=$1 AND member_id=$2
      FOR UPDATE`, [organizationId, memberId]);
    const row = result.rows?.[0];
    if ((result.rowCount ?? result.rows?.length ?? 0) !== 1 || row.status !== "active") {
      throw new OrganizationRepositoryError("ERR_MEMBER_NOT_FOUND", "organization member was not found");
    }
    if (returnedVersion(row.version) !== expectedVersion) {
      throw new OrganizationRepositoryError("ERR_VERSION_CONFLICT", "organization member version is stale");
    }
    return safeMembershipRow(row);
  }

  async function revokeMemberSessions(tx, { organizationId, memberId, revokedAt, reason }) {
    await tx.query(`UPDATE webauthn_challenges
      SET consumed_at=$3,status='consumed'
      WHERE organization_id=$1 AND member_id=$2
        AND status IN ('pending','consuming') AND consumed_at IS NULL`, [organizationId, memberId, revokedAt]);
    await tx.query(`UPDATE human_sessions
      SET revoked_at=$3,revoke_reason=$4,version=version+1,
        recent_auth_at=NULL,recent_auth_challenge_id=NULL,
        recent_auth_organization_id=NULL,recent_auth_operation=NULL,
        recent_auth_consumed_at=NULL
      WHERE organization_id=$1 AND member_id=$2 AND revoked_at IS NULL`, [organizationId, memberId, revokedAt, reason]);
    await tx.query(`UPDATE capabilities
      SET revoked_at=$3
      WHERE organization_id=$1 AND issued_by_member_id=$2 AND revoked_at IS NULL`, [organizationId, memberId, revokedAt]);
  }

  async function notifyAuthorityReduction(tx, { organizationId, actorId, memberId, eventType, occurredAt }) {
    if (!onAuthorityReduction) throw new OrganizationRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable");
    const result = await onAuthorityReduction(Object.freeze({
      tx,
      organization_id: organizationId,
      actor_member_id: actorId,
      member_id: memberId,
      event_type: eventType,
      occurred_at: occurredAt
    }));
    if (!result || typeof result !== "object" || !Number.isSafeInteger(result.generation) || result.generation < 1) {
      throw new OrganizationRepositoryError("ERR_AUTHORITY_REDUCTION_UNAVAILABLE", "authority reduction propagation is unavailable");
    }
  }

  async function acquireIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash }) {
    await tx.query(`DELETE FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
        AND expires_at<=clock_timestamp()`, [organizationId, actorPrincipal, idempotencyKey]);
    const inserted = await tx.query(`INSERT INTO idempotency_records
      (organization_id,principal_id,idempotency_key,request_hash,response_status,response_json,expires_at)
      VALUES ($1,$2,$3,$4,102,'{}'::jsonb,clock_timestamp()+$5::interval)
      ON CONFLICT (organization_id,principal_id,idempotency_key) DO NOTHING`,
    [organizationId, actorPrincipal, idempotencyKey, requestHash, IDEMPOTENCY_TTL]);
    const record = await tx.query(`SELECT request_hash,response_status,response_json
      FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
      FOR UPDATE`, [organizationId, actorPrincipal, idempotencyKey]);
    if ((record.rowCount ?? record.rows?.length ?? 0) !== 1) throw new OrganizationRepositoryError("ERR_IDEMPOTENCY", "idempotency record could not be acquired");
    const row = record.rows[0];
    if (String(row.request_hash).toLowerCase() !== requestHash) {
      throw new OrganizationRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key was already used for a different request");
    }
    if ((inserted.rowCount ?? inserted.rows?.length ?? 0) !== 1) return { replayed: true, response: replayResponse(row.response_json) };
    return { replayed: false };
  }

  async function completeIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash, response, responseStatus }) {
    const responseJson = JSON.stringify(response === undefined ? null : response);
    const completed = await tx.query(`UPDATE idempotency_records
      SET response_status=$4,response_json=$5::jsonb
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND request_hash=$6`,
    [organizationId, actorPrincipal, idempotencyKey, responseStatus, responseJson, requestHash]);
    if ((completed.rowCount ?? completed.rows?.length ?? 0) !== 1) throw new OrganizationRepositoryError("ERR_IDEMPOTENCY", "idempotency response could not be completed");
  }

  async function abandonIdempotency(tx, { organizationId, actorPrincipal, idempotencyKey, requestHash }) {
    const removed = await tx.query(`DELETE FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND request_hash=$4`,
    [organizationId, actorPrincipal, idempotencyKey, requestHash]);
    if ((removed.rowCount ?? removed.rows?.length ?? 0) !== 1) throw new OrganizationRepositoryError("ERR_IDEMPOTENCY", "idempotency response could not be abandoned");
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
      throw mapPostgresMutationError(error);
    } finally {
      if (tx !== client) tx.release?.();
    }
  }

  return Object.freeze({
    getOrganization,
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

export function canonicalOrganizationMutationRequest(operation, identity) {
  return stableCanonicalize({ version: 1, operation: text(operation, 128, "operation"), identity });
}

export function organizationMutationRequestHash(operation, identity) {
  return sha256Hex(canonicalOrganizationMutationRequest(operation, identity));
}

function canonicalOutboxPayload(event, eventHash) {
  return { version: 1, audit_event_id: event.audit_event_id, action: event.action, target_type: event.target_type, target_id: event.target_id, event_hash: eventHash, details: event.details };
}

function replayResponse(value) {
  const response = typeof value === "string" ? JSON.parse(value) : value;
  if (response && typeof response === "object" && !Array.isArray(response)) return { ...response, replayed: true };
  return { result: response, replayed: true };
}

function stableCanonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Number.isSafeInteger(value) || typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCanonicalize).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("canonical identity contains an invalid value");
  const keys = Object.keys(value).sort();
  if (keys.some((key) => value[key] === undefined)) throw new TypeError("canonical identity contains undefined");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableCanonicalize(value[key])}`).join(",")}}`;
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

function safeInvitationRow(row = {}, evaluatedAt) {
  const expiresAt = returnedTimestamp(row.expires_at);
  const consumedAt = nullableReturnedTimestamp(row.consumed_at);
  const revokedAt = nullableReturnedTimestamp(row.revoked_at);
  const statusAt = timestamp(evaluatedAt, "evaluated_at");
  return { organization_id: uuid(String(row.organization_id)), invitation_id: uuid(String(row.invitation_id ?? row.id)), role: memberRole(row.role), created_by: uuid(String(row.created_by)), created_at: returnedTimestamp(row.created_at), expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt, status: invitationStatus({ expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt }, statusAt), version: returnedVersion(row.version) };
}

function membershipStatus(value) { if (value !== "active" && value !== "revoked") throw new TypeError("membership status is invalid"); return value; }
function invitationStatus({ expires_at: expiresAt, consumed_at: consumedAt, revoked_at: revokedAt }, evaluatedAt) { if (consumedAt !== null) return "accepted"; if (revokedAt !== null) return "revoked"; if (Date.parse(expiresAt) <= Date.parse(evaluatedAt)) return "expired"; return "pending"; }
function memberRole(value) { if (typeof value !== "string" || !ROLES.has(value)) throw new TypeError("membership role is invalid"); return value; }
function invitationRole(value) { if (typeof value !== "string" || !INVITABLE_ROLES.has(value)) throw new TypeError("invitation role is invalid"); return value; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("UUID is invalid"); return value.toLowerCase(); }
function text(value, max, field) { if (typeof value !== "string" || value.length < 1 || value.length > max || CONTROL_CHARACTERS.test(value)) throw new TypeError(`${field} is invalid`); return value; }
function version(value) { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError("version is invalid"); return value; }
function timestamp(value, field) { if (typeof value !== "string" || !RFC3339.test(value)) throw new TypeError(`${field} is invalid`); const date = new Date(value); if (!Number.isFinite(date.getTime())) throw new TypeError(`${field} is invalid`); return value; }
function pageLimit(value) { if (!Number.isSafeInteger(value) || value < 1 || value > MAX_PAGE_SIZE) throw new TypeError("limit is invalid"); return value; }
function keysetPagination(input, resource) {
  const limit = input.limit === undefined ? DEFAULT_PAGE_SIZE : pageLimit(input.limit);
  const hasCreatedAt = input.after_created_at !== undefined;
  const hasId = input.after_id !== undefined;
  if (hasCreatedAt !== hasId) throw new TypeError(`${resource} cursor position is incomplete`);
  return { limit, after: hasCreatedAt ? { createdAt: timestamp(input.after_created_at, "after_created_at"), id: uuid(input.after_id) } : null };
}
function nullableTimestamp(value, field) { return value === null || value === undefined ? null : timestamp(value, field); }
function returnedVersion(value) { const result = typeof value === "bigint" ? Number(value) : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; return version(result); }
function returnedSequence(value) { const result = typeof value === "bigint" ? Number(value) : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 0) throw new TypeError("audit sequence is invalid"); return result; }
function returnedTimestamp(value) { if (value instanceof Date) { if (!Number.isFinite(value.getTime())) throw new TypeError("timestamp is invalid"); return value.toISOString(); } return timestamp(value, "timestamp"); }
function nullableReturnedTimestamp(value) { return value === null || value === undefined ? null : returnedTimestamp(value); }
function digest(value) { return Buffer.from(digestHex(value, "digest"), "hex"); }
function digestHex(value, field) { if (Buffer.isBuffer(value) || value instanceof Uint8Array) { if (value.byteLength !== 32) throw new TypeError(`${field} is invalid`); return Buffer.from(value).toString("hex"); } if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError(`${field} is invalid`); return value.toLowerCase(); }
function deterministicOrganizationId(actorPrincipal, idempotencyKey) {
  const bytes = createHash("sha256")
    .update("agentpass:organization:create:v1\u0000", "utf8")
    .update(actorPrincipal, "utf8")
    .update("\u0000", "utf8")
    .update(idempotencyKey, "utf8")
    .digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid"); }
function actorMemberId(input) { return uuid(input.actor_member_id ?? input.actorMemberId ?? input.actor?.member_id ?? input.member_id ?? input.memberId); }
function mutationAuthorization(input) {
  const sessionValue = input.actor_session_id ?? input.actorSessionId ?? input.actor?.session_id;
  if (sessionValue === undefined) return undefined;
  const sessionId = uuid(sessionValue);
  const challengeValue = input.recent_auth_challenge_id ?? input.recentAuthChallengeId;
  const operationValue = input.recent_auth_operation ?? input.recentAuthOperation;
  if (challengeValue === undefined && operationValue === undefined) return Object.freeze({ session_id: sessionId });
  if (challengeValue === undefined || operationValue === undefined) {
    throw new OrganizationRepositoryError("ERR_RECENT_AUTH_BINDING", "recent authorization binding is incomplete");
  }
  return Object.freeze({
    session_id: sessionId,
    challenge_id: uuid(challengeValue),
    operation: text(operationValue, 128, "recent_auth_operation")
  });
}
function principalId(input, fallback) {
  const value = input.principal_id ?? input.principalId ?? input.actor?.principal_id ?? input.actor?.principalId ?? fallback;
  return text(value, 256, "principal_id");
}
function requireIdempotencyKey(input) {
  const value = input.idempotency_key ?? input.idempotencyKey;
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new OrganizationRepositoryError("ERR_IDEMPOTENCY_KEY_REQUIRED", "mutation requires a valid idempotency_key");
  return value;
}
function mapPostgresMutationError(error) {
  if (error instanceof OrganizationRepositoryError) return error;
  if (error?.code === "23514" && error?.constraint === "memberships_last_active_owner") {
    return new OrganizationRepositoryError("ERR_LAST_OWNER", "the final active organization owner is protected");
  }
  return error;
}

export default createPostgresOrganizationRepository;
