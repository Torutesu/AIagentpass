import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_32 = /^[0-9a-f]{64}$/;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/;
const SUBJECT = /^[^\u0000-\u001f\u007f]{1,512}$/u;
const CREDENTIAL_TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const DEFAULT_MANAGEMENT_PAGE_SIZE = 25;
const MAX_MANAGEMENT_PAGE_SIZE = 100;

export function createPostgresHumanRepository({ client, onAuthorityReduction } = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid");
  if (onAuthorityReduction !== undefined && typeof onAuthorityReduction !== "function") throw new TypeError("onAuthorityReduction must be a function");
  return Object.freeze({
    createSession,
    findSessionByTokenHash,
    updateSessionActivity,
    revokeSession,
    listSessions,
    bindRecentAuth,
    consumeRecentAuth,
    createUpstreamIdentity,
    findUpstreamIdentity,
    listMembershipsForUpstreamIdentity,
    resolveUpstreamIdentity,
    consumeConsoleIdentityJti,
    getRegistrationUser,
    listCredentialsForSession,
    listCredentialMetadataForSession,
    findCredentialForSession,
    insertCredential,
    createCredential,
    insertCredentialForSession: insertCredential,
    updateCredentialCounter,
    updateCredentialLabel,
    revokeCredential,
    listSafeSessions,
    revokeManagedSession,
    revokeOtherSessions,
    revokeAllOtherSessions: revokeOtherSessions
  });

  async function createSession(record) {
    validateSession(record);
    const result = await client.query(`INSERT INTO human_sessions (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at,recent_auth_at,revoked_at,revoke_reason) SELECT $1,m.member_id,m.organization_id,m.id,m.role,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL FROM memberships m WHERE m.id=$4 AND m.member_id=$2 AND m.organization_id=$3 AND m.role=$11 AND m.status='active' RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [record.session_id, record.member_id, record.organization_id, record.membership_id, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at, record.role]);
    const created = sessionRow(result.rows?.[0]);
    if (!created) throw new TypeError("active session membership is unavailable");
    return created;
  }

  async function findSessionByTokenHash(input) {
    const result = await client.query(`SELECT s.*,encode(s.token_hash,'hex') AS token_hash_hex,encode(s.csrf_token_hash,'hex') AS csrf_token_hash_hex FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.token_hash=$1 AND m.status='active' AND m.role=s.role LIMIT 1`, [bytes32(input.token_hash ?? input.tokenHash)]);
    return sessionRow(result.rows?.[0]);
  }

  async function updateSessionActivity(input) {
    const result = await client.query(`UPDATE human_sessions SET last_seen_at=$2,idle_expires_at=$3 WHERE id=$1 AND revoked_at IS NULL RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [uuid(input.session_id ?? input.sessionId), input.last_seen_at ?? input.lastSeenAt, input.idle_expires_at ?? input.idleExpiresAt]);
    return sessionRow(result.rows?.[0]);
  }

  async function revokeSession(input) {
    const result = await client.query(`UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,$2),revoke_reason=COALESCE(revoke_reason,$3) WHERE id=$1 RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [uuid(input.session_id ?? input.sessionId), input.revoked_at ?? input.revokedAt, bounded(input.revoke_reason ?? input.reason, 128)]);
    return sessionRow(result.rows?.[0]);
  }

  async function listSessions(input) {
    const result = await client.query(`SELECT *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex FROM human_sessions WHERE member_id=$1 ORDER BY created_at ASC,id ASC LIMIT 100`, [uuid(input.member_id ?? input.memberId)]);
    return (result.rows ?? []).map(sessionRow);
  }

  async function listSafeSessions(input) {
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationValue = input?.organization_id ?? input?.organizationId;
    const organizationId = organizationValue === undefined ? undefined : uuid(organizationValue);
    const paging = keysetPagination(input, DEFAULT_MANAGEMENT_PAGE_SIZE, "session");
    const params = [memberId];
    const predicates = [
      "s.member_id=$1",
      "m.organization_id=s.organization_id",
      "m.member_id=s.member_id",
      "m.id=s.membership_id",
      "m.status='active'",
      "m.role=s.role"
    ];
    if (organizationId !== undefined) {
      params.push(organizationId);
      predicates.push(`s.organization_id=$${params.length}`);
    }
    const after = paging.after
      ? ` AND (date_trunc('milliseconds',s.created_at),s.id) > ($${params.length + 1},$${params.length + 2})`
      : "";
    if (paging.after) params.push(paging.after.createdAt, paging.after.id);
    params.push(paging.limit + 1);
    const result = await client.query(`SELECT s.id AS session_id,s.member_id,s.organization_id,s.role,s.version,s.created_at,s.expires_at,s.last_seen_at,s.idle_expires_at,s.recent_auth_at,s.revoked_at,s.revoke_reason FROM human_sessions s JOIN memberships m ON ${predicates.slice(1).join(" AND ")} WHERE ${predicates[0]}${after} ORDER BY date_trunc('milliseconds',s.created_at) ASC,s.id ASC LIMIT $${params.length}`, params);
    return (result.rows ?? []).map(safeSessionRow);
  }

  async function bindRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions SET recent_auth_at=$6,recent_auth_challenge_id=$5,recent_auth_organization_id=$3,recent_auth_operation=$4,recent_auth_consumed_at=NULL WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND revoked_at IS NULL AND expires_at>$6 RETURNING id`, [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), input.authenticated_at]);
    return result.rowCount === 1;
  }

  async function consumeRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions SET recent_auth_consumed_at=$5 WHERE member_id=$1 AND recent_auth_organization_id=$2 AND recent_auth_operation=$3 AND recent_auth_challenge_id=$4 AND recent_auth_consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$5 AND recent_auth_at>$5-INTERVAL '5 minutes' RETURNING recent_auth_at AS authenticated_at`, [uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), input.consumed_at]);
    return result.rowCount === 1 ? result.rows[0] : null;
  }

  async function createUpstreamIdentity(input) {
    const provider = identityProvider(input?.provider);
    const subject = identitySubject(input?.subject);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const inserted = await client.query(`INSERT INTO upstream_identities (provider,subject,member_id) VALUES ($1,$2,$3) ON CONFLICT (provider,subject) DO NOTHING RETURNING provider,subject,member_id,created_at`, [provider, subject, memberId]);
    if (inserted.rowCount === 1) return upstreamIdentityRow(inserted.rows[0]);

    // A conflict is idempotent only when it points at the same member. Never
    // silently rebind an identity, even if the caller presents a valid session.
    const existing = await client.query(`SELECT provider,subject,member_id,created_at FROM upstream_identities WHERE provider=$1 AND subject=$2`, [provider, subject]);
    const row = existing.rows?.[0];
    if (!row) throw upstreamIdentityConflict();
    if (String(row.member_id).toLowerCase() !== memberId) throw upstreamIdentityConflict();
    return upstreamIdentityRow(row);
  }

  async function findUpstreamIdentity(input) {
    const result = await client.query(`SELECT provider,subject,member_id,created_at FROM upstream_identities WHERE provider=$1 AND subject=$2`, [identityProvider(input?.provider), identitySubject(input?.subject)]);
    return result.rows?.[0] ? upstreamIdentityRow(result.rows[0]) : null;
  }

  async function listMembershipsForUpstreamIdentity(input) {
    const provider = identityProvider(input?.provider);
    const subject = identitySubject(input?.subject);
    const organizationId = input?.organization_id ?? input?.organizationId;
    const params = [provider, subject];
    let organizationClause = "";
    if (organizationId !== undefined) {
      organizationClause = " AND m.organization_id=$3";
      params.push(uuid(organizationId));
    }
    const result = await client.query(`SELECT ui.provider,ui.subject,ui.member_id,ui.created_at AS identity_created_at,m.organization_id,m.id AS membership_id,m.role,m.status,m.version,m.created_at,m.updated_at,o.name AS organization_name FROM upstream_identities ui JOIN memberships m ON m.member_id=ui.member_id JOIN organizations o ON o.id=m.organization_id WHERE ui.provider=$1 AND ui.subject=$2 AND m.status='active'${organizationClause} ORDER BY m.organization_id ASC,m.id ASC LIMIT 128`, params);
    return (result.rows ?? []).map(upstreamMembershipRow);
  }

  async function resolveUpstreamIdentity(input) {
    const memberships = await listMembershipsForUpstreamIdentity(input);
    const first = memberships[0];
    if (!first) return null;
    return Object.freeze({
      provider: first.provider,
      subject: first.subject,
      member_id: first.member_id,
      memberships
    });
  }

  /**
   * Atomically consume a signed-console identity jti before resolving its
   * provider subject. The dedicated replay table is created by the contract
   * migration; this repository method is the only caller-facing seam.
   */
  async function consumeConsoleIdentityJti(input) {
    const digest = digest32(input?.jti_digest ?? input?.jtiDigest);
    const expiresAt = timestamp(input?.expires_at ?? input?.expiresAt);
    const result = await client.query("SELECT agentpass_consume_human_identity_assertion($1::bytea,$2::timestamptz) AS consumed", [digest, expiresAt]);
    return result.rows?.[0]?.consumed === true;
  }

  async function getRegistrationUser(input) {
    const result = await client.query(`SELECT s.member_id,m.display_name FROM human_sessions s JOIN members m ON m.id=s.member_id JOIN memberships ms ON ms.organization_id=s.organization_id AND ms.member_id=s.member_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND ms.status='active' AND ms.role=s.role LIMIT 1`, [uuid(input?.session_id ?? input?.sessionId), uuid(input?.member_id ?? input?.memberId), uuid(input?.organization_id ?? input?.organizationId)]);
    const row = result.rows?.[0];
    if (!row) return null;
    const memberId = uuid(String(row.member_id));
    return { id: uuidUserHandle(memberId), name: `agentpass:${memberId}`, display_name: bounded(row.display_name ?? "AgentPass user", 128) };
  }

  async function listCredentialsForSession(input) {
    const result = await client.query(`SELECT c.id,c.transports FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.id=$1 AND s.organization_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND c.revoked_at IS NULL AND m.status='active' ORDER BY c.created_at ASC,c.id ASC LIMIT 64`, [uuid(input.session_id), uuid(input.organization_id)]);
    return (result.rows ?? []).map((row) => ({ id: credentialId(row.id), type: "public-key", transports: credentialTransports(row.transports) }));
  }

  async function findCredentialForSession(input) {
    const result = await client.query(`SELECT c.id,c.public_key,c.sign_count,c.transports,c.revoked_at FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND s.revoked_at IS NULL AND c.revoked_at IS NULL AND m.status='active' LIMIT 1`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024)]);
    const row = result.rows?.[0];
    return row ? { ...row, id: Buffer.from(row.id).toString("base64url"), sign_count: storedCounter(row.sign_count) } : null;
  }

  async function listCredentialMetadataForSession(input) {
    const scope = credentialScope(input);
    const paging = keysetPagination(input, DEFAULT_MANAGEMENT_PAGE_SIZE, "credential");
    const params = [scope.sessionId, scope.memberId, scope.organizationId];
    const after = paging.after
      ? ` AND EXISTS (SELECT 1 FROM webauthn_credentials anchor WHERE anchor.member_id=$2 AND ${credentialCursorIdSql("anchor")}=$5)
        AND (date_trunc('milliseconds',c.created_at),c.id) > (SELECT date_trunc('milliseconds',anchor.created_at),anchor.id FROM webauthn_credentials anchor WHERE anchor.member_id=$2 AND date_trunc('milliseconds',anchor.created_at)=$4 AND ${credentialCursorIdSql("anchor")}=$5 LIMIT 1)`
      : "";
    if (paging.after) params.push(paging.after.createdAt, paging.after.id);
    params.push(paging.limit + 1);
    const result = await client.query(`SELECT c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.version FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role${after} ORDER BY date_trunc('milliseconds',c.created_at) ASC,c.id ASC LIMIT $${params.length}`, params);
    return (result.rows ?? []).map(safeCredentialRow);
  }

  async function insertCredential(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const credentialId = base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024);
    const publicKey = publicKeyBytes(input?.public_key ?? input?.publicKey);
    const signCount = counter(input?.sign_count ?? input?.signCount);
    const transports = credentialTransports(input?.transports);
    const label = credentialLabel(input?.label);
    const backupEligible = strictBoolean(input?.backup_eligible ?? input?.backupEligible, "backup_eligible");
    const backupState = strictBoolean(input?.backup_state ?? input?.backupState, "backup_state");
    if (backupState && !backupEligible) throw new TypeError("backup_state requires backup_eligible");
    const result = await client.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state) SELECT $3,$2,$4,$5,$6,$7,$8,$9 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$10 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role ON CONFLICT (id) DO NOTHING RETURNING id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state,created_at,last_used_at,revoked_at`, [sessionId, memberId, credentialId, publicKey, signCount, transports, label, backupEligible, backupState, organizationId]);
    return result.rows?.[0] ? credentialRow(result.rows[0]) : null;
  }

  async function createCredential(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const credentialId = input?.credential_id ?? input?.credentialId;
    const backupState = input?.backup_state ?? input?.backupState ?? input?.credential_backed_up ?? false;
    const deviceType = input?.credential_device_type;
    if (deviceType !== undefined && deviceType !== "singleDevice" && deviceType !== "multiDevice") throw new TypeError("credential device type is invalid");
    if (deviceType === "singleDevice" && backupState === true) throw new TypeError("single-device credential cannot be backed up");
    const backupEligible = input?.backup_eligible ?? input?.backupEligible ?? (backupState === true || deviceType === "multiDevice");
    const created = await insertCredential({
      ...input,
      credential_id: credentialId,
      label: input?.label ?? "Unnamed credential",
      backup_eligible: backupEligible,
      backup_state: backupState
    });
    if (created) return Object.freeze({ created: true, credential_id: created.id });

    // `INSERT ... ON CONFLICT DO NOTHING` keeps duplicate registration
    // harmless. Distinguish that case for the registration service without
    // exposing the existing credential record or public key.
    const duplicate = await client.query(`SELECT 1 FROM webauthn_credentials c WHERE c.id=$1 AND EXISTS (SELECT 1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.id=$2 AND s.member_id=$3 AND s.organization_id=$4 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role) LIMIT 1`, [base64Bytes(credentialId, 16, 1024), sessionId, memberId, organizationId]);
    if (duplicate.rows?.length === 1) throw credentialExists();
    throw new Error("credential registration could not be stored");
  }

  async function updateCredentialCounter(input) {
    const result = await client.query(`UPDATE webauthn_credentials c SET sign_count=$4,last_used_at=clock_timestamp() FROM human_sessions s WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND c.member_id=s.member_id AND c.sign_count=$5 AND c.revoked_at IS NULL RETURNING c.id`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024), counter(input.sign_count), counter(input.expected_sign_count)]);
    return result.rowCount === 1;
  }

  async function updateCredentialLabel(input) {
    const scope = credentialScope(input);
    const label = credentialLabel(input?.label);
    const expectedVersion = positiveInteger(input?.expected_version ?? input?.expectedVersion);
    try {
      return await inTransaction(async (transactionClient) => {
        await lockOrganization(transactionClient, scope.organizationId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const result = await transactionClient.query(`UPDATE webauthn_credentials c SET label=$4,version=c.version+1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND c.id=$5 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$6 RETURNING c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.version`, [scope.sessionId, scope.memberId, scope.organizationId, label, base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024), expectedVersion]);
        if (result.rowCount === 0 && await credentialExistsInScope(transactionClient, scope, input?.credential_id ?? input?.credentialId)) throw versionConflict();
        return result.rows?.[0] ? safeCredentialRow(result.rows[0]) : null;
      });
    } catch (error) {
      throw normalizeLastCredentialError(error);
    }
  }

  async function revokeCredential(input) {
    const scope = credentialScope(input);
    const expectedVersion = positiveInteger(input?.expected_version ?? input?.expectedVersion);
    const credentialId = base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024);
    const revokedAt = input?.revoked_at ?? input?.revokedAt;
    if (typeof revokedAt !== "string" || !Number.isFinite(Date.parse(revokedAt))) throw new TypeError("revoked_at is invalid");
    const reasonValue = input?.revoke_reason ?? input?.revokeReason ?? input?.reason;
    const reason = reasonValue === undefined ? undefined : bounded(reasonValue, 128);
    try {
      return await inTransaction(async (transactionClient) => {
        await lockOrganization(transactionClient, scope.organizationId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const candidate = await transactionClient.query(`SELECT c.id FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND c.id=$4 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$5 LIMIT 1`, [scope.sessionId, scope.memberId, scope.organizationId, credentialId, expectedVersion]);
        if (candidate.rowCount !== 1) {
          if (await credentialExistsInScope(transactionClient, scope, input?.credential_id ?? input?.credentialId)) throw versionConflict();
          return null;
        }
        const count = await transactionClient.query("SELECT count(*)::text AS active_count FROM webauthn_credentials WHERE member_id=$1 AND revoked_at IS NULL", [scope.memberId]);
        const activeCount = Number(count.rows?.[0]?.active_count);
        if (!Number.isSafeInteger(activeCount) || activeCount < 1) throw lastCredentialError();
        if (activeCount === 1) throw lastCredentialError();
        const result = await transactionClient.query(`UPDATE webauthn_credentials c SET revoked_at=$7,revoke_reason=COALESCE($6,c.revoke_reason),version=c.version+1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND c.id=$4 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$5 RETURNING c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.version`, [scope.sessionId, scope.memberId, scope.organizationId, credentialId, expectedVersion, reason ?? null, revokedAt]);
        const record = result.rows?.[0] ? safeCredentialRow(result.rows[0]) : null;
        if (record && input?.authority_reduction === true) await notifyAuthorityReduction(transactionClient, { ...scope, memberId: scope.memberId, actorSessionId: input?.actor_session_id ?? input?.actorSessionId ?? scope.sessionId, targetId: record.id, resource: "credential", reason, occurredAt: revokedAt });
        return record;
      });
    } catch (error) {
      throw normalizeLastCredentialError(error);
    }
  }

  async function revokeOtherSessions(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const revokedAt = input?.revoked_at ?? input?.revokedAt;
    if (typeof revokedAt !== "string" || !Number.isFinite(Date.parse(revokedAt))) throw new TypeError("revoked_at is invalid");
    const reason = bounded(input?.revoke_reason ?? input?.revokeReason ?? input?.reason ?? "other_sessions_revoked", 128);
    return inTransaction(async (transactionClient) => {
      await lockOrganization(transactionClient, organizationId);
      await lockSessionSet(transactionClient, memberId);
      const result = await transactionClient.query(`UPDATE human_sessions target SET revoked_at=COALESCE(target.revoked_at,$4),revoke_reason=COALESCE(target.revoke_reason,$5) WHERE target.member_id=$2 AND target.id<>$1 AND target.revoked_at IS NULL AND EXISTS (SELECT 1 FROM human_sessions actor JOIN memberships m ON m.organization_id=actor.organization_id AND m.member_id=actor.member_id AND m.id=actor.membership_id WHERE actor.id=$1 AND actor.member_id=$2 AND actor.organization_id=$3 AND actor.revoked_at IS NULL AND actor.expires_at>clock_timestamp() AND (actor.idle_expires_at IS NULL OR actor.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=actor.role) RETURNING target.id AS session_id,target.member_id,target.organization_id,target.role,target.created_at,target.expires_at,target.last_seen_at,target.idle_expires_at,target.recent_auth_at,target.revoked_at,target.revoke_reason`, [sessionId, memberId, organizationId, revokedAt, reason]);
      return (result.rows ?? []).map(safeSessionRow);
    });
  }

  async function revokeManagedSession(input) {
    const actorSessionId = uuid(input?.actor_session_id ?? input?.actorSessionId ?? input?.session_id ?? input?.sessionId);
    const targetSessionId = uuid(input?.target_session_id ?? input?.targetSessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const expectedVersion = positiveInteger(input?.expected_version ?? input?.expectedVersion);
    const revokedAt = input?.revoked_at ?? input?.revokedAt;
    if (typeof revokedAt !== "string" || !Number.isFinite(Date.parse(revokedAt))) throw new TypeError("revoked_at is invalid");
    const reason = bounded(input?.reason ?? "human_management", 128);
    return inTransaction(async (transactionClient) => {
      await lockOrganization(transactionClient, organizationId);
      await lockSessionSet(transactionClient, memberId);
      const result = await transactionClient.query(`UPDATE human_sessions target SET revoked_at=$6,revoke_reason=$7,version=target.version+1 WHERE target.id=$4 AND target.member_id=$2 AND target.organization_id=$3 AND target.revoked_at IS NULL AND target.version=$5 AND EXISTS (SELECT 1 FROM human_sessions actor JOIN memberships m ON m.organization_id=actor.organization_id AND m.member_id=actor.member_id AND m.id=actor.membership_id WHERE actor.id=$1 AND actor.member_id=$2 AND actor.organization_id=$3 AND actor.revoked_at IS NULL AND actor.expires_at>clock_timestamp() AND (actor.idle_expires_at IS NULL OR actor.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=actor.role) RETURNING target.id AS session_id,target.member_id,target.organization_id,target.role,target.version,target.created_at,target.expires_at,target.last_seen_at,target.idle_expires_at,target.recent_auth_at,target.revoked_at,target.revoke_reason`, [actorSessionId, memberId, organizationId, targetSessionId, expectedVersion, revokedAt, reason]);
      if (result.rowCount === 0) {
        const exists = await transactionClient.query("SELECT 1 FROM human_sessions WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND revoked_at IS NULL LIMIT 1", [targetSessionId, memberId, organizationId]);
        if (exists.rowCount === 1) throw versionConflict();
      }
      const record = result.rows?.[0] ? safeSessionRow(result.rows[0]) : null;
      if (record && input?.authority_reduction === true) await notifyAuthorityReduction(transactionClient, { organizationId, memberId, actorSessionId, targetId: targetSessionId, resource: "session", reason, occurredAt: revokedAt });
      return record;
    });
  }

  async function inTransaction(operation) {
    if (typeof client.connect !== "function") return withTransaction(client, operation);
    const connection = await client.connect();
    try {
      return await withTransaction(connection, operation);
    } finally {
      connection.release?.();
    }
  }

  async function lockCredentialSet(transactionClient, memberId) {
    await transactionClient.query("SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:credentials:' || $1::text, 0)) AS locked", [memberId]);
  }

  async function lockOrganization(transactionClient, organizationId) {
    await transactionClient.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:organization:${organizationId}`]);
  }

  async function lockSessionSet(transactionClient, memberId) {
    await transactionClient.query("SELECT pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || $1::text, 0)) AS locked", [memberId]);
  }

  async function notifyAuthorityReduction(tx, { organizationId, memberId, actorSessionId, targetId, resource, reason, occurredAt }) {
    if (!onAuthorityReduction) {
      const error = new Error("authority reduction propagation is unavailable");
      error.code = "ERR_AUTHORITY_REDUCTION_UNAVAILABLE";
      throw error;
    }
    const result = await onAuthorityReduction(Object.freeze({
      tx,
      organization_id: organizationId,
      member_id: memberId,
      actor_session_id: actorSessionId,
      target_id: targetId,
      resource,
      reason: reason ?? null,
      occurred_at: occurredAt
    }));
    if (!result || typeof result !== "object" || !Number.isSafeInteger(result.generation) || result.generation < 1) {
      const error = new Error("authority reduction propagation is unavailable");
      error.code = "ERR_AUTHORITY_REDUCTION_UNAVAILABLE";
      throw error;
    }
  }

  async function credentialExistsInScope(transactionClient, scope, credentialValue) {
    const result = await transactionClient.query(`SELECT 1 FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role AND c.id=$4 AND c.revoked_at IS NULL LIMIT 1`, [scope.sessionId, scope.memberId, scope.organizationId, base64Bytes(credentialValue, 16, 1024)]);
    return result.rowCount === 1;
  }
}

function validateSession(record) { uuid(record?.session_id); uuid(record?.member_id); uuid(record?.membership_id); uuid(record?.organization_id); if (!["owner", "admin", "auditor", "viewer"].includes(record.role)) throw new TypeError("session role is invalid"); bytes32(record.token_hash); bytes32(record.csrf_token_hash); }
function sessionRow(row) { return row ? { ...row, session_id: row.session_id ?? row.id, token_hash: row.token_hash_hex ?? row.token_hash, csrf_token_hash: row.csrf_token_hash_hex ?? row.csrf_token_hash } : null; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("UUID is invalid"); return value.toLowerCase(); }
function bounded(value, max) { if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("bounded text is invalid"); return value; }
function identityProvider(value) { if (typeof value !== "string" || !PROVIDER.test(value)) throw new TypeError("identity provider is invalid"); return value; }
function identitySubject(value) { if (typeof value !== "string" || !SUBJECT.test(value) || value.trim() !== value) throw new TypeError("identity subject is invalid"); return value; }
function uuidUserHandle(value) { return Buffer.from(value.replaceAll("-", ""), "hex").toString("base64url"); }
function bytes32(value) { if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("digest is invalid"); return Buffer.from(value, "hex"); }
function digest32(value) { if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("identity replay digest is invalid"); return Buffer.from(value, "hex"); }
function timestamp(value) { if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new TypeError("timestamp is invalid"); return value; }
function base64Bytes(value, min, max) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("credential id is invalid"); const bytes=Buffer.from(value,"base64url"); if(bytes.length<min||bytes.length>max||bytes.toString("base64url")!==value) throw new TypeError("credential id is invalid"); return bytes; }
function credentialId(value) { if (!Buffer.isBuffer(value) || value.length < 16 || value.length > 1024) throw new TypeError("stored credential id is invalid"); return value.toString("base64url"); }
function credentialTransports(value) { if(!Array.isArray(value)||value.length>7||value.some((item)=>typeof item!=="string"||!CREDENTIAL_TRANSPORTS.has(item))||new Set(value).size!==value.length) throw new TypeError("stored credential transports are invalid"); return [...value]; }
function publicKeyBytes(value) { if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.length < 32 || value.length > 4096) throw new TypeError("public key is invalid"); return Buffer.from(value); }
function credentialLabel(value) { return bounded(value, 128); }
function strictBoolean(value, name) { if (typeof value !== "boolean") throw new TypeError(`${name} is invalid`); return value; }
function counter(value) { if (!Number.isSafeInteger(value)||value<0) throw new TypeError("counter is invalid"); return value; }
function storedCounter(value) { if (typeof value === "string" && /^(?:0|[1-9]\d*)$/.test(value)) value=Number(value); return counter(value); }
function upstreamIdentityRow(row) { return { provider: identityProvider(row.provider), subject: identitySubject(row.subject), member_id: uuid(String(row.member_id)), created_at: row.created_at }; }
function upstreamMembershipRow(row) { return { provider: identityProvider(row.provider), subject: identitySubject(row.subject), member_id: uuid(String(row.member_id)), identity_created_at: row.identity_created_at, organization_id: uuid(String(row.organization_id)), membership_id: uuid(String(row.membership_id)), role: membershipRole(row.role), status: "active", version: positiveInteger(row.version), created_at: row.created_at, updated_at: row.updated_at, organization_name: bounded(row.organization_name, 128) }; }
function membershipRole(value) { if (!["owner", "admin", "auditor", "viewer"].includes(value)) throw new TypeError("membership role is invalid"); return value; }
function positiveInteger(value) { if (typeof value === "string" && /^\d+$/.test(value)) value=Number(value); if (!Number.isSafeInteger(value)||value<1) throw new TypeError("membership version is invalid"); return value; }
function credentialRow(row) { return { id: credentialId(row.id), member_id: uuid(String(row.member_id)), public_key: publicKeyBytes(row.public_key), sign_count: storedCounter(row.sign_count), transports: credentialTransports(row.transports), label: credentialLabel(row.label), backup_eligible: strictBoolean(row.backup_eligible, "backup_eligible"), backup_state: strictBoolean(row.backup_state, "backup_state"), created_at: row.created_at, last_used_at: row.last_used_at ?? null, revoked_at: row.revoked_at ?? null }; }
function safeCredentialRow(row) { return { id: credentialId(row.id), member_id: uuid(String(row.member_id)), label: credentialLabel(row.label), transports: credentialTransports(row.transports), backup_eligible: strictBoolean(row.backup_eligible, "backup_eligible"), backup_state: strictBoolean(row.backup_state, "backup_state"), created_at: row.created_at, last_used_at: row.last_used_at ?? null, revoked_at: row.revoked_at ?? null, version: positiveInteger(row.version) }; }
function safeSessionRow(row) { const sessionId = uuid(String(row.session_id ?? row.id)); const memberId = uuid(String(row.member_id)); const organizationId = uuid(String(row.organization_id)); return { session_id: sessionId, member_id: memberId, organization_id: organizationId, role: membershipRole(row.role), version: positiveInteger(row.version ?? 1), created_at: row.created_at, expires_at: row.expires_at, last_seen_at: row.last_seen_at ?? null, idle_expires_at: row.idle_expires_at ?? null, recent_auth_at: row.recent_auth_at ?? null, revoked_at: row.revoked_at ?? null, revoke_reason: row.revoke_reason ?? null, status: row.revoked_at ? "revoked" : "active" }; }
function credentialScope(input) { return { sessionId: uuid(input?.session_id ?? input?.sessionId), memberId: uuid(input?.member_id ?? input?.memberId), organizationId: uuid(input?.organization_id ?? input?.organizationId) }; }
function keysetPagination(input, defaultLimit, resource) {
  const rawLimit = input?.limit;
  const limit = rawLimit === undefined ? defaultLimit : pageLimit(rawLimit);
  const hasCreatedAt = input?.after_created_at !== undefined;
  const hasId = input?.after_id !== undefined;
  if (hasCreatedAt !== hasId) throw new TypeError(`${resource} cursor position is incomplete`);
  if (!hasCreatedAt) return { limit, after: undefined };
  return {
    limit,
    after: {
      createdAt: cursorTimestamp(input.after_created_at),
      id: uuid(input.after_id)
    }
  };
}
function pageLimit(value) { if (!Number.isSafeInteger(value) || value < 1 || value > MAX_MANAGEMENT_PAGE_SIZE) throw new TypeError("management page limit is invalid"); return value; }
function cursorTimestamp(value) {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("cursor timestamp is invalid");
  return date.toISOString();
}
function credentialCursorIdSql(alias) {
  const digest = `encode(sha256(${alias}.id),'hex')`;
  return `(substr(${digest},1,8)||'-'||substr(${digest},9,4)||'-4'||substr(${digest},14,3)||'-8'||substr(${digest},18,3)||'-'||substr(${digest},21,12))::uuid`;
}
function lastCredentialError() { const error = new Error("cannot revoke the last active WebAuthn credential"); error.code = "ERR_LAST_ACTIVE_CREDENTIAL"; return error; }
function versionConflict() { const error = new Error("resource version conflict"); error.code = "ERR_VERSION_CONFLICT"; return error; }
function normalizeLastCredentialError(error) { return error?.code === "23514" && (error.constraint === "webauthn_credentials_last_active" || /last active WebAuthn credential/i.test(error.message ?? "")) ? lastCredentialError() : error; }
function upstreamIdentityConflict() { const error = new Error("upstream identity mapping conflict"); error.code = "ERR_UPSTREAM_IDENTITY_CONFLICT"; return error; }
function credentialExists() { const error = new Error("credential already exists"); error.code = "credential_exists"; return error; }
