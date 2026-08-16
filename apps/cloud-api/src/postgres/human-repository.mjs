import { createHash } from "node:crypto";

import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_32 = /^[0-9a-f]{64}$/;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/;
const SUBJECT = /^[^\u0000-\u001f\u007f]{1,512}$/u;
const CREDENTIAL_TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const DEFAULT_MANAGEMENT_PAGE_SIZE = 25;
const MAX_MANAGEMENT_PAGE_SIZE = 100;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const IDEMPOTENCY_TTL = "24 hours";

export function createPostgresHumanRepository({ client, onAuthorityReduction } = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid");
  if (onAuthorityReduction !== undefined && typeof onAuthorityReduction !== "function") throw new TypeError("onAuthorityReduction must be a function");
  return Object.freeze({
    createSession,
    createSessionWithLimit,
    rotateSession,
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
    createCredentialWithRecentAuth,
    insertCredentialForSession: insertCredential,
    updateCredentialCounter,
    quarantineCredentialClone,
    updateCredentialLabel,
    revokeCredential,
    listSafeSessions,
    revokeManagedSession,
    revokeOtherSessions,
    revokeAllOtherSessions: revokeOtherSessions
  });

  async function createSession(record) {
    validateSession(record);
    const result = await client.query(`INSERT INTO human_sessions (id,member_id,organization_id,membership_id,role,organization_authority_epoch,membership_session_epoch,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at,recent_auth_at,revoked_at,revoke_reason) SELECT $1,m.member_id,m.organization_id,m.id,m.role,o.authority_epoch,m.session_epoch,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.id=$4 AND m.member_id=$2 AND m.organization_id=$3 AND m.role=$11 AND m.status='active' RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [record.session_id, record.member_id, record.organization_id, record.membership_id, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at, record.role]);
    const created = sessionRow(result.rows?.[0]);
    if (!created) throw new TypeError("active session membership is unavailable");
    return created;
  }

  async function createSessionWithLimit(input) {
    const record = input?.session;
    validateSession(record);
    const limit = positiveInteger(input?.max_concurrent_sessions ?? input?.maxConcurrentSessions);
    if (limit > 10_000) throw new TypeError("max concurrent sessions is invalid");
    const issuedAt = timestamp(input?.issued_at ?? input?.issuedAt ?? record.created_at);
    const reason = bounded(input?.revoke_reason ?? input?.revokeReason ?? "concurrent_session_limit", 128);
    const identityReplay = optionalIdentityReplay(input?.identity_replay ?? input?.identityReplay);

    return inTransaction(async (transactionClient) => {
      // The global member lock, rather than a process-local mutex, makes the
      // ceiling authoritative across every API replica and organization.
      await lockSessionSet(transactionClient, record.member_id);
      if (identityReplay !== undefined) {
        const replay = await transactionClient.query("SELECT agentpass_consume_human_identity_assertion($1::bytea,$2::timestamptz) AS consumed", [identityReplay.jti_digest, identityReplay.expires_at]);
        if (replay.rows?.[0]?.consumed !== true) {
          const error = new Error("human identity assertion was already consumed");
          error.code = "human_identity_assertion_replay";
          throw error;
        }
      }
      const reduced = await transactionClient.query(`WITH ranked AS (
          SELECT s.id,row_number() OVER (ORDER BY s.created_at DESC,s.id DESC) AS position
          FROM human_sessions s
          JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id
          JOIN organizations o ON o.id=s.organization_id
          WHERE s.member_id=$1 AND s.revoked_at IS NULL AND s.expires_at>$2::timestamptz
            AND (s.idle_expires_at IS NULL OR s.idle_expires_at>$2::timestamptz)
            AND m.status='active' AND m.role=s.role
            AND o.authority_epoch=s.organization_authority_epoch
            AND m.session_epoch=s.membership_session_epoch
        ), excess AS (
          SELECT id FROM ranked WHERE position >= $3
        )
        UPDATE human_sessions target
        SET revoked_at=$2::timestamptz,revoke_reason=COALESCE(target.revoke_reason,$4)
        FROM excess
        WHERE target.id=excess.id AND target.revoked_at IS NULL
        RETURNING target.id`, [record.member_id, issuedAt, limit, reason]);
      if (!Number.isSafeInteger(Number(reduced?.rowCount ?? reduced?.rows?.length ?? 0))) throw new TypeError("session limit reduction failed");

      const result = await transactionClient.query(`INSERT INTO human_sessions (id,member_id,organization_id,membership_id,role,organization_authority_epoch,membership_session_epoch,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at,recent_auth_at,revoked_at,revoke_reason) SELECT $1,m.member_id,m.organization_id,m.id,m.role,o.authority_epoch,m.session_epoch,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.id=$4 AND m.member_id=$2 AND m.organization_id=$3 AND m.role=$11 AND m.status='active' RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [record.session_id, record.member_id, record.organization_id, record.membership_id, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at, record.role]);
      const created = sessionRow(result.rows?.[0]);
      if (!created) throw new TypeError("active session membership is unavailable");
      return created;
    });
  }

  async function rotateSession(input) {
    const oldSessionId = uuid(input?.old_session_id ?? input?.oldSessionId);
    const oldTokenHash = bytes32(input?.old_token_hash ?? input?.oldTokenHash);
    const record = input?.session;
    validateSession(record);
    const rotatedAt = timestamp(input?.rotated_at ?? input?.rotatedAt);
    const reason = bounded(input?.reason ?? "session_rotation", 128);

    return inTransaction(async (transactionClient) => {
      // The organization lock serializes this operation with authority changes;
      // the member lock serializes retries and concurrent session rotations.
      await lockOrganization(transactionClient, record.organization_id);
      await lockSessionSet(transactionClient, record.member_id);

      const old = await transactionClient.query(`SELECT s.id FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.token_hash=$2 AND s.member_id=$3 AND s.organization_id=$4 AND s.membership_id=$5 AND s.role=$6 AND s.revoked_at IS NULL AND s.expires_at>$7 AND (s.idle_expires_at IS NULL OR s.idle_expires_at>$7) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch FOR UPDATE`, [oldSessionId, oldTokenHash, record.member_id, record.organization_id, record.membership_id, record.role, rotatedAt]);
      // A retry sees the already-revoked exact old session and must not create
      // another active replacement.
      if (old.rowCount !== 1) return null;

      const created = await transactionClient.query(`INSERT INTO human_sessions (id,member_id,organization_id,membership_id,role,organization_authority_epoch,membership_session_epoch,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at,recent_auth_at,revoked_at,revoke_reason) SELECT $1,m.member_id,m.organization_id,m.id,m.role,o.authority_epoch,m.session_epoch,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.id=$4 AND m.member_id=$2 AND m.organization_id=$3 AND m.role=$11 AND m.status='active' RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [record.session_id, record.member_id, record.organization_id, record.membership_id, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at, record.role]);
      if (created.rowCount !== 1) throw new TypeError("active session membership is unavailable");

      const revoked = await transactionClient.query("UPDATE human_sessions s SET revoked_at=COALESCE(s.revoked_at,$2),revoke_reason=COALESCE(s.revoke_reason,$3) FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.token_hash=$4 AND s.organization_id=m.organization_id AND s.member_id=m.member_id AND s.membership_id=m.id AND s.revoked_at IS NULL AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING s.id", [oldSessionId, rotatedAt, reason, oldTokenHash]);
      if (revoked.rowCount !== 1) throw new Error("session rotation lost its old session lock");
      return sessionRow(created.rows[0]);
    });
  }

  async function findSessionByTokenHash(input) {
    const result = await client.query(`SELECT s.*,encode(s.token_hash,'hex') AS token_hash_hex,encode(s.csrf_token_hash,'hex') AS csrf_token_hash_hex FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch LIMIT 1`, [bytes32(input.token_hash ?? input.tokenHash)]);
    return sessionRow(result.rows?.[0]);
  }

  async function updateSessionActivity(input) {
    const result = await client.query(`UPDATE human_sessions s SET last_seen_at=$2,idle_expires_at=$3 FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.organization_id=m.organization_id AND s.member_id=m.member_id AND s.membership_id=m.id AND s.revoked_at IS NULL AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING s.*,encode(s.token_hash,'hex') AS token_hash_hex,encode(s.csrf_token_hash,'hex') AS csrf_token_hash_hex`, [uuid(input.session_id ?? input.sessionId), input.last_seen_at ?? input.lastSeenAt, input.idle_expires_at ?? input.idleExpiresAt]);
    return sessionRow(result.rows?.[0]);
  }

  async function revokeSession(input) {
    const result = await client.query(`UPDATE human_sessions s SET revoked_at=COALESCE(s.revoked_at,$2),revoke_reason=COALESCE(s.revoke_reason,$3) FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.organization_id=m.organization_id AND s.member_id=m.member_id AND s.membership_id=m.id AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING s.*,encode(s.token_hash,'hex') AS token_hash_hex,encode(s.csrf_token_hash,'hex') AS csrf_token_hash_hex`, [uuid(input.session_id ?? input.sessionId), input.revoked_at ?? input.revokedAt, bounded(input.revoke_reason ?? input.reason, 128)]);
    return sessionRow(result.rows?.[0]);
  }

  async function listSessions(input) {
    const result = await client.query(`SELECT s.*,encode(s.token_hash,'hex') AS token_hash_hex,encode(s.csrf_token_hash,'hex') AS csrf_token_hash_hex FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.member_id=$1 AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch ORDER BY s.created_at ASC,s.id ASC LIMIT 100`, [uuid(input.member_id ?? input.memberId)]);
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
      "m.role=s.role",
      "o.id=s.organization_id",
      "o.authority_epoch=s.organization_authority_epoch",
      "m.session_epoch=s.membership_session_epoch"
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
    const result = await client.query(`SELECT s.id AS session_id,s.member_id,s.organization_id,s.role,s.version,s.created_at,s.expires_at,s.last_seen_at,s.idle_expires_at,s.recent_auth_at,s.revoked_at,s.revoke_reason FROM human_sessions s JOIN memberships m ON ${predicates.slice(1, 6).join(" AND ")} JOIN organizations o ON ${predicates.slice(6).join(" AND ")} WHERE ${predicates[0]}${after} ORDER BY date_trunc('milliseconds',s.created_at) ASC,s.id ASC LIMIT $${params.length}`, params);
    return (result.rows ?? []).map(safeSessionRow);
  }

  async function bindRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions s SET recent_auth_at=$7,recent_auth_challenge_id=$5,recent_auth_organization_id=$3,recent_auth_operation=$4,recent_auth_context_hash=$6,recent_auth_consumed_at=NULL FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.membership_id=m.id AND m.member_id=s.member_id AND m.organization_id=s.organization_id AND s.revoked_at IS NULL AND s.expires_at>$7 AND (s.idle_expires_at IS NULL OR s.idle_expires_at>$7) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch AND EXISTS (SELECT 1 FROM webauthn_challenges c WHERE c.id=$5 AND c.session_id=s.id AND c.member_id=s.member_id AND c.organization_id=s.organization_id AND c.operation=$4 AND c.context_hash IS NOT DISTINCT FROM $6::bytea AND c.ceremony='authentication' AND c.status='consumed' AND c.consumed_at=$7) RETURNING s.id`, [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), contextHashBytes(input.context_hash), input.authenticated_at]);
    return result.rowCount === 1;
  }

  async function consumeRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions s SET recent_auth_consumed_at=$7 FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.recent_auth_organization_id=$3 AND s.organization_id=$3 AND s.recent_auth_operation=$4 AND s.recent_auth_challenge_id=$5 AND s.recent_auth_context_hash IS NOT DISTINCT FROM $6::bytea AND s.recent_auth_consumed_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>$7 AND (s.idle_expires_at IS NULL OR s.idle_expires_at>$7) AND s.recent_auth_at>$7-INTERVAL '5 minutes' AND s.membership_id=m.id AND m.member_id=s.member_id AND m.organization_id=s.organization_id AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING s.recent_auth_at AS authenticated_at, encode(s.recent_auth_context_hash, 'hex') AS context_hash`, [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), contextHashBytes(input.context_hash), input.consumed_at]);
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

  function optionalIdentityReplay(value) {
    if (value === undefined) return undefined;
    return Object.freeze({
      jti_digest: digest32(value?.jti_digest ?? value?.jtiDigest),
      expires_at: timestamp(value?.expires_at ?? value?.expiresAt)
    });
  }

  async function getRegistrationUser(input) {
    const result = await client.query(`SELECT s.member_id,m.display_name FROM human_sessions s JOIN members m ON m.id=s.member_id JOIN memberships ms ON ms.organization_id=s.organization_id AND ms.member_id=s.member_id AND ms.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND ms.status='active' AND ms.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND ms.session_epoch=s.membership_session_epoch LIMIT 1`, [uuid(input?.session_id ?? input?.sessionId), uuid(input?.member_id ?? input?.memberId), uuid(input?.organization_id ?? input?.organizationId)]);
    const row = result.rows?.[0];
    if (!row) return null;
    const memberId = uuid(String(row.member_id));
    return { id: uuidUserHandle(memberId), name: `agentpass:${memberId}`, display_name: bounded(row.display_name ?? "AgentPass user", 128) };
  }

  async function listCredentialsForSession(input) {
    const result = await client.query(`SELECT c.id,c.transports FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.organization_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND c.revoked_at IS NULL AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch ORDER BY c.created_at ASC,c.id ASC LIMIT 64`, [uuid(input.session_id), uuid(input.organization_id)]);
    return (result.rows ?? []).map((row) => ({ id: credentialId(row.id), type: "public-key", transports: credentialTransports(row.transports) }));
  }

  async function findCredentialForSession(input) {
    const result = await client.query(`SELECT c.id,c.public_key,c.sign_count,c.transports,c.backup_eligible,c.backup_state,c.revoked_at FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND c.revoked_at IS NULL AND c.clone_detected_at IS NULL AND c.sign_count_state<>'clone-detected' AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch LIMIT 1`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024)]);
    const row = result.rows?.[0];
    return row ? { ...row, id: Buffer.from(row.id).toString("base64url"), sign_count: storedCounter(row.sign_count), backup_eligible: strictBoolean(row.backup_eligible, "backup_eligible"), backup_state: strictBoolean(row.backup_state, "backup_state") } : null;
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
    const result = await client.query(`SELECT c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.clone_detected_at,c.version FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch${after} ORDER BY date_trunc('milliseconds',c.created_at) ASC,c.id ASC LIMIT $${params.length}`, params);
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
    const result = await client.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state) SELECT $3,$2,$4,$5,$6,$7,$8,$9 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$10 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch ON CONFLICT (id) DO NOTHING RETURNING id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state,created_at,last_used_at,revoked_at`, [sessionId, memberId, credentialId, publicKey, signCount, transports, label, backupEligible, backupState, organizationId]);
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
    const duplicate = await client.query(`SELECT 1 FROM webauthn_credentials c WHERE c.id=$1 AND EXISTS (SELECT 1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$2 AND s.member_id=$3 AND s.organization_id=$4 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch) LIMIT 1`, [base64Bytes(credentialId, 16, 1024), sessionId, memberId, organizationId]);
    if (duplicate.rows?.length === 1) throw credentialExists();
    throw new Error("credential registration could not be stored");
  }

  async function createCredentialWithRecentAuth(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const credentialId = base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024);
    const publicKey = publicKeyBytes(input?.public_key ?? input?.publicKey);
    const signCount = counter(input?.sign_count ?? input?.signCount);
    const transports = credentialTransports(input?.transports);
    const label = credentialLabel(input?.label ?? "Unnamed credential");
    const backupState = strictBoolean(input?.backup_state ?? input?.backupState ?? input?.credential_backed_up ?? false, "backup_state");
    const deviceType = input?.credential_device_type;
    if (deviceType !== undefined && deviceType !== "singleDevice" && deviceType !== "multiDevice") throw new TypeError("credential device type is invalid");
    if (deviceType === "singleDevice" && backupState) throw new TypeError("single-device credential cannot be backed up");
    const backupEligible = strictBoolean(input?.backup_eligible ?? input?.backupEligible ?? (backupState || deviceType === "multiDevice"), "backup_eligible");
    if (backupState && !backupEligible) throw new TypeError("backup_state requires backup_eligible");
    const recentAuth = input?.recent_auth;

    return inTransaction(async (transactionClient) => {
      await lockCredentialSet(transactionClient, memberId);
      const active = await transactionClient.query("SELECT COUNT(*) FILTER (WHERE revoked_at IS NULL AND clone_detected_at IS NULL) AS active_count,COUNT(*) AS total_count FROM webauthn_credentials WHERE member_id=$1", [memberId]);
      const activeCount = parseDatabaseCount(active.rows?.[0]?.active_count, "active credential count");
      const totalCount = parseDatabaseCount(active.rows?.[0]?.total_count, "credential count");
      if (activeCount > totalCount) throw new TypeError("credential counts are invalid");
      if (totalCount > 0) {
        let authorizationId;
        let operation;
        let proofSessionId;
        let proofMemberId;
        let proofOrganizationId;
        try {
          authorizationId = uuid(recentAuth?.authorization_id);
          operation = bounded(recentAuth?.operation, 128);
          proofSessionId = uuid(recentAuth?.session_id);
          proofMemberId = uuid(recentAuth?.member_id);
          proofOrganizationId = uuid(recentAuth?.organization_id);
        } catch {
          throw recentAuthRequired();
        }
        if (operation !== "human.webauthn.credential.register" || proofSessionId !== sessionId || proofMemberId !== memberId || proofOrganizationId !== organizationId) throw recentAuthRequired();
        const consumed = await transactionClient.query(`UPDATE human_sessions s SET recent_auth_consumed_at=clock_timestamp() FROM memberships m JOIN organizations o ON o.id=m.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.recent_auth_operation=$4 AND s.recent_auth_challenge_id=$5 AND s.recent_auth_context_hash IS NOT DISTINCT FROM $6::bytea AND s.recent_auth_consumed_at IS NULL AND s.recent_auth_at>clock_timestamp()-INTERVAL '5 minutes' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND s.membership_id=m.id AND m.member_id=s.member_id AND m.organization_id=s.organization_id AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING s.id`, [sessionId, memberId, organizationId, operation, authorizationId, contextHashBytes(recentAuth?.context_hash)]);
        if (consumed.rowCount !== 1) throw recentAuthRequired();
      }

      const inserted = await transactionClient.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state) SELECT $3,$2,$4,$5,$6,$7,$8,$9 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$10 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch ON CONFLICT (id) DO NOTHING RETURNING id`, [sessionId, memberId, credentialId, publicKey, signCount, transports, label, backupEligible, backupState, organizationId]);
      if (inserted.rowCount === 1) return Object.freeze({ created: true, credential_id: credentialId.toString("base64url"), authorized: true });
      const duplicate = await transactionClient.query("SELECT 1 FROM webauthn_credentials WHERE id=$1 LIMIT 1", [credentialId]);
      if (duplicate.rowCount === 1) throw credentialExists();
      throw new Error("credential registration could not be stored");
    });
  }

  async function updateCredentialCounter(input) {
    const hasBackupState = input?.backup_eligible !== undefined || input?.backup_state !== undefined || input?.expected_backup_eligible !== undefined || input?.expected_backup_state !== undefined;
    const backupEligible = hasBackupState ? strictBoolean(input?.backup_eligible, "backup_eligible") : null;
    const backupState = hasBackupState ? strictBoolean(input?.backup_state, "backup_state") : null;
    const expectedBackupEligible = hasBackupState ? strictBoolean(input?.expected_backup_eligible, "expected_backup_eligible") : null;
    const expectedBackupState = hasBackupState ? strictBoolean(input?.expected_backup_state, "expected_backup_state") : null;
    if (hasBackupState && ((backupState && !backupEligible) || (expectedBackupState && !expectedBackupEligible))) throw new TypeError("backup_state requires backup_eligible");
    const nextCount = counter(input.sign_count);
    const result = await client.query(`UPDATE webauthn_credentials c SET sign_count=$4,sign_count_state=CASE WHEN $4=0 THEN 'zero-counter' ELSE 'monotonic' END,backup_eligible=COALESCE($6,c.backup_eligible),backup_state=COALESCE($7,c.backup_state),last_used_at=clock_timestamp() FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND c.member_id=s.member_id AND c.sign_count=$5 AND ($8::boolean IS NULL OR c.backup_eligible=$8) AND ($9::boolean IS NULL OR c.backup_state=$9) AND c.revoked_at IS NULL AND c.clone_detected_at IS NULL AND c.sign_count_state<>'clone-detected' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch RETURNING c.id`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024), nextCount, counter(input.expected_sign_count), backupEligible, backupState, expectedBackupEligible, expectedBackupState]);
    return result.rowCount === 1;
  }

  async function quarantineCredentialClone(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const credentialValue = input?.credential_id ?? input?.credentialId;
    const expectedCount = counter(input?.expected_sign_count ?? input?.expectedSignCount);
    const observedCount = counter(input?.observed_sign_count ?? input?.observedSignCount);
    if ((expectedCount === 0 && observedCount === 0) || observedCount > expectedCount) throw new TypeError("clone counter evidence is invalid");
    return inTransaction(async (transactionClient) => {
      await lockOrganization(transactionClient, organizationId);
      const session = await transactionClient.query(`SELECT s.member_id FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.organization_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch`, [sessionId, organizationId]);
      const memberId = session.rows?.[0]?.member_id === undefined ? null : uuid(String(session.rows[0].member_id));
      if (memberId === null) return false;
      await lockCredentialSet(transactionClient, memberId);
      const result = await transactionClient.query(`UPDATE webauthn_credentials
        SET sign_count_state='clone-detected',clone_detected_at=clock_timestamp(),version=version+1
        WHERE id=$1 AND member_id=$2 AND revoked_at IS NULL AND clone_detected_at IS NULL
          AND sign_count_state<>'clone-detected' AND sign_count>0 AND sign_count>=$3
        RETURNING id,clone_detected_at`, [base64Bytes(credentialValue, 16, 1024), memberId, expectedCount]);
      if (result.rowCount !== 1) return false;
      const detectedAt = storedTimestamp(result.rows[0].clone_detected_at, "clone_detected_at");
      await notifyAuthorityReduction(transactionClient, { organizationId, memberId, actorSessionId: sessionId, targetId: credentialId(result.rows[0].id), resource: "credential", reason: "webauthn_clone_detected", occurredAt: detectedAt });
      return true;
    });
  }

  async function updateCredentialLabel(input) {
    const scope = credentialScope(input);
    const label = credentialLabel(input?.label);
    const expectedVersion = positiveInteger(input?.expected_version ?? input?.expectedVersion);
    const idempotencyKey = optionalIdempotencyKey(input?.idempotency_key ?? input?.idempotencyKey);
    const requestHash = idempotencyKey === undefined ? undefined : humanCredentialMutationRequestHash("credential.rename", {
      organization_id: scope.organizationId,
      member_id: scope.memberId,
      session_id: scope.sessionId,
      credential_id: input?.credential_id ?? input?.credentialId,
      label,
      expected_version: expectedVersion
    });
    try {
      return await inTransaction(async (transactionClient) => {
        await lockOrganization(transactionClient, scope.organizationId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const idempotency = idempotencyKey === undefined ? undefined : await acquireHumanCredentialIdempotency(transactionClient, {
          organizationId: scope.organizationId,
          principalId: scope.sessionId,
          idempotencyKey,
          requestHash
        });
        if (idempotency?.replayed) return idempotency.response;
        const result = await transactionClient.query(`UPDATE webauthn_credentials c SET label=$4,version=c.version+1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch AND c.id=$5 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$6 RETURNING c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.version`, [scope.sessionId, scope.memberId, scope.organizationId, label, base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024), expectedVersion]);
        if (result.rowCount === 0 && await credentialExistsInScope(transactionClient, scope, input?.credential_id ?? input?.credentialId)) throw versionConflict();
        const record = result.rows?.[0] ? safeCredentialRow(result.rows[0]) : null;
        if (record && idempotencyKey !== undefined) await completeHumanCredentialIdempotency(transactionClient, { organizationId: scope.organizationId, principalId: scope.sessionId, idempotencyKey, requestHash, response: record, responseStatus: 200 });
        if (!record && idempotencyKey !== undefined) await abandonHumanCredentialIdempotency(transactionClient, { organizationId: scope.organizationId, principalId: scope.sessionId, idempotencyKey, requestHash });
        return record;
      });
    } catch (error) {
      throw normalizeLastCredentialError(error);
    }
  }

  async function revokeCredential(input) {
    const scope = credentialScope(input);
    const expectedVersion = positiveInteger(input?.expected_version ?? input?.expectedVersion);
    const credentialId = base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024);
    const idempotencyKey = optionalIdempotencyKey(input?.idempotency_key ?? input?.idempotencyKey);
    const revokedAt = input?.revoked_at ?? input?.revokedAt;
    if (typeof revokedAt !== "string" || !Number.isFinite(Date.parse(revokedAt))) throw new TypeError("revoked_at is invalid");
    const reasonValue = input?.revoke_reason ?? input?.revokeReason ?? input?.reason;
    const reason = reasonValue === undefined ? undefined : bounded(reasonValue, 128);
    const requestHash = idempotencyKey === undefined ? undefined : humanCredentialMutationRequestHash("credential.revoke", {
      organization_id: scope.organizationId,
      member_id: scope.memberId,
      session_id: scope.sessionId,
      credential_id: input?.credential_id ?? input?.credentialId,
      expected_version: expectedVersion,
      revoked_at: revokedAt,
      reason: reason ?? null
    });
    try {
      return await inTransaction(async (transactionClient) => {
        await lockOrganization(transactionClient, scope.organizationId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const idempotency = idempotencyKey === undefined ? undefined : await acquireHumanCredentialIdempotency(transactionClient, {
          organizationId: scope.organizationId,
          principalId: scope.sessionId,
          idempotencyKey,
          requestHash
        });
        if (idempotency?.replayed) return idempotency.response;
        const candidate = await transactionClient.query(`SELECT c.id FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch AND c.id=$4 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$5 LIMIT 1`, [scope.sessionId, scope.memberId, scope.organizationId, credentialId, expectedVersion]);
        if (candidate.rowCount !== 1) {
          if (await credentialExistsInScope(transactionClient, scope, input?.credential_id ?? input?.credentialId)) throw versionConflict();
          return null;
        }
        const count = await transactionClient.query("SELECT count(*)::text AS active_count FROM webauthn_credentials WHERE member_id=$1 AND revoked_at IS NULL", [scope.memberId]);
        const activeCount = Number(count.rows?.[0]?.active_count);
        if (!Number.isSafeInteger(activeCount) || activeCount < 1) throw lastCredentialError();
        if (activeCount === 1) throw lastCredentialError();
        const result = await transactionClient.query(`UPDATE webauthn_credentials c SET revoked_at=$7,revoke_reason=COALESCE($6,c.revoke_reason),version=c.version+1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch AND c.id=$4 AND c.member_id=s.member_id AND c.revoked_at IS NULL AND c.version=$5 RETURNING c.id,c.member_id,c.label,c.transports,c.backup_eligible,c.backup_state,c.created_at,c.last_used_at,c.revoked_at,c.version`, [scope.sessionId, scope.memberId, scope.organizationId, credentialId, expectedVersion, reason ?? null, revokedAt]);
        const record = result.rows?.[0] ? safeCredentialRow(result.rows[0]) : null;
        if (record && input?.authority_reduction === true) await notifyAuthorityReduction(transactionClient, { ...scope, memberId: scope.memberId, actorSessionId: input?.actor_session_id ?? input?.actorSessionId ?? scope.sessionId, targetId: record.id, resource: "credential", reason, occurredAt: revokedAt });
        if (record && idempotencyKey !== undefined) await completeHumanCredentialIdempotency(transactionClient, { organizationId: scope.organizationId, principalId: scope.sessionId, idempotencyKey, requestHash, response: record, responseStatus: 200 });
        if (!record && idempotencyKey !== undefined) await abandonHumanCredentialIdempotency(transactionClient, { organizationId: scope.organizationId, principalId: scope.sessionId, idempotencyKey, requestHash });
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
      const result = await transactionClient.query(`UPDATE human_sessions target SET revoked_at=COALESCE(target.revoked_at,$4),revoke_reason=COALESCE(target.revoke_reason,$5),version=target.version+1 WHERE target.member_id=$2 AND target.organization_id=$3 AND target.id<>$1 AND target.revoked_at IS NULL AND target.expires_at>clock_timestamp() AND (target.idle_expires_at IS NULL OR target.idle_expires_at>clock_timestamp()) AND EXISTS (SELECT 1 FROM human_sessions actor JOIN memberships m ON m.organization_id=actor.organization_id AND m.member_id=actor.member_id AND m.id=actor.membership_id JOIN organizations o ON o.id=actor.organization_id WHERE actor.id=$1 AND actor.member_id=$2 AND actor.organization_id=$3 AND actor.revoked_at IS NULL AND actor.expires_at>clock_timestamp() AND (actor.idle_expires_at IS NULL OR actor.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=actor.role AND o.authority_epoch=actor.organization_authority_epoch AND m.session_epoch=actor.membership_session_epoch) AND EXISTS (SELECT 1 FROM memberships target_m JOIN organizations target_o ON target_o.id=target.organization_id WHERE target_m.id=target.membership_id AND target_m.organization_id=target.organization_id AND target_m.member_id=target.member_id AND target_m.status='active' AND target_m.role=target.role AND target_o.authority_epoch=target.organization_authority_epoch AND target_m.session_epoch=target.membership_session_epoch) RETURNING target.id AS session_id,target.member_id,target.organization_id,target.role,target.version,target.created_at,target.expires_at,target.last_seen_at,target.idle_expires_at,target.recent_auth_at,target.revoked_at,target.revoke_reason`, [sessionId, memberId, organizationId, revokedAt, reason]);
      if (!result || !Array.isArray(result.rows) || !Number.isSafeInteger(result.rowCount) || result.rowCount !== result.rows.length) throw new TypeError("other-session revocation result is invalid");
      const records = result.rows.map(safeSessionRow);
      const seen = new Set();
      for (const record of records) {
        if (record.session_id === sessionId || record.member_id !== memberId || record.organization_id !== organizationId || record.status !== "revoked" || record.revoked_at === null || seen.has(record.session_id)) throw new TypeError("other-session revocation result is not authoritative");
        seen.add(record.session_id);
      }
      // Each requested authority reduction uses the same transaction-bound
      // propagation hook. If any publication/audit step fails,
      // withTransaction rolls back the entire batch, including all session
      // rows already updated above. A zero-target no-op does not require a
      // propagation dependency, but a non-empty administrative reduction does.
      if (input?.authority_reduction === true) {
        for (const record of records) {
          await notifyAuthorityReduction(transactionClient, { organizationId, memberId, actorSessionId: sessionId, targetId: record.session_id, resource: "session", reason, occurredAt: revokedAt });
        }
      }
      return records;
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
      const result = await transactionClient.query(`UPDATE human_sessions target SET revoked_at=$6,revoke_reason=$7,version=target.version+1 WHERE target.id=$4 AND target.member_id=$2 AND target.organization_id=$3 AND target.revoked_at IS NULL AND target.version=$5 AND EXISTS (SELECT 1 FROM human_sessions actor JOIN memberships m ON m.organization_id=actor.organization_id AND m.member_id=actor.member_id AND m.id=actor.membership_id JOIN organizations o ON o.id=actor.organization_id WHERE actor.id=$1 AND actor.member_id=$2 AND actor.organization_id=$3 AND actor.revoked_at IS NULL AND actor.expires_at>clock_timestamp() AND (actor.idle_expires_at IS NULL OR actor.idle_expires_at>clock_timestamp()) AND m.status='active' AND m.role=actor.role AND o.authority_epoch=actor.organization_authority_epoch AND m.session_epoch=actor.membership_session_epoch) AND EXISTS (SELECT 1 FROM memberships target_m JOIN organizations target_o ON target_o.id=target.organization_id WHERE target_m.id=target.membership_id AND target_m.organization_id=target.organization_id AND target_m.member_id=target.member_id AND target_m.status='active' AND target_m.role=target.role AND target_o.authority_epoch=target.organization_authority_epoch AND target_m.session_epoch=target.membership_session_epoch) RETURNING target.id AS session_id,target.member_id,target.organization_id,target.role,target.version,target.created_at,target.expires_at,target.last_seen_at,target.idle_expires_at,target.recent_auth_at,target.revoked_at,target.revoke_reason`, [actorSessionId, memberId, organizationId, targetSessionId, expectedVersion, revokedAt, reason]);
      if (result.rowCount === 0) {
        const exists = await transactionClient.query("SELECT 1 FROM human_sessions s JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch LIMIT 1", [targetSessionId, memberId, organizationId]);
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
    const result = await transactionClient.query(`SELECT 1 FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id AND m.id=s.membership_id JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.status='active' AND m.role=s.role AND o.authority_epoch=s.organization_authority_epoch AND m.session_epoch=s.membership_session_epoch AND c.id=$4 AND c.revoked_at IS NULL LIMIT 1`, [scope.sessionId, scope.memberId, scope.organizationId, base64Bytes(credentialValue, 16, 1024)]);
    return result.rowCount === 1;
  }

  async function acquireHumanCredentialIdempotency(tx, { organizationId, principalId, idempotencyKey, requestHash }) {
    await tx.query(`DELETE FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
        AND expires_at<=clock_timestamp()`, [organizationId, principalId, idempotencyKey]);
    const inserted = await tx.query(`INSERT INTO idempotency_records
      (organization_id,principal_id,idempotency_key,request_hash,response_status,response_json,expires_at)
      VALUES ($1,$2,$3,$4,102,'{}'::jsonb,clock_timestamp()+$5::interval)
      ON CONFLICT (organization_id,principal_id,idempotency_key) DO NOTHING`, [organizationId, principalId, idempotencyKey, requestHash, IDEMPOTENCY_TTL]);
    const record = await tx.query(`SELECT request_hash,response_status,response_json
      FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
      FOR UPDATE`, [organizationId, principalId, idempotencyKey]);
    if ((record.rowCount ?? record.rows?.length ?? 0) !== 1) throw idempotencyUnavailable();
    const row = record.rows[0];
    if (String(row.request_hash).toLowerCase() !== requestHash) throw idempotencyConflict();
    if ((inserted.rowCount ?? inserted.rows?.length ?? 0) !== 1) return { replayed: true, response: replayCredentialResponse(row.response_json) };
    return { replayed: false };
  }

  async function completeHumanCredentialIdempotency(tx, { organizationId, principalId, idempotencyKey, requestHash, response, responseStatus }) {
    const result = await tx.query(`UPDATE idempotency_records
      SET response_status=$4,response_json=$5::jsonb
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND request_hash=$6`, [organizationId, principalId, idempotencyKey, responseStatus, JSON.stringify(response), requestHash]);
    if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) throw idempotencyUnavailable();
  }

  async function abandonHumanCredentialIdempotency(tx, { organizationId, principalId, idempotencyKey, requestHash }) {
    const result = await tx.query(`DELETE FROM idempotency_records
      WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND request_hash=$4`, [organizationId, principalId, idempotencyKey, requestHash]);
    if ((result.rowCount ?? result.rows?.length ?? 0) !== 1) throw idempotencyUnavailable();
  }
}

function validateSession(record) { uuid(record?.session_id); uuid(record?.member_id); uuid(record?.membership_id); uuid(record?.organization_id); if (!["owner", "admin", "auditor", "viewer"].includes(record.role)) throw new TypeError("session role is invalid"); bytes32(record.token_hash); bytes32(record.csrf_token_hash); }
function sessionRow(row) {
  return row ? {
    ...row,
    session_id: row.session_id ?? row.id,
    token_hash: row.token_hash_hex ?? row.token_hash,
    csrf_token_hash: row.csrf_token_hash_hex ?? row.csrf_token_hash,
    created_at: storedTimestamp(row.created_at, "created_at"),
    expires_at: storedTimestamp(row.expires_at, "expires_at"),
    last_seen_at: storedTimestamp(row.last_seen_at, "last_seen_at"),
    idle_expires_at: nullableStoredTimestamp(row.idle_expires_at, "idle_expires_at"),
    recent_auth_at: nullableStoredTimestamp(row.recent_auth_at, "recent_auth_at"),
    revoked_at: nullableStoredTimestamp(row.revoked_at, "revoked_at")
  } : null;
}
function storedTimestamp(value, name) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === "string" && Number.isFinite(Date.parse(value))) return value;
  throw new TypeError(`${name} is invalid`);
}
function nullableStoredTimestamp(value, name) { return value === null || value === undefined ? null : storedTimestamp(value, name); }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("UUID is invalid"); return value.toLowerCase(); }
function bounded(value, max) { if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("bounded text is invalid"); return value; }
function identityProvider(value) { if (typeof value !== "string" || !PROVIDER.test(value)) throw new TypeError("identity provider is invalid"); return value; }
function identitySubject(value) { if (typeof value !== "string" || !SUBJECT.test(value) || value.trim() !== value) throw new TypeError("identity subject is invalid"); return value; }
function uuidUserHandle(value) { return Buffer.from(value.replaceAll("-", ""), "hex").toString("base64url"); }
function bytes32(value) { if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("digest is invalid"); return Buffer.from(value, "hex"); }
function contextHashBytes(value) { if (value === undefined) return null; if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("context_hash is invalid"); return Buffer.from(value, "hex"); }
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
function safeCredentialRow(row) { return { id: credentialId(row.id), member_id: uuid(String(row.member_id)), label: credentialLabel(row.label), transports: credentialTransports(row.transports), backup_eligible: strictBoolean(row.backup_eligible, "backup_eligible"), backup_state: strictBoolean(row.backup_state, "backup_state"), created_at: storedTimestamp(row.created_at, "created_at"), last_used_at: nullableStoredTimestamp(row.last_used_at, "last_used_at"), revoked_at: nullableStoredTimestamp(row.revoked_at ?? row.clone_detected_at, "revoked_at"), version: positiveInteger(row.version) }; }
function safeSessionRow(row) { const sessionId = uuid(String(row.session_id ?? row.id)); const memberId = uuid(String(row.member_id)); const organizationId = uuid(String(row.organization_id)); return { session_id: sessionId, member_id: memberId, organization_id: organizationId, role: membershipRole(row.role), version: positiveInteger(row.version ?? 1), created_at: storedTimestamp(row.created_at, "created_at"), expires_at: storedTimestamp(row.expires_at, "expires_at"), last_seen_at: nullableStoredTimestamp(row.last_seen_at, "last_seen_at"), idle_expires_at: nullableStoredTimestamp(row.idle_expires_at, "idle_expires_at"), recent_auth_at: nullableStoredTimestamp(row.recent_auth_at, "recent_auth_at"), revoked_at: nullableStoredTimestamp(row.revoked_at, "revoked_at"), revoke_reason: row.revoke_reason ?? null, status: row.revoked_at ? "revoked" : "active" }; }
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
function recentAuthRequired() { const error = new Error("recent authentication is required"); error.code = "recent_auth_required"; return error; }
function optionalIdempotencyKey(value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new TypeError("idempotency_key is invalid");
  return value;
}
function humanCredentialMutationRequestHash(operation, identity) {
  return createHash("sha256").update(stableCanonicalize({ version: 1, operation, identity }), "utf8").digest("hex");
}
function stableCanonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Number.isSafeInteger(value) || typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCanonicalize).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("canonical identity contains an invalid value");
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableCanonicalize(value[key])}`).join(",")}}`;
}
function replayCredentialResponse(value) {
  const response = typeof value === "string" ? JSON.parse(value) : value;
  if (!response || typeof response !== "object" || Array.isArray(response)) throw idempotencyUnavailable();
  return response;
}
function idempotencyConflict() { const error = new Error("idempotency key was already used for a different request"); error.code = "ERR_IDEMPOTENCY_CONFLICT"; return error; }
function idempotencyUnavailable() { const error = new Error("idempotency response could not be acquired"); error.code = "ERR_IDEMPOTENCY"; return error; }
function parseDatabaseCount(value, label) { const count = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; if (!Number.isSafeInteger(count) || count < 0) throw new TypeError(`${label} is invalid`); return count; }
