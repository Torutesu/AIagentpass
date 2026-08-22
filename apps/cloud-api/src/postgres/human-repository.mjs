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
    logoutSession,
    switchSessionOrganization,
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
    const created = await createSessionThroughAuthority(client, record);
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
      const created = await createSessionThroughAuthority(transactionClient, record, { limit, issuedAt, reason });
      if (!created) throw new TypeError("active session membership is unavailable");
      return created;
    });
  }

  async function createSessionThroughAuthority(transactionClient, record, { limit = null, issuedAt = null, reason = null } = {}) {
    const withCeiling = limit !== null;
    const sql = withCeiling
      ? "SELECT public.agentpass_human_session_create_with_ceiling($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::text,$6::bytea,$7::bytea,$8::timestamptz,$9::timestamptz,$10::timestamptz,$11::timestamptz,$12::integer,$13::text,$14::timestamptz) AS session"
      : "SELECT public.agentpass_human_session_create($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::text,$6::bytea,$7::bytea,$8::timestamptz,$9::timestamptz,$10::timestamptz,$11::timestamptz) AS session";
    const params = [record.session_id, record.member_id, record.organization_id, record.membership_id, record.role, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at];
    if (withCeiling) params.push(limit, reason, issuedAt);
    const result = await transactionClient.query(
      sql,
      params
    );
    return sessionRow(result.rows?.[0]?.session);
  }

  async function rotateSession(input) {
    const oldSessionId = uuid(input?.old_session_id ?? input?.oldSessionId);
    const oldTokenHash = bytes32(input?.old_token_hash ?? input?.oldTokenHash);
    const record = input?.session;
    validateSession(record);
    const rotatedAt = timestamp(input?.rotated_at ?? input?.rotatedAt);
    const reason = bounded(input?.reason ?? "session_rotation", 128);

    const result = await client.query(
      "SELECT public.agentpass_human_session_rotate($1::uuid,$2::bytea,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::text,$8::bytea,$9::bytea,$10::timestamptz,$11::timestamptz,$12::timestamptz,$13::timestamptz,$14::timestamptz,$15::text) AS session",
      [oldSessionId, oldTokenHash, record.session_id, record.member_id, record.organization_id, record.membership_id, record.role, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at, rotatedAt, reason]
    );
    return sessionRow(result.rows?.[0]?.session);
  }

  /**
   * Revoke the session represented by a logout cookie as one serialized
   * operation.  The initial token lookup happens in the service so CSRF and
   * expiry checks remain unchanged; this second, authoritative step takes the
   * same member lock as rotateSession.  If rotation won the race, the old row
   * contains an exact successor link and only that lineage is followed.
   */
  async function logoutSession(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const tokenHash = bytes32(input?.token_hash ?? input?.tokenHash);
    const revokedAt = timestamp(input?.revoked_at ?? input?.revokedAt);
    const reason = bounded(input?.revoke_reason ?? input?.revokeReason ?? input?.reason ?? "logout", 128);
    const result = await client.query(
      "SELECT public.agentpass_human_session_logout($1::uuid,$2::uuid,$3::uuid,$4::bytea,$5::timestamptz,$6::text) AS session",
      [sessionId, memberId, organizationId, tokenHash, revokedAt, reason]
    );
    return sessionRow(result.rows?.[0]?.session);
  }

  async function switchSessionOrganization(input) {
    const oldSessionId = uuid(input?.old_session_id ?? input?.oldSessionId);
    const oldTokenHash = bytes32(input?.old_token_hash ?? input?.oldTokenHash);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const oldOrganizationId = uuid(input?.old_organization_id ?? input?.oldOrganizationId);
    const targetOrganizationId = uuid(input?.target_organization_id ?? input?.targetOrganizationId);
    const record = input?.session;
    if (!record || typeof record !== "object") throw new TypeError("switch session record is invalid");
    const sessionId = uuid(record.session_id);
    const createdAt = timestamp(record.created_at);
    const expiresAt = timestamp(record.expires_at);
    const lastSeenAt = timestamp(record.last_seen_at);
    const idleExpiresAt = timestamp(record.idle_expires_at);
    const switchedAt = timestamp(input?.switched_at ?? input?.switchedAt);
    const reason = bounded(input?.reason ?? "organization_switch", 128);
    const result = await client.query(
      "SELECT public.agentpass_human_session_switch($1::uuid,$2::bytea,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bytea,$8::bytea,$9::timestamptz,$10::timestamptz,$11::timestamptz,$12::timestamptz,$13::timestamptz,$14::text) AS session",
      [oldSessionId, oldTokenHash, sessionId, memberId, oldOrganizationId, targetOrganizationId, bytes32(record.token_hash), bytes32(record.csrf_token_hash), createdAt, expiresAt, lastSeenAt, idleExpiresAt, switchedAt, reason]
    );
    return sessionRow(result.rows?.[0]?.session);
  }

  async function findSessionByTokenHash(input) {
    const result = await client.query("SELECT public.agentpass_human_session_find_by_token($1::bytea) AS session", [bytes32(input.token_hash ?? input.tokenHash)]);
    return sessionRow(result.rows?.[0]?.session);
  }

  async function updateSessionActivity(input) {
    const result = await client.query("SELECT public.agentpass_human_session_touch($1::uuid,$2::timestamptz,$3::timestamptz) AS session", [uuid(input.session_id ?? input.sessionId), input.last_seen_at ?? input.lastSeenAt, input.idle_expires_at ?? input.idleExpiresAt]);
    return sessionRow(result.rows?.[0]?.session);
  }

  async function revokeSession(input) {
    const result = await client.query(
      "SELECT public.agentpass_human_session_revoke($1::uuid,$2::timestamptz,$3::text) AS session",
      [uuid(input.session_id ?? input.sessionId), input.revoked_at ?? input.revokedAt, bounded(input.revoke_reason ?? input.reason, 128)]
    );
    return sessionRow(result.rows?.[0]?.session);
  }

  async function listSessions(input) {
    const result = await client.query(
      "SELECT public.agentpass_human_session_list($1::uuid) AS session",
      [uuid(input.member_id ?? input.memberId)]
    );
    return (result.rows ?? []).map((row) => sessionRow(row.session));
  }

  async function listSafeSessions(input) {
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationValue = input?.organization_id ?? input?.organizationId;
    const organizationId = organizationValue === undefined ? undefined : uuid(organizationValue);
    const paging = keysetPagination(input, DEFAULT_MANAGEMENT_PAGE_SIZE, "session");
    const result = await client.query(
      "SELECT public.agentpass_human_session_list_safe($1::uuid,$2::uuid,$3::timestamptz,$4::uuid,$5::integer) AS session",
      [memberId, organizationId ?? null, paging.after?.createdAt ?? null, paging.after?.id ?? null, paging.limit + 1]
    );
    return (result.rows ?? []).map((row) => safeSessionRow(row.session));
  }

  async function bindRecentAuth(input) {
    const result = await client.query(
      "SELECT public.agentpass_human_session_bind_recent_auth($1::uuid,$2::uuid,$3::uuid,$4::text,$5::uuid,$6::bytea,$7::timestamptz) AS bound",
      [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), contextHashBytes(input.context_hash), input.authenticated_at]
    );
    return result.rows?.[0]?.bound === true;
  }

  async function consumeRecentAuth(input) {
    const result = await client.query(
      "SELECT public.agentpass_human_session_consume_recent_auth($1::uuid,$2::uuid,$3::uuid,$4::text,$5::uuid,$6::bytea,$7::timestamptz) AS authorization",
      [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), contextHashBytes(input.context_hash), input.consumed_at]
    );
    return result.rows?.[0]?.authorization ?? null;
  }

  async function createUpstreamIdentity(input) {
    const provider = identityProvider(input?.provider);
    const subject = identitySubject(input?.subject);
    const memberId = uuid(input?.member_id ?? input?.memberId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const result = await client.query(
      "SELECT public.agentpass_human_identity_bind($1::text,$2::text,$3::uuid,$4::uuid) AS result",
      [provider, subject, memberId, organizationId]
    );
    const status = result.rows?.[0]?.result;
    if (result.rowCount !== 1 || !["created", "already_exists"].includes(status)) throw new TypeError("identity bind result is invalid");
    const identity = await findUpstreamIdentity({ provider, subject });
    if (!identity || identity.member_id !== memberId) throw upstreamIdentityConflict();
    return identity;
  }

  async function findUpstreamIdentity(input) {
    const result = await client.query(
      "SELECT * FROM public.agentpass_human_identity_find($1::text,$2::text)",
      [identityProvider(input?.provider), identitySubject(input?.subject)]
    );
    return result.rows?.[0] ? upstreamIdentityRow(result.rows[0]) : null;
  }

  async function listMembershipsForUpstreamIdentity(input) {
    const provider = identityProvider(input?.provider);
    const subject = identitySubject(input?.subject);
    const organizationId = input?.organization_id ?? input?.organizationId;
    const result = await client.query(
      "SELECT * FROM public.agentpass_human_identity_list_memberships($1::text,$2::text,$3::uuid)",
      [provider, subject, organizationId === undefined ? null : uuid(organizationId)]
    );
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
    const result = await client.query(
      "SELECT * FROM public.agentpass_human_get_registration_user($1::uuid,$2::uuid,$3::uuid)",
      [uuid(input?.session_id ?? input?.sessionId), uuid(input?.member_id ?? input?.memberId), uuid(input?.organization_id ?? input?.organizationId)]
    );
    const row = result.rows?.[0];
    if (!row) return null;
    const memberId = uuid(String(row.member_id));
    return { id: uuidUserHandle(memberId), name: `agentpass:${memberId}`, display_name: bounded(row.display_name ?? "AgentPass user", 128) };
  }

  async function listCredentialsForSession(input) {
    const result = await client.query("SELECT * FROM public.agentpass_human_list_credentials_for_session($1::uuid,$2::uuid)", [uuid(input.session_id), uuid(input.organization_id)]);
    return (result.rows ?? []).map((row) => ({ id: credentialId(row.id), type: "public-key", transports: credentialTransports(row.transports) }));
  }

  async function findCredentialForSession(input) {
    const result = await client.query("SELECT * FROM public.agentpass_human_find_credential_for_session($1::uuid,$2::uuid,$3::bytea)", [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024)]);
    const row = result.rows?.[0];
    return row ? { ...row, id: Buffer.from(row.id).toString("base64url"), sign_count: storedCounter(row.sign_count), backup_eligible: strictBoolean(row.backup_eligible, "backup_eligible"), backup_state: strictBoolean(row.backup_state, "backup_state") } : null;
  }

  async function listCredentialMetadataForSession(input) {
    const scope = credentialScope(input);
    const paging = keysetPagination(input, DEFAULT_MANAGEMENT_PAGE_SIZE, "credential");
    const result = await client.query(
      "SELECT * FROM public.agentpass_human_list_credential_metadata_for_session($1::uuid,$2::uuid,$3::uuid,$4::timestamptz,$5::uuid,$6::integer)",
      [scope.sessionId, scope.memberId, scope.organizationId, paging.after?.createdAt ?? null, paging.after?.id ?? null, paging.limit]
    );
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
    const result = await client.query(
      "SELECT * FROM public.agentpass_human_register_credential($1::uuid,$2::uuid,$3::uuid,$4::bytea,$5::bytea,$6::bigint,$7::text[],$8::text,$9::boolean,$10::boolean)",
      [sessionId, memberId, organizationId, credentialId, publicKey, signCount, transports, label, backupEligible, backupState]
    );
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
    const duplicate = await client.query(
      "SELECT * FROM public.agentpass_human_credential_registration_status($1::uuid,$2::uuid,$3::uuid,$4::bytea)",
      [sessionId, memberId, organizationId, base64Bytes(credentialId, 16, 1024)]
    );
    if (duplicate.rows?.[0]?.credential_exists === true) throw credentialExists();
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
      await lockHumanAuthority(transactionClient, memberId);
      await lockOrganization(transactionClient, organizationId);
      await lockSessionSet(transactionClient, memberId);
      await lockCredentialSet(transactionClient, memberId);
      const active = await transactionClient.query(
        "SELECT * FROM public.agentpass_human_credential_registration_status($1::uuid,$2::uuid,$3::uuid,$4::bytea)",
        [sessionId, memberId, organizationId, credentialId]
      );
      if (active.rowCount !== 1) throw recentAuthRequired();
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
        const consumed = await transactionClient.query(
          "SELECT public.agentpass_human_session_consume_recent_auth($1::uuid,$2::uuid,$3::uuid,$4::text,$5::uuid,$6::bytea,$7::timestamptz) AS authorization",
          [sessionId, memberId, organizationId, operation, authorizationId, contextHashBytes(recentAuth?.context_hash), new Date().toISOString()]
        );
        if (consumed.rows?.[0]?.authorization === null || consumed.rows?.[0]?.authorization === undefined) throw recentAuthRequired();
      }

      const inserted = await transactionClient.query(
        "SELECT * FROM public.agentpass_human_register_credential($1::uuid,$2::uuid,$3::uuid,$4::bytea,$5::bytea,$6::bigint,$7::text[],$8::text,$9::boolean,$10::boolean)",
        [sessionId, memberId, organizationId, credentialId, publicKey, signCount, transports, label, backupEligible, backupState]
      );
      if (inserted.rowCount === 1) return Object.freeze({ created: true, credential_id: credentialId.toString("base64url"), authorized: true });
      const duplicate = await transactionClient.query(
        "SELECT * FROM public.agentpass_human_credential_registration_status($1::uuid,$2::uuid,$3::uuid,$4::bytea)",
        [sessionId, memberId, organizationId, credentialId]
      );
      if (duplicate.rows?.[0]?.credential_exists === true) throw credentialExists();
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
    const result = await client.query(
      "SELECT public.agentpass_human_update_credential_counter($1::uuid,$2::uuid,$3::bytea,$4::bigint,$5::bigint,$6::boolean,$7::boolean,$8::boolean,$9::boolean) AS updated",
      [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024), nextCount, counter(input.expected_sign_count), backupEligible, backupState, expectedBackupEligible, expectedBackupState]
    );
    return result.rows?.[0]?.updated === true;
  }

  async function quarantineCredentialClone(input) {
    const sessionId = uuid(input?.session_id ?? input?.sessionId);
    const organizationId = uuid(input?.organization_id ?? input?.organizationId);
    const credentialValue = input?.credential_id ?? input?.credentialId;
    const expectedCount = counter(input?.expected_sign_count ?? input?.expectedSignCount);
    const observedCount = counter(input?.observed_sign_count ?? input?.observedSignCount);
    if ((expectedCount === 0 && observedCount === 0) || observedCount > expectedCount) throw new TypeError("clone counter evidence is invalid");
    return inTransaction(async (transactionClient) => {
      const result = await transactionClient.query(
        "SELECT * FROM public.agentpass_human_quarantine_credential_clone($1::uuid,$2::uuid,$3::bytea,$4::bigint,$5::bigint)",
        [sessionId, organizationId, base64Bytes(credentialValue, 16, 1024), expectedCount, observedCount]
      );
      if (result.rowCount !== 1) return false;
      const detectedAt = storedTimestamp(result.rows[0].clone_detected_at, "clone_detected_at");
      const memberId = uuid(String(result.rows[0].member_id));
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
        await lockHumanAuthority(transactionClient, scope.memberId);
        await lockOrganization(transactionClient, scope.organizationId);
        await lockSessionSet(transactionClient, scope.memberId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const idempotency = idempotencyKey === undefined ? undefined : await acquireHumanCredentialIdempotency(transactionClient, {
          organizationId: scope.organizationId,
          principalId: scope.sessionId,
          idempotencyKey,
          requestHash
        });
        if (idempotency?.replayed) return idempotency.response;
        const result = await transactionClient.query(
          "SELECT * FROM public.agentpass_human_update_credential_label($1::uuid,$2::uuid,$3::uuid,$4::bytea,$5::text,$6::bigint)",
          [scope.sessionId, scope.memberId, scope.organizationId, base64Bytes(input?.credential_id ?? input?.credentialId, 16, 1024), label, expectedVersion]
        );
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
        await lockHumanAuthority(transactionClient, scope.memberId);
        await lockOrganization(transactionClient, scope.organizationId);
        await lockSessionSet(transactionClient, scope.memberId);
        await lockCredentialSet(transactionClient, scope.memberId);
        const idempotency = idempotencyKey === undefined ? undefined : await acquireHumanCredentialIdempotency(transactionClient, {
          organizationId: scope.organizationId,
          principalId: scope.sessionId,
          idempotencyKey,
          requestHash
        });
        if (idempotency?.replayed) return idempotency.response;
        const result = await transactionClient.query(
          "SELECT * FROM public.agentpass_human_revoke_credential($1::uuid,$2::uuid,$3::uuid,$4::bytea,$5::bigint,$6::timestamptz,$7::text)",
          [scope.sessionId, scope.memberId, scope.organizationId, credentialId, expectedVersion, revokedAt, reason ?? null]
        );
        if (result.rowCount === 0) {
          if (await credentialExistsInScope(transactionClient, scope, input?.credential_id ?? input?.credentialId)) throw versionConflict();
          return null;
        }
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
      const result = await transactionClient.query(
        "SELECT public.agentpass_human_session_revoke_others($1::uuid,$2::uuid,$3::uuid,$4::timestamptz,$5::text) AS sessions",
        [sessionId, memberId, organizationId, revokedAt, reason]
      );
      if (!result || !Array.isArray(result.rows) || !Number.isSafeInteger(result.rowCount) || result.rowCount !== result.rows.length) throw new TypeError("other-session revocation result is invalid");
      const rows = result.rows?.[0]?.sessions ?? [];
      if (!Array.isArray(rows)) throw new TypeError("other-session revocation result is invalid");
      const records = rows.map(safeSessionRow);
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
      const result = await transactionClient.query(
        "SELECT public.agentpass_human_session_revoke_managed($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bigint,$6::timestamptz,$7::text) AS session",
        [actorSessionId, targetSessionId, memberId, organizationId, expectedVersion, revokedAt, reason]
      );
      const record = result.rows?.[0]?.session ? safeSessionRow(result.rows[0].session) : null;
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

  async function lockHumanAuthority(transactionClient, memberId) {
    await transactionClient.query("SELECT pg_advisory_xact_lock(hashtextextended('agentpass:human:authority:' || $1::text, 0)) AS locked", [memberId]);
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
    const result = await transactionClient.query(
      "SELECT * FROM public.agentpass_human_find_credential_for_session($1::uuid,$2::uuid,$3::bytea)",
      [scope.sessionId, scope.organizationId, base64Bytes(credentialValue, 16, 1024)]
    );
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
    revoked_at: nullableStoredTimestamp(row.revoked_at, "revoked_at"),
    revoke_reason: visibleRevokeReason(row.revoke_reason)
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
function identitySubject(value) { if (typeof value !== "string" || !SUBJECT.test(value) || Buffer.byteLength(value, "utf8") > 512 || value.trim() !== value) throw new TypeError("identity subject is invalid"); return value; }
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
function safeSessionRow(row) { const sessionId = uuid(String(row.session_id ?? row.id)); const memberId = uuid(String(row.member_id)); const organizationId = uuid(String(row.organization_id)); return { session_id: sessionId, member_id: memberId, organization_id: organizationId, role: membershipRole(row.role), version: positiveInteger(row.version ?? 1), created_at: storedTimestamp(row.created_at, "created_at"), expires_at: storedTimestamp(row.expires_at, "expires_at"), last_seen_at: nullableStoredTimestamp(row.last_seen_at, "last_seen_at"), idle_expires_at: nullableStoredTimestamp(row.idle_expires_at, "idle_expires_at"), recent_auth_at: nullableStoredTimestamp(row.recent_auth_at, "recent_auth_at"), revoked_at: nullableStoredTimestamp(row.revoked_at, "revoked_at"), revoke_reason: visibleRevokeReason(row.revoke_reason), status: row.revoked_at ? "revoked" : "active" }; }
function rotationSuccessorId(reason) {
  if (typeof reason !== "string") return null;
  const separator = reason.indexOf(":");
  if (separator < 1 || !new Set(["session_rotation", "organization_switch"]).has(reason.slice(0, separator))) return null;
  const candidate = reason.slice(separator + 1);
  return UUID.test(candidate) ? candidate.toLowerCase() : null;
}
function visibleRevokeReason(reason) {
  if (rotationSuccessorId(reason) === null) return reason ?? null;
  return String(reason).slice(0, String(reason).indexOf(":"));
}
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
