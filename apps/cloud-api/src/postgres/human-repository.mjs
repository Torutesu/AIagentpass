const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_32 = /^[0-9a-f]{64}$/;

export function createPostgresHumanRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid");
  return Object.freeze({ createSession, findSessionByTokenHash, updateSessionActivity, revokeSession, listSessions, bindRecentAuth, consumeRecentAuth, findCredentialForSession, updateCredentialCounter });

  async function createSession(record) {
    validateSession(record);
    const result = await client.query(`INSERT INTO human_sessions (id,member_id,organization_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at,recent_auth_at,revoked_at,revoke_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,NULL) RETURNING *,encode(token_hash,'hex') AS token_hash_hex,encode(csrf_token_hash,'hex') AS csrf_token_hash_hex`, [record.session_id, record.member_id, record.organization_id, record.role, bytes32(record.token_hash), bytes32(record.csrf_token_hash), record.created_at, record.expires_at, record.last_seen_at, record.idle_expires_at]);
    return sessionRow(result.rows?.[0]);
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

  async function bindRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions SET recent_auth_at=$6,recent_auth_challenge_id=$5,recent_auth_organization_id=$3,recent_auth_operation=$4,recent_auth_consumed_at=NULL WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND revoked_at IS NULL AND expires_at>$6 RETURNING id`, [uuid(input.session_id), uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), input.authenticated_at]);
    return result.rowCount === 1;
  }

  async function consumeRecentAuth(input) {
    const result = await client.query(`UPDATE human_sessions SET recent_auth_consumed_at=$5 WHERE member_id=$1 AND recent_auth_organization_id=$2 AND recent_auth_operation=$3 AND recent_auth_challenge_id=$4 AND recent_auth_consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$5 AND recent_auth_at>$5-INTERVAL '5 minutes' RETURNING recent_auth_at AS authenticated_at`, [uuid(input.member_id), uuid(input.organization_id), bounded(input.operation, 128), uuid(input.challenge_id), input.consumed_at]);
    return result.rowCount === 1 ? result.rows[0] : null;
  }

  async function findCredentialForSession(input) {
    const result = await client.query(`SELECT c.id,c.public_key,c.sign_count,c.transports,c.revoked_at FROM webauthn_credentials c JOIN human_sessions s ON s.member_id=c.member_id JOIN memberships m ON m.organization_id=s.organization_id AND m.member_id=s.member_id WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND s.revoked_at IS NULL AND c.revoked_at IS NULL AND m.status='active' LIMIT 1`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024)]);
    const row = result.rows?.[0];
    return row ? { ...row, id: Buffer.from(row.id).toString("base64url") } : null;
  }

  async function updateCredentialCounter(input) {
    const result = await client.query(`UPDATE webauthn_credentials c SET sign_count=$4,last_used_at=clock_timestamp() FROM human_sessions s WHERE s.id=$1 AND s.organization_id=$2 AND c.id=$3 AND c.member_id=s.member_id AND c.sign_count=$5 AND c.revoked_at IS NULL RETURNING c.id`, [uuid(input.session_id), uuid(input.organization_id), base64Bytes(input.credential_id, 16, 1024), counter(input.sign_count), counter(input.expected_sign_count)]);
    return result.rowCount === 1;
  }
}

function validateSession(record) { uuid(record?.session_id); uuid(record?.member_id); uuid(record?.organization_id); if (!["owner", "admin", "auditor", "viewer"].includes(record.role)) throw new TypeError("session role is invalid"); bytes32(record.token_hash); bytes32(record.csrf_token_hash); }
function sessionRow(row) { return row ? { ...row, session_id: row.session_id ?? row.id, token_hash: row.token_hash_hex ?? row.token_hash, csrf_token_hash: row.csrf_token_hash_hex ?? row.csrf_token_hash } : null; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("UUID is invalid"); return value.toLowerCase(); }
function bounded(value, max) { if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("bounded text is invalid"); return value; }
function bytes32(value) { if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("digest is invalid"); return Buffer.from(value, "hex"); }
function base64Bytes(value, min, max) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("credential id is invalid"); const bytes=Buffer.from(value,"base64url"); if(bytes.length<min||bytes.length>max||bytes.toString("base64url")!==value) throw new TypeError("credential id is invalid"); return bytes; }
function counter(value) { if (!Number.isSafeInteger(value)||value<0) throw new TypeError("counter is invalid"); return value; }
