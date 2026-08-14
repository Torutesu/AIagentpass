#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { chmod, lstat, open, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { loadSqlMigrations } from "../../apps/cloud-api/src/postgres/migration-runner.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const ZERO_HASH = "0".repeat(64);

// Values are selected through to_jsonb(t), so a newly added column is covered
// by the row digest without ever being copied into the manifest. The table
// names and predicates are reviewed constants, not caller-controlled SQL.
const AUTHORITY_TABLES = Object.freeze([
  ["organizations", "t.id = ANY($1::uuid[])", "tenant"],
  ["members", "EXISTS (SELECT 1 FROM memberships mt WHERE mt.organization_id = ANY($1::uuid[]) AND mt.member_id = t.id)", "member"],
  ["memberships", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["human_sessions", "t.organization_id = ANY($1::uuid[]) OR EXISTS (SELECT 1 FROM memberships mt WHERE mt.organization_id = ANY($1::uuid[]) AND mt.member_id = t.member_id)", "human"],
  ["webauthn_credentials", "EXISTS (SELECT 1 FROM memberships mt WHERE mt.organization_id = ANY($1::uuid[]) AND mt.member_id = t.member_id)", "human"],
  ["webauthn_challenges", "t.organization_id = ANY($1::uuid[])", "human"],
  ["upstream_identities", "EXISTS (SELECT 1 FROM memberships mt WHERE mt.organization_id = ANY($1::uuid[]) AND mt.member_id = t.member_id)", "human"],
  ["devices", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["device_enrollments", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["release_candidates", "$1::uuid[] IS NOT NULL", "security"],
  ["device_enrollment_possession_receipts", "t.organization_id = ANY($1::uuid[])", "security"],
  ["agents", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["agent_session_grants", "t.organization_id = ANY($1::uuid[])", "security"],
  ["agent_sessions", "t.organization_id = ANY($1::uuid[])", "security"],
  ["qualification_grant_control_heads", "t.organization_id = ANY($1::uuid[])", "security"],
  ["qualification_grant_batches", "t.organization_id = ANY($1::uuid[])", "security"],
  ["qualification_grant_batch_steps", "t.organization_id = ANY($1::uuid[])", "security"],
  ["cloud_agent_audit_heads", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["cloud_agent_audit_events", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["policies", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["revocations", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["capabilities", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["bundle_heads", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["bundle_acknowledgements", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["admin_audit_heads", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["admin_audit_events", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["outbox_events", "t.organization_id = ANY($1::uuid[])", "outbox"],
  ["organization_invitations", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["device_audit_events", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["device_audit_heads", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["device_audit_gaps", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["idempotency_records", "t.organization_id = ANY($1::uuid[])", "security"],
  ["device_request_nonces", "t.organization_id = ANY($1::uuid[])", "security"],
  ["rate_limit_buckets", "t.organization_id = ANY($1::uuid[])", "security"],
  ["anonymous_rate_limit_buckets", "$1::uuid[] IS NOT NULL", "security"],
  ["human_identity_assertion_replays", "$1::uuid[] IS NOT NULL", "replay"],
  ["owner_recovery_requests", "t.organization_id = ANY($1::uuid[])", "human"],
  ["owner_recovery_approvals", "t.organization_id = ANY($1::uuid[])", "human"],
  ["owner_recovery_exchanges", "t.organization_id = ANY($1::uuid[])", "human"],
  ["owner_recovery_sessions", "t.organization_id = ANY($1::uuid[])", "human"],
  ["owner_recovery_outbox", "t.organization_id = ANY($1::uuid[])", "outbox"],
  ["owner_recovery_outbox_retention_ledger", "t.organization_id = ANY($1::uuid[])", "audit"],
  ["owner_recovery_webauthn_challenges", "t.organization_id = ANY($1::uuid[])", "human"],
  ["owner_recovery_idempotency_records", "t.organization_id = ANY($1::uuid[])", "security"],
  ["control_plane_authority_generations", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["device_key_epochs", "t.organization_id = ANY($1::uuid[])", "security"],
  ["device_control_plane_state", "t.organization_id = ANY($1::uuid[])", "tenant"],
  ["control_bundle_statements", "t.organization_id = ANY($1::uuid[])", "security"],
  ["device_refresh_outbox", "t.organization_id = ANY($1::uuid[])", "outbox"],
  ["device_refresh_delivery_attempts", "t.organization_id = ANY($1::uuid[])", "outbox"],
  ["device_bundle_acknowledgements", "t.organization_id = ANY($1::uuid[])", "security"],
  ["device_manual_wake_events", "t.organization_id = ANY($1::uuid[])", "outbox"],
  ["device_manual_wake_requests", "t.organization_id = ANY($1::uuid[])", "security"],
  ["schema_migration_attempts", "$1::uuid[] IS NOT NULL", "migration"]
]);
const AUTHORITY_TABLE_NAMES = Object.freeze(AUTHORITY_TABLES.map(([name]) => name));
const TENANT_TABLE_NAMES = new Set(AUTHORITY_TABLES.filter(([, , kind]) => ["tenant", "audit", "outbox", "security"].includes(kind)).map(([name]) => name));

export const AUTHORITY_MANIFEST_SCHEMA_VERSION = 2;
export const REQUIRED_MIGRATION_VERSION = "33";
export const MANIFEST_KIND = "agentpass.authority-manifest";

export const DIAGNOSTICS = Object.freeze({
  INVALID_ARGUMENTS: Object.freeze({ code: "AGENTPASS_MANIFEST_INVALID_ARGUMENTS", message: "authority manifest arguments are invalid" }),
  DATABASE: Object.freeze({ code: "AGENTPASS_MANIFEST_DATABASE_UNAVAILABLE", message: "authority manifest database snapshot is unavailable" }),
  SCHEMA: Object.freeze({ code: "AGENTPASS_MANIFEST_SCHEMA_UNSUPPORTED", message: "authority manifest schema is unsupported" }),
  MALFORMED_DATABASE: Object.freeze({ code: "AGENTPASS_MANIFEST_DATABASE_MALFORMED", message: "authority manifest database state is malformed" }),
  CROSS_TENANT: Object.freeze({ code: "AGENTPASS_MANIFEST_CROSS_TENANT", message: "authority manifest database state crosses a tenant boundary" }),
  INVALID_FILE: Object.freeze({ code: "AGENTPASS_MANIFEST_INVALID_FILE", message: "authority manifest file is invalid" }),
  SIGNATURE: Object.freeze({ code: "AGENTPASS_MANIFEST_SIGNATURE_INVALID", message: "authority manifest detached signature is invalid" }),
  ARTIFACT: Object.freeze({ code: "AGENTPASS_MANIFEST_ARTIFACT_INVALID", message: "authority manifest backup artifact binding is invalid" }),
  TENANT_SCOPE_MISMATCH: Object.freeze({ code: "AGENTPASS_MANIFEST_TENANT_MISMATCH", message: "authority manifest tenant scopes do not match" }),
  MISMATCH: Object.freeze({ code: "AGENTPASS_MANIFEST_MISMATCH", message: "authority manifests do not match" })
});

const SENSITIVE_KEY = /(?:^|_)(?:authorization|bearer|body|cookie|credential|csrf|event_json|nonce|password|payload|private|raw|redacted_json|secret|session|signature|token)(?:_|$)/iu;

const ROW_COUNT_SQL = `/* authority-manifest:all-row-counts */
SELECT table_name, row_count FROM (
${AUTHORITY_TABLES.map(([name, predicate]) => `  SELECT '${name}'::text AS table_name, count(*)::text AS row_count FROM ${name} t WHERE ${predicate}`).join("\n  UNION ALL\n")}
) counts ORDER BY table_name`;

const COLUMN_SQL = `/* authority-manifest:columns */
SELECT table_name, column_name, ordinal_position::text AS ordinal_position
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = ANY($1::text[])
ORDER BY table_name, ordinal_position`;

const MIGRATION_SQL = `/* authority-manifest:migrations */
SELECT version::text, checksum FROM schema_migrations ORDER BY version`;
const ATTEMPT_SQL = `/* authority-manifest:migration-attempts */
SELECT version::text, checksum, status FROM schema_migration_attempts WHERE status IN ('running', 'failed') ORDER BY version, id`;
const CONSTRAINT_SQL = `/* authority-manifest:constraints */
SELECT n.nspname AS schema_name, c.relname AS table_name, pc.conname AS constraint_name,
  pc.contype AS constraint_type, pc.convalidated AS validated,
  pg_get_constraintdef(pc.oid, true) AS definition
FROM pg_constraint pc
JOIN pg_class c ON c.oid = pc.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])
ORDER BY c.relname, pc.conname`;

const CROSS_TENANT_SQL = `/* authority-manifest:tenant-integrity */
WITH tenants AS (SELECT unnest($1::uuid[]) AS organization_id), violations AS (
  SELECT count(*) FROM memberships m JOIN tenants t ON t.organization_id=m.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id=m.organization_id)
       OR NOT EXISTS (SELECT 1 FROM members x WHERE x.id=m.member_id)
  UNION ALL SELECT count(*) FROM human_sessions s JOIN tenants t ON t.organization_id=s.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM members m WHERE m.id=s.member_id)
       OR (s.membership_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id))
  UNION ALL SELECT count(*) FROM webauthn_credentials w
    WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=ANY($1::uuid[]) AND m.member_id=w.member_id)
      AND NOT EXISTS (SELECT 1 FROM members m WHERE m.id=w.member_id)
  UNION ALL SELECT count(*) FROM webauthn_challenges h JOIN tenants t ON t.organization_id=h.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM human_sessions s WHERE s.id=h.session_id AND s.member_id=h.member_id)
       OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=h.organization_id AND m.id IS NOT NULL AND m.member_id=h.member_id)
  UNION ALL SELECT count(*) FROM upstream_identities u
    WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=ANY($1::uuid[]) AND m.member_id=u.member_id)
      AND NOT EXISTS (SELECT 1 FROM members m WHERE m.id=u.member_id)
  UNION ALL SELECT count(*) FROM device_enrollments e JOIN tenants t ON t.organization_id=e.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=e.organization_id AND d.id=e.device_id)
       OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=e.organization_id AND m.member_id=e.created_by)
  UNION ALL SELECT count(*) FROM agents a JOIN tenants t ON t.organization_id=a.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=a.organization_id AND d.id=a.device_id)
  UNION ALL SELECT count(*) FROM agent_session_grants g JOIN tenants t ON t.organization_id=g.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=g.organization_id AND d.id=g.device_id)
       OR NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id=g.organization_id AND a.id=g.agent_id AND a.device_id=g.device_id)
       OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=g.organization_id AND m.member_id=g.created_by)
  UNION ALL SELECT count(*) FROM agent_sessions s JOIN tenants t ON t.organization_id=s.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM agent_session_grants g WHERE g.organization_id=s.organization_id AND g.grant_id=s.grant_id AND g.device_id=s.device_id AND g.agent_id=s.agent_id AND g.grant_hash=s.grant_hash)
       OR NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id=s.organization_id AND a.id=s.agent_id AND a.device_id=s.device_id)
       OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=s.organization_id AND d.id=s.device_id)
  UNION ALL SELECT count(*) FROM qualification_grant_control_heads q JOIN tenants t ON t.organization_id=q.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=q.organization_id AND d.id=q.device_id)
  UNION ALL SELECT count(*) FROM qualification_grant_batches q JOIN tenants t ON t.organization_id=q.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=q.organization_id AND d.id=q.device_id)
       OR NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id=q.organization_id AND a.id=q.agent_id AND a.device_id=q.device_id)
       OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=q.organization_id AND m.member_id=q.authorized_member_id)
  UNION ALL SELECT count(*) FROM qualification_grant_batch_steps q JOIN tenants t ON t.organization_id=q.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM qualification_grant_batches b WHERE b.organization_id=q.organization_id AND b.batch_id=q.batch_id AND b.device_id=q.device_id AND b.agent_id=q.agent_id)
       OR NOT EXISTS (SELECT 1 FROM agent_session_grants g WHERE g.organization_id=q.organization_id AND g.grant_id=q.grant_id AND g.device_id=q.device_id AND g.agent_id=q.agent_id AND g.grant_hash=q.grant_hash)
  UNION ALL SELECT count(*) FROM policies p JOIN tenants t ON t.organization_id=p.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=p.organization_id AND m.member_id=p.created_by)
  UNION ALL SELECT count(*) FROM revocations r JOIN tenants t ON t.organization_id=r.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=r.organization_id AND m.member_id=r.created_by)
       OR (r.revoked_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=r.organization_id AND m.member_id=r.revoked_by))
       OR (r.target_type='organization' AND r.target_id IS NOT NULL)
       OR (r.target_type='device' AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=r.organization_id AND d.id=r.target_id))
       OR (r.target_type='agent' AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id=r.organization_id AND a.id=r.target_id))
       OR (r.target_type='capability' AND NOT EXISTS (SELECT 1 FROM capabilities c WHERE c.organization_id=r.organization_id AND c.id=r.target_id))
  UNION ALL SELECT count(*) FROM capabilities c JOIN tenants t ON t.organization_id=c.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id=c.organization_id AND a.id=c.agent_id)
       OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=c.organization_id AND d.id=c.device_id)
       OR (c.issued_by_member_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=c.organization_id AND m.member_id=c.issued_by_member_id))
  UNION ALL SELECT count(*) FROM bundle_heads b JOIN tenants t ON t.organization_id=b.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=b.organization_id AND d.id=b.device_id)
  UNION ALL SELECT count(*) FROM bundle_acknowledgements k JOIN tenants t ON t.organization_id=k.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=k.organization_id AND d.id=k.device_id)
       OR NOT EXISTS (SELECT 1 FROM bundle_heads b WHERE b.organization_id=k.organization_id AND b.device_id=k.device_id AND b.format_epoch=k.format_epoch AND b.sequence=k.sequence AND b.statement_hash=k.statement_hash)
  UNION ALL SELECT count(*) FROM organization_invitations i JOIN tenants t ON t.organization_id=i.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=i.organization_id AND m.member_id=i.created_by)
       OR (i.consumed_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=i.organization_id AND m.member_id=i.consumed_by))
       OR (i.revoked_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=i.organization_id AND m.member_id=i.revoked_by))
  UNION ALL SELECT count(*) FROM admin_audit_events a JOIN tenants t ON t.organization_id=a.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=a.organization_id AND m.member_id=a.actor_id)
  UNION ALL SELECT count(*) FROM outbox_events x JOIN tenants t ON t.organization_id=x.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id=x.organization_id)
  UNION ALL SELECT count(*) FROM device_audit_events e JOIN tenants t ON t.organization_id=e.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=e.organization_id AND d.id=e.device_id)
  UNION ALL SELECT count(*) FROM device_audit_heads h JOIN tenants t ON t.organization_id=h.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=h.organization_id AND d.id=h.device_id)
       OR (h.last_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM device_audit_events e WHERE e.organization_id=h.organization_id AND e.device_id=h.device_id AND e.event_id=h.last_event_id))
  UNION ALL SELECT count(*) FROM device_audit_gaps g JOIN tenants t ON t.organization_id=g.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=g.organization_id AND d.id=g.device_id)
       OR NOT EXISTS (SELECT 1 FROM device_audit_events e WHERE e.organization_id=g.organization_id AND e.device_id=g.device_id AND e.event_id=g.event_id)
  UNION ALL SELECT count(*) FROM idempotency_records i JOIN tenants t ON t.organization_id=i.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id=i.organization_id)
  UNION ALL SELECT count(*) FROM device_request_nonces n JOIN tenants t ON t.organization_id=n.organization_id
    WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=n.organization_id AND d.id=n.device_id)
  UNION ALL SELECT count(*) FROM rate_limit_buckets l JOIN tenants t ON t.organization_id=l.organization_id
    WHERE (l.principal_type='device' AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.organization_id=l.organization_id AND d.id=l.principal_id))
       OR (l.principal_type='human' AND NOT EXISTS (SELECT 1 FROM members m JOIN memberships ms ON ms.member_id=m.id WHERE ms.organization_id=l.organization_id AND m.id=l.principal_id))
)
SELECT COALESCE(sum(count), 0)::text AS violation_count FROM violations`;

export class AuthorityManifestError extends Error {
  constructor(diagnostic, cause = undefined) {
    super(diagnostic.message, cause === undefined ? undefined : { cause });
    this.name = "AuthorityManifestError";
    this.code = diagnostic.code;
    this.diagnostic = diagnostic;
  }
}

export async function createAuthorityManifest({ client, organizationIds = undefined, artifactDigest = undefined } = {}) {
  assertClient(client);
  const requestedTenantIds = normalizeTenantIds(organizationIds);
  const read = async (sql, params = []) => {
    assertReadOnlyQuery(sql);
    try { return await client.query(sql, params); }
    catch (error) { throw new AuthorityManifestError(DIAGNOSTICS.DATABASE, error); }
  };
  let inTransaction = false;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    inTransaction = true;
    const expectedMigrations = await loadSqlMigrations();
    const migrations = normalizeMigrations((await read(MIGRATION_SQL)).rows ?? [], expectedMigrations, true);
    if (migrations.at(-1)?.version !== REQUIRED_MIGRATION_VERSION) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);
    const attempts = (await read(ATTEMPT_SQL)).rows ?? [];
    if (attempts.length !== 0) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);

    const tenantResult = await read(
      "SELECT id AS organization_id FROM organizations WHERE ($1::uuid[] IS NULL OR id=ANY($1::uuid[])) ORDER BY id",
      [requestedTenantIds === undefined ? null : requestedTenantIds]
    );
    const tenantIds = uniqueSorted((tenantResult.rows ?? []).map((row) => normalizeUuid(row.organization_id)), "organization_id");
    if (requestedTenantIds !== undefined && canonicalJson(tenantIds) !== canonicalJson(requestedTenantIds)) throw new AuthorityManifestError(DIAGNOSTICS.CROSS_TENANT);
    if (tenantIds.length === 0) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    const tenantParams = [tenantIds];
    const integrity = await read(CROSS_TENANT_SQL, tenantParams);
    if (normalizeDecimal(integrity.rows?.[0]?.violation_count) !== "0") throw new AuthorityManifestError(DIAGNOSTICS.CROSS_TENANT);

    const tableNames = [...AUTHORITY_TABLE_NAMES];
    const columns = normalizeColumns((await read(COLUMN_SQL, [tableNames])).rows ?? [], tableNames);
    const constraints = normalizeDatabaseConstraints((await read(CONSTRAINT_SQL, [tableNames])).rows ?? [], tableNames);
    if (constraints.some((constraint) => constraint.validated !== true)) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);
    const counts = normalizeCounts((await read(ROW_COUNT_SQL, tenantParams)).rows ?? []);
    const tables = [];
    for (const [tableName] of AUTHORITY_TABLES) {
      const rows = (await read(rowSql(tableName), tenantParams)).rows ?? [];
      const rowDigests = rows.map((entry) => digestDatabaseRow(entry?.row ?? entry));
      rowDigests.sort();
      if (counts[tableName] !== String(rowDigests.length)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
      tables.push({
        table_name: tableName,
        row_count: counts[tableName],
        column_count: String(columns[tableName].length),
        columns_digest: digestValue(columns[tableName]),
        rows_digest: digestValue(rowDigests),
        row_digests: rowDigests
      });
    }
    const normalizedArtifactDigest = artifactDigest === undefined ? undefined : normalizeHash(artifactDigest);
    const manifest = {
      schema_version: AUTHORITY_MANIFEST_SCHEMA_VERSION,
      kind: MANIFEST_KIND,
      migration_version: REQUIRED_MIGRATION_VERSION,
      migrations,
      tenant_ids: tenantIds,
      tenants: tenantIds.map((organization_id) => ({ organization_id })),
      row_counts: counts,
      tables,
      constraints,
      ...(normalizedArtifactDigest === undefined ? {} : { artifact_digest: normalizedArtifactDigest })
    };
    const sealed = sealAuthorityManifest(manifest);
    await client.query("COMMIT");
    inTransaction = false;
    return sealed;
  } catch (error) {
    if (inTransaction) { try { await client.query("ROLLBACK"); } catch { /* preserve stable diagnostic */ } }
    if (error instanceof AuthorityManifestError) throw error;
    throw new AuthorityManifestError(DIAGNOSTICS.DATABASE, error);
  }
}

export function sealAuthorityManifest(manifest) {
  const body = normalizeManifestBody(manifest);
  return Object.freeze({ ...body, manifest_hash: hashManifestBody(body) });
}

export function verifyAuthorityManifest(manifest) {
  try {
    const body = normalizeManifestBody(manifest);
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || typeof manifest.manifest_hash !== "string" || !SHA256.test(manifest.manifest_hash)) throw new Error("invalid manifest envelope");
    if (manifest.manifest_hash !== hashManifestBody(body)) throw new Error("manifest hash mismatch");
    return true;
  } catch (error) {
    if (error instanceof AuthorityManifestError) throw error;
    throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE, error);
  }
}

export function canonicalAuthorityManifest(manifest) {
  const body = normalizeManifestBody(manifest);
  const sealed = { ...body, manifest_hash: hashManifestBody(body) };
  if (manifest?.manifest_hash !== sealed.manifest_hash) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  return `${canonicalJson(sealed)}\n`;
}

export function compareAuthorityManifests(left, right) {
  try {
    const leftBody = normalizeManifestBody(left);
    const rightBody = normalizeManifestBody(right);
    verifyAuthorityManifest(left);
    verifyAuthorityManifest(right);
    if (canonicalJson(leftBody.tenant_ids) !== canonicalJson(rightBody.tenant_ids)) return Object.freeze({ same: false, diagnostic: DIAGNOSTICS.TENANT_SCOPE_MISMATCH });
    if (canonicalJson(leftBody) === canonicalJson(rightBody)) return Object.freeze({ same: true, diagnostic: null });
    return Object.freeze({ same: false, diagnostic: DIAGNOSTICS.MISMATCH });
  } catch {
    return Object.freeze({ same: false, diagnostic: DIAGNOSTICS.INVALID_FILE });
  }
}

export function hashAuthorityManifest(manifest) {
  verifyAuthorityManifest(manifest);
  return manifest.manifest_hash;
}

export function verifyDetachedSignature(manifest, signature, publicKey) {
  try {
    verifyAuthorityManifest(manifest);
    const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
    const signatureBytes = decodeSignature(signature);
    const digestAlgorithm = ["ed25519", "ed448"].includes(key.asymmetricKeyType) ? null : "sha256";
    if (!crypto.verify(digestAlgorithm, Buffer.from(canonicalAuthorityManifest(manifest), "utf8"), key, signatureBytes)) throw new Error("signature mismatch");
    return true;
  } catch (error) {
    if (error instanceof AuthorityManifestError && error.code === DIAGNOSTICS.INVALID_FILE.code) throw error;
    throw new AuthorityManifestError(DIAGNOSTICS.SIGNATURE, error);
  }
}

export async function verifyBackupArtifactDigest(manifest, artifactPath) {
  try {
    verifyAuthorityManifest(manifest);
    if (typeof manifest.artifact_digest !== "string") throw new Error("manifest is not bound to an artifact");
    if (manifest.artifact_digest !== await digestRegularFile(artifactPath, MAX_ARTIFACT_BYTES)) throw new Error("artifact digest mismatch");
    return true;
  } catch (error) {
    if (error instanceof AuthorityManifestError && error.code === DIAGNOSTICS.INVALID_FILE.code) throw error;
    throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT, error);
  }
}

export async function verifyManifestEvidence({ manifest, signature = undefined, publicKey = undefined, artifactPath = undefined } = {}) {
  verifyAuthorityManifest(manifest);
  if (signature === undefined || publicKey === undefined) throw new AuthorityManifestError(DIAGNOSTICS.SIGNATURE);
  verifyDetachedSignature(manifest, signature, publicKey);
  if (artifactPath !== undefined) await verifyBackupArtifactDigest(manifest, artifactPath);
  else if (manifest.artifact_digest !== undefined) throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT);
  return true;
}

async function loadManifest(filePath) {
  try { return JSON.parse((await readRegularFile(filePath, MAX_MANIFEST_BYTES)).toString("utf8")); }
  catch (error) { if (error instanceof AuthorityManifestError) throw error; throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE, error); }
}

async function runCli(argv, env = process.env) {
  const [command, ...args] = argv;
  if (command === "snapshot") {
    const output = args.shift();
    if (!output) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
    const options = parseCliOptions(args, new Set(["tenant", "artifact", "artifact-digest"]));
    const databaseUrl = env.AGENTPASS_DATABASE_URL;
    if (typeof databaseUrl !== "string" || databaseUrl.length === 0) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
    const artifactDigest = options.artifact === undefined ? options["artifact-digest"] : await digestRegularFile(options.artifact, MAX_ARTIFACT_BYTES);
    const { Pool } = await import("pg");
    const pool = new Pool({ connectionString: databaseUrl, max: 1, statement_timeout: 15000, idle_in_transaction_session_timeout: 20000 });
    try {
      const client = await pool.connect();
      try {
        const manifest = await createAuthorityManifest({ client, organizationIds: options.tenant, artifactDigest });
        await atomicWrite(output, canonicalAuthorityManifest(manifest));
        process.stdout.write(`${JSON.stringify({ manifest_hash: manifest.manifest_hash, ...(manifest.artifact_digest === undefined ? {} : { artifact_digest: manifest.artifact_digest }) })}\n`);
      } finally { client.release(); }
    } finally { await pool.end(); }
    return;
  }
  if (command === "verify") {
    const input = args.shift();
    if (!input) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
    const options = parseCliOptions(args, new Set(["signature-file", "artifact"]));
    const manifest = await loadManifest(input);
    const signature = await readRegularFile(options["signature-file"], MAX_SIGNATURE_BYTES);
    const publicKey = await loadPublicKey(env);
    await verifyManifestEvidence({ manifest, signature, publicKey, artifactPath: options.artifact });
    process.stdout.write(`${JSON.stringify({ verified: true, manifest_hash: manifest.manifest_hash })}\n`);
    return;
  }
  if (command === "compare" && args.length >= 2) {
    const leftPath = args.shift();
    const rightPath = args.shift();
    const options = parseCliOptions(args, new Set(["left-signature-file", "right-signature-file", "left-artifact", "right-artifact"]));
    const left = await loadManifest(leftPath);
    const right = await loadManifest(rightPath);
    for (const [manifest, signatureOption, artifactOption] of [[left, "left-signature-file", "left-artifact"], [right, "right-signature-file", "right-artifact"]]) {
      if (options[signatureOption] !== undefined) {
        await verifyManifestEvidence({ manifest, signature: await readRegularFile(options[signatureOption], MAX_SIGNATURE_BYTES), publicKey: await loadPublicKey(env), artifactPath: options[artifactOption] });
      } else if (options[artifactOption] !== undefined) {
        await verifyBackupArtifactDigest(manifest, options[artifactOption]);
      }
    }
    const result = compareAuthorityManifests(left, right);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.same) process.exitCode = 1;
    return;
  }
  throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
}

export { atomicWrite as writeAuthorityManifest, digestRegularFile as digestBackupArtifact, readRegularFile as readBoundedRegularFile, runCli as runAuthorityManifestCli };

function rowSql(tableName) {
  const definition = AUTHORITY_TABLES.find(([name]) => name === tableName);
  return `/* authority-manifest:table:${tableName} */ SELECT to_jsonb(t) AS row FROM ${definition[0]} t WHERE ${definition[1]}`;
}

function normalizeManifestBody(value) {
  if (!isPlainObject(value)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const allowed = ["artifact_digest", "constraints", "kind", "manifest_hash", "migrations", "migration_version", "row_counts", "schema_version", "tables", "tenant_ids", "tenants"];
  const keys = Object.keys(value).sort();
  const required = allowed.filter((key) => !["artifact_digest", "manifest_hash"].includes(key));
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  if (value.schema_version !== AUTHORITY_MANIFEST_SCHEMA_VERSION || value.kind !== MANIFEST_KIND || value.migration_version !== REQUIRED_MIGRATION_VERSION) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const tenantIds = uniqueSorted(value.tenant_ids?.map((id) => normalizeUuid(id)) ?? [], "organization_id");
  if (tenantIds.length === 0 || tenantIds.length !== value.tenant_ids.length) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  if (!Array.isArray(value.tenants) || value.tenants.length !== tenantIds.length) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const tenants = value.tenants.map(normalizeTenant).sort((a, b) => a.organization_id.localeCompare(b.organization_id));
  if (canonicalJson(tenants.map((tenant) => tenant.organization_id)) !== canonicalJson(tenantIds)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const rowCounts = normalizeCountsObject(value.row_counts);
  const tables = normalizeTables(value.tables, rowCounts);
  const constraints = normalizeManifestConstraints(value.constraints, AUTHORITY_TABLE_NAMES);
  if (constraints.some((constraint) => constraint.validated !== true)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const body = { schema_version: AUTHORITY_MANIFEST_SCHEMA_VERSION, kind: MANIFEST_KIND, migration_version: REQUIRED_MIGRATION_VERSION, migrations: normalizeMigrations(value.migrations, undefined), tenant_ids: tenantIds, tenants, row_counts: rowCounts, tables, constraints };
  if (value.artifact_digest !== undefined) body.artifact_digest = normalizeHash(value.artifact_digest);
  // row_counts keys are already normalized against the exact authority-table
  // allowlist. Do not interpret an allowlisted table name such as
  // agent_session_grants as a secret-bearing manifest field.
  const { row_counts: _normalizedRowCounts, ...sensitiveFieldCheckBody } = body;
  rejectSensitiveKeys(sensitiveFieldCheckBody);
  return body;
}

function normalizeTenant(value) {
  if (!isPlainObject(value) || Object.keys(value).sort().join(",") !== "organization_id") throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  return { organization_id: normalizeUuid(value.organization_id) };
}

function normalizeTables(values, rowCounts) {
  if (!Array.isArray(values) || values.length !== AUTHORITY_TABLE_NAMES.length) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const seen = new Set();
  const result = values.map((value) => {
    if (!isPlainObject(value) || Object.keys(value).sort().join(",") !== "column_count,columns_digest,row_count,row_digests,rows_digest,table_name") throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    const tableName = enumValue(value.table_name, AUTHORITY_TABLE_NAMES);
    if (seen.has(tableName)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    seen.add(tableName);
    const rowDigests = normalizeHashArray(value.row_digests);
    const rowCount = normalizeDecimal(value.row_count);
    if (rowCount !== rowCounts[tableName] || rowCount !== String(rowDigests.length) || digestValue(rowDigests) !== value.rows_digest) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    return { table_name: tableName, row_count: rowCount, column_count: normalizeDecimal(value.column_count), columns_digest: normalizeHash(value.columns_digest), rows_digest: normalizeHash(value.rows_digest), row_digests: rowDigests };
  }).sort((a, b) => a.table_name.localeCompare(b.table_name));
  if (seen.size !== AUTHORITY_TABLE_NAMES.length || canonicalJson([...seen].sort()) !== canonicalJson([...AUTHORITY_TABLE_NAMES].sort())) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  return result;
}

function normalizeMigrations(rows, expected, databaseRows = false) {
  if (!Array.isArray(rows) || rows.length !== Number(REQUIRED_MIGRATION_VERSION)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const result = rows.map((row) => {
    const expectedMigration = expected?.find((migration) => String(migration.version) === String(row.version));
    if (!isPlainObject(row) || (databaseRows ? Object.keys(row).sort().join(",") !== "checksum,version" : Object.keys(row).sort().join(",") !== "checksum,name,version")) throw new AuthorityManifestError(databaseRows ? DIAGNOSTICS.SCHEMA : DIAGNOSTICS.INVALID_FILE);
    return { version: normalizeDecimal(row.version), name: safeName(databaseRows ? expectedMigration?.name : row.name), checksum: normalizeHash(row.checksum) };
  }).sort((a, b) => Number(a.version) - Number(b.version));
  for (let index = 0; index < result.length; index += 1) if (result[index].version !== String(index + 1)) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);
  if (result.at(-1).version !== REQUIRED_MIGRATION_VERSION) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);
  if (expected !== undefined && result.some((row, index) => row.version !== String(expected[index].version) || row.name !== expected[index].name || row.checksum !== expected[index].checksum)) throw new AuthorityManifestError(DIAGNOSTICS.SCHEMA);
  return result;
}

function normalizeCounts(rows) {
  if (!Array.isArray(rows) || rows.length !== AUTHORITY_TABLE_NAMES.length) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
  const result = {};
  for (const row of rows) {
    if (!isPlainObject(row) || Object.keys(row).sort().join(",") !== "row_count,table_name") throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    const name = enumValue(row.table_name, AUTHORITY_TABLE_NAMES);
    if (result[name] !== undefined) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    result[name] = normalizeDecimal(row.row_count);
  }
  return normalizeCountsObject(result);
}

function normalizeCountsObject(value) {
  if (!isPlainObject(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...AUTHORITY_TABLE_NAMES].sort())) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  return Object.fromEntries([...AUTHORITY_TABLE_NAMES].sort().map((name) => [name, normalizeDecimal(value[name])]));
}

function normalizeColumns(rows, tableNames) {
  const result = Object.fromEntries(tableNames.map((name) => [name, []]));
  for (const row of rows) {
    if (!isPlainObject(row) || !result[row.table_name]) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    result[row.table_name].push({ name: safeName(row.column_name), position: normalizeDecimal(row.ordinal_position) });
  }
  for (const name of tableNames) {
    result[name].sort((a, b) => Number(a.position) - Number(b.position));
    if (new Set(result[name].map((column) => column.position)).size !== result[name].length) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
  }
  return result;
}

function normalizeDatabaseConstraints(rows, tableNames) {
  if (!Array.isArray(rows)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
  const allowed = new Set(tableNames);
  const seen = new Set();
  return rows.map((row) => {
    if (!isPlainObject(row) || Object.keys(row).sort().join(",") !== "constraint_name,constraint_type,definition,schema_name,table_name,validated") throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    if (row.schema_name !== "public" || !allowed.has(row.table_name) || typeof row.validated !== "boolean" || typeof row.definition !== "string") throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    const key = `${row.table_name}\u0000${row.constraint_name}`;
    if (seen.has(key)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
    seen.add(key);
    return { table_name: safeName(row.table_name), constraint_name: safeName(row.constraint_name), constraint_type: enumValue(row.constraint_type, ["c", "f", "p", "u", "x", "t"]), validated: row.validated, definition_digest: digestValue(row.definition) };
  }).sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
}

function normalizeManifestConstraints(rows, tableNames) {
  if (!Array.isArray(rows)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  const allowed = new Set(tableNames);
  const seen = new Set();
  return rows.map((row) => {
    if (!isPlainObject(row) || Object.keys(row).sort().join(",") !== "constraint_name,constraint_type,definition_digest,table_name,validated") throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    if (!allowed.has(row.table_name) || typeof row.validated !== "boolean" || !SHA256.test(row.definition_digest)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    const key = `${row.table_name}\u0000${row.constraint_name}`;
    if (seen.has(key)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    seen.add(key);
    return { table_name: safeName(row.table_name), constraint_name: safeName(row.constraint_name), constraint_type: enumValue(row.constraint_type, ["c", "f", "p", "u", "x", "t"]), validated: row.validated, definition_digest: row.definition_digest.toLowerCase() };
  }).sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
}

function normalizeHashArray(value) {
  if (!Array.isArray(value)) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
  return [...value].map((item) => normalizeHash(item)).sort();
}

function digestDatabaseRow(row) {
  if (!isPlainObject(row)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
  return digestValue(row);
}

function digestValue(value) {
  return crypto.createHash("sha256").update(canonicalJson(digestableValue(value)), "utf8").digest("hex");
}

function digestableValue(value, key = undefined) {
  if (SENSITIVE_KEY.test(key ?? "")) return { $sha256: digestValue(value) };
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((item) => digestableValue(item));
  if (isPlainObject(value)) return Object.fromEntries(Object.keys(value).sort().map((name) => [name, digestableValue(value[name], name)]));
  throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE);
}

function rejectSensitiveKeys(value) {
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key) || key.startsWith("$")) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    if (nested && typeof nested === "object") rejectSensitiveKeys(nested);
  }
}

function hashManifestBody(body) { return crypto.createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"); }
function normalizeTenantIds(value) { if (value === undefined) return undefined; if (!Array.isArray(value) || value.length === 0) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS); return uniqueSorted(value.map((id) => normalizeUuid(id)), "organization_id"); }
function uniqueSorted(values, label) { const sorted = [...values].sort(); for (let index = 1; index < sorted.length; index += 1) if (sorted[index] === sorted[index - 1]) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); sorted.forEach((value) => normalizeUuid(value, label)); return sorted; }
function normalizeUuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); return value.toLowerCase(); }
function normalizeHash(value) { if (typeof value !== "string" || !SHA256.test(value)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); return value.toLowerCase(); }
function normalizeDecimal(value) { const result = typeof value === "number" && Number.isSafeInteger(value) ? String(value) : value; if (typeof result !== "string" || !DECIMAL.test(result)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); return result; }
function enumValue(value, allowed) { if (typeof value !== "string" || !allowed.includes(value)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); return value; }
function safeName(value) { if (typeof value !== "string" || value.length < 1 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) throw new AuthorityManifestError(DIAGNOSTICS.MALFORMED_DATABASE); return value; }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS); }
function assertReadOnlyQuery(sql) { const text = sql.replace(/\/\*[\s\S]*?\*\//gu, "").trim(); if (!/^(?:SELECT|WITH)\b/iu.test(text) || /\b(?:INSERT|UPDATE|DELETE|MERGE|COPY|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE)\b/iu.test(text) || text.includes(";")) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS); }

async function readRegularFile(filePath, maxBytes) {
  const handle = await openRegularFile(filePath, fs.constants.O_RDONLY);
  try {
    const stat = await handle.stat();
    if (stat.size > maxBytes) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE);
    return await handle.readFile();
  } catch (error) { if (error instanceof AuthorityManifestError) throw error; throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE, error); }
  finally { await handle.close(); }
}

async function digestRegularFile(filePath, maxBytes) {
  const handle = await openRegularFile(filePath, fs.constants.O_RDONLY);
  try {
    const initial = await handle.stat();
    if (initial.size > maxBytes) throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT);
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT);
      hash.update(buffer.subarray(0, bytesRead));
    }
    const final = await handle.stat();
    if (final.dev !== initial.dev || final.ino !== initial.ino || final.size !== initial.size) throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT);
    return hash.digest("hex");
  } catch (error) { if (error instanceof AuthorityManifestError) throw error; throw new AuthorityManifestError(DIAGNOSTICS.ARTIFACT, error); }
  finally { await handle.close(); }
}

async function openRegularFile(filePath, flags) {
  if (typeof filePath !== "string" || filePath.length < 1 || filePath.length > 4096 || filePath.includes("\u0000")) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
  try {
    const stat = await lstat(filePath);
    if (!stat.isFile()) throw new Error("not regular");
    if (stat.isSymbolicLink()) throw new Error("symlink");
    return await open(filePath, flags | NOFOLLOW);
  } catch (error) { if (error instanceof AuthorityManifestError) throw error; throw new AuthorityManifestError(DIAGNOSTICS.INVALID_FILE, error); }
}

async function atomicWrite(filePath, contents) {
  if (typeof filePath !== "string" || filePath.length < 1 || filePath.length > 4096 || filePath.includes("\u0000")) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
  const directory = path.dirname(path.resolve(filePath));
  const base = path.basename(filePath);
  let tempPath;
  let handle;
  try {
    const dirStat = await lstat(directory);
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) throw new Error("output directory is not safe");
    try { const target = await lstat(filePath); if (target) throw new Error("output exists"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    for (let attempt = 0; attempt < 8; attempt += 1) {
      tempPath = path.join(directory, `.${base}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
      try { handle = await open(tempPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NOFOLLOW, 0o640); break; }
      catch (error) { if (error?.code !== "EEXIST") throw error; }
    }
    if (!handle) throw new Error("temporary output unavailable");
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(tempPath, filePath);
    tempPath = undefined;
    const directoryHandle = await open(directory, fs.constants.O_RDONLY | NOFOLLOW);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    await chmod(filePath, 0o640);
  } catch (error) { if (handle) await handle.close().catch(() => {}); if (tempPath) await unlink(tempPath).catch(() => {}); if (error instanceof AuthorityManifestError) throw error; throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS, error); }
}

function parseCliOptions(args, allowed) {
  const options = {};
  for (const arg of args) {
    const match = /^--([a-z-]+)=(.*)$/u.exec(arg);
    if (!match || !allowed.has(match[1]) || match[2].length === 0) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
    if (options[match[1]] !== undefined) throw new AuthorityManifestError(DIAGNOSTICS.INVALID_ARGUMENTS);
    if (match[1] === "tenant") (options.tenant ??= []).push(normalizeUuid(match[2]));
    else if (match[1] === "artifact-digest") options[match[1]] = normalizeHash(match[2]);
    else options[match[1]] = match[2];
  }
  if (options.tenant) options.tenant = uniqueSorted(options.tenant, "organization_id");
  return options;
}

function decodeSignature(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length === 0 || value.length > MAX_SIGNATURE_BYTES) throw new Error("empty signature");
    return value;
  }
  const bytes = Buffer.from(String(value).trim(), "utf8");
  if (bytes.length === 0 || bytes.length > MAX_SIGNATURE_BYTES) throw new Error("empty signature");
  const text = bytes.toString("utf8").trim();
  if (/^[0-9a-f]+$/iu.test(text) && text.length % 2 === 0) return Buffer.from(text, "hex");
  if (/^[A-Za-z0-9+/_-]+={0,2}$/u.test(text)) return Buffer.from(text.replace(/-/gu, "+").replace(/_/gu, "/"), "base64");
  return bytes;
}

async function loadPublicKey(env) {
  const inline = env.AGENTPASS_MANIFEST_PUBLIC_KEY;
  const file = env.AGENTPASS_MANIFEST_PUBLIC_KEY_FILE;
  if ((inline === undefined) === (file === undefined)) throw new AuthorityManifestError(DIAGNOSTICS.SIGNATURE);
  if (inline !== undefined) {
    if (typeof inline !== "string" || inline.length < 1 || inline.length > MAX_SIGNATURE_BYTES) throw new AuthorityManifestError(DIAGNOSTICS.SIGNATURE);
    return inline;
  }
  return (await readRegularFile(file, MAX_SIGNATURE_BYTES)).toString("utf8");
}

function formatDiagnostic(error) { if (error instanceof AuthorityManifestError) return `${error.code}: ${error.diagnostic.message}`; return `${DIAGNOSTICS.DATABASE.code}: ${DIAGNOSTICS.DATABASE.message}`; }

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) runCli(process.argv.slice(2)).catch((error) => { process.stderr.write(`${formatDiagnostic(error)}\n`); process.exitCode = 1; });
