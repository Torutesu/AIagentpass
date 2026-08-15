import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0056_identity_epoch_invalidation.sql",
  import.meta.url
);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const authorityManifestUrl = new URL("../../../../scripts/postgres/authority-manifest.mjs", import.meta.url);

const readMigration = () => readFile(migrationUrl, "utf8");

function functionBodies(sql) {
  const starts = [...sql.matchAll(/CREATE (?:OR REPLACE )?FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)/gu)];
  return new Map(starts.map((match, index) => {
    const next = starts[index + 1]?.index ?? sql.length;
    return [match[1], sql.slice(match.index, next)];
  }));
}

function bodyOf(sql, name) {
  return functionBodies(sql).get(name) ?? "";
}

test("0056 is cataloged at the PostgreSQL schema head and remains transactional", async () => {
  const [sql, catalog, manifest] = await Promise.all([
    readMigration(),
    readFile(catalogUrl, "utf8").then(JSON.parse),
    readFile(authorityManifestUrl, "utf8")
  ]);
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE\s+TABLE/iu);

  const entry = catalog.entries.find((candidate) => candidate.id === "migration.0056_identity_epoch_invalidation");
  assert.deepEqual(entry, {
    id: "migration.0056_identity_epoch_invalidation",
    kind: "postgres-migration",
    source: "postgres/0056_identity_epoch_invalidation.sql",
    version: 56,
    profile: "migration-global",
    purpose: "migration.0056.identity-epoch-invalidation",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: [
        "tables.organizations.id",
        "tables.memberships.organization_id",
        "tables.human_sessions.organization_id"
      ]
    },
    implementation_refs: [
      "contracts/postgres/0056_identity_epoch_invalidation.sql",
      "scripts/postgres/authority-manifest.v1.json"
    ],
    compatibility_fixtures: [
      "apps/cloud-api/test/postgres/identity-epoch-invalidation-migration.test.mjs"
    ]
  });
  assert.match(manifest, /POSTGRES_SCHEMA_HEAD/u);
  assert.match(manifest, /REQUIRED_MIGRATION_VERSION = String\(POSTGRES_SCHEMA_HEAD\.version\)/u);
});

test("0056 exposes one tenant-bound SECURITY DEFINER invalidation primitive", async () => {
  const sql = await readMigration();
  const primitive = bodyOf(sql, "agentpass_invalidate_identity_epoch");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_invalidate_identity_epoch\(\s*p_organization_id uuid,\s*p_member_id uuid,\s*p_event text\s*\)/u);
  assert.match(primitive, /SECURITY DEFINER/u);
  assert.match(primitive, /SET search_path = pg_catalog, public/u);
  assert.doesNotMatch(primitive, /p_(?:actor|role|member_authority|caller)/iu);
  for (const event of [
    "membership_changed",
    "membership_removed",
    "membership_deleted",
    "webauthn_credential_revoked",
    "platform_credential_revoked",
    "recovery_transition",
    "organization_security_event"
  ]) assert.match(primitive, new RegExp(`'${event}'`, "u"), event);

  assert.match(primitive, /clock_timestamp\(\)/u);
  assert.match(primitive, /max_bigint constant bigint := 9223372036854775807::bigint/u);
  assert.match(primitive, /organization_epoch = max_bigint[\s\S]*numeric_value_out_of_range/u);
  assert.match(primitive, /membership_epoch = max_bigint[\s\S]*numeric_value_out_of_range/u);
  assert.match(primitive, /organization_id = p_organization_id[\s\S]*member_id = p_member_id/u);
  assert.match(primitive, /FOR UPDATE/u);
  assert.match(primitive, /recent_auth_at = NULL[\s\S]*recent_auth_challenge_id = NULL[\s\S]*recent_auth_context_hash = NULL[\s\S]*recent_auth_consumed_at = NULL/u);
  assert.match(primitive, /UPDATE webauthn_challenges[\s\S]*consumed_at = now_value/u);
  assert.match(primitive, /UPDATE capabilities[\s\S]*revoked_at = now_value/u);
  assert.match(primitive, /UPDATE platform_sessions[\s\S]*status = 'revoked'/u);
});

test("0056 fixes the lock order and makes the invalidation atomic with sessions", async () => {
  const sql = await readMigration();
  const primitive = bodyOf(sql, "agentpass_invalidate_identity_epoch");
  const organizationLock = primitive.indexOf("agentpass:organization:");
  const memberLock = primitive.indexOf("agentpass:human:sessions:");
  const organizationRowLock = primitive.indexOf("FROM organizations");
  const membershipRowLock = primitive.indexOf("FROM memberships");
  assert.ok(organizationLock >= 0 && memberLock > organizationLock, "organization lock must precede member lock");
  assert.ok(organizationRowLock > memberLock, "advisory locks must precede organization row lock");
  assert.ok(membershipRowLock > organizationRowLock, "organization row lock must precede membership row lock");
  assert.match(primitive, /p_event <> 'organization_security_event'/u);
  assert.match(primitive, /member-scoped identity invalidation requires a member/u);
  assert.match(primitive, /organization-scoped identity invalidation cannot carry a member/u);
  assert.match(primitive, /SET revoked_at = CASE[\s\S]*version = version \+ 1/u);
  assert.match(primitive, /GET DIAGNOSTICS invalidated_human_sessions = ROW_COUNT/u);
  assert.match(primitive, /GET DIAGNOSTICS invalidated_platform_sessions = ROW_COUNT/u);
  assert.match(sql, /agentpass\.recovery_epoch_bump/u, "0025 compatibility must be explicit and scoped");
});

test("0056 covers every reviewed mutation path through wrappers and triggers", async () => {
  const sql = await readMigration();
  for (const name of [
    "agentpass_invalidate_membership_after_change",
    "agentpass_invalidate_credential_after_revoke",
    "agentpass_invalidate_recovery_transition",
    "agentpass_invalidate_organization_security_event"
  ]) {
    const body = bodyOf(sql, name);
    assert.match(body, /SECURITY DEFINER/u, `${name} must be SECURITY DEFINER`);
    assert.match(body, /SET search_path = pg_catalog, public/u, `${name} search_path`);
    assert.match(body, /agentpass_invalidate_identity_epoch/u, `${name} must use the primitive`);
  }
  assert.match(sql, /AFTER UPDATE OF organization_id, member_id, role, status OR DELETE ON memberships/u);
  assert.match(sql, /AFTER UPDATE OF revoked_at ON webauthn_credentials/u);
  assert.match(sql, /AFTER UPDATE OF status, revoked_at ON platform_credentials/u);
  assert.match(sql, /AFTER UPDATE OF state ON owner_recovery_requests/u);
  assert.match(sql, /AFTER INSERT ON revocations/u);
  assert.match(sql, /AFTER UPDATE OF target_type, status ON revocations/u);
  assert.match(sql, /DROP TRIGGER memberships_bump_session_epoch ON memberships/u);
  assert.match(sql, /CREATE TRIGGER memberships_guard_session_epoch/u);
  assert.match(sql, /agentpass_bump_organization_authority_epoch[\s\S]*agentpass_invalidate_identity_epoch/u);
});

test("0056 has exact function grants and denies direct service-role invocation", async () => {
  const sql = await readMigration();
  const functions = [
    "agentpass_invalidate_identity_epoch",
    "agentpass_invalidate_membership_after_change",
    "agentpass_invalidate_credential_after_revoke",
    "agentpass_invalidate_recovery_transition",
    "agentpass_invalidate_organization_security_event",
    "agentpass_guard_membership_session_epoch"
  ];
  for (const name of functions) {
    assert.match(sql, new RegExp(`REVOKE ALL PRIVILEGES ON FUNCTION public\\.${name}\\([^;]* FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup`, "u"), name);
    assert.match(sql, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${name}\\([^;]* TO agentpass_migrator`, "u"), name);
  }
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_guard_organization_authority_epoch\(\) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_invalidate_identity_epoch\([^;]* TO [^;]*(?:agentpass_app|agentpass_signer|agentpass_backup)/u);
});
