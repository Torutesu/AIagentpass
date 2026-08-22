import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0107_organization_core_authority.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

function compact(source) {
  return source.replace(/\s+/gu, " ");
}

function functionBody(source, name) {
  const start = source.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `missing ${name}`);
  const end = source.indexOf("\n$$;", start);
  assert.notEqual(end, -1, `${name} has no body terminator`);
  return source.slice(start, end);
}

test("0107 organization core authority exposes only the two repository contracts", async () => {
  const source = await readFile(migrationUrl, "utf8");
  const sql = compact(source);

  assert.equal((source.match(/CREATE FUNCTION /gu) ?? []).length, 2);
  assert.equal((source.match(/SECURITY DEFINER/gu) ?? []).length, 2);
  assert.equal((source.match(/SET search_path = pg_catalog, public/gu) ?? []).length, 2);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_organization_create_with_owner\( p_organization_id uuid, p_owner_member_id uuid, p_owner_membership_id uuid, p_name text, p_actor_principal text, p_idempotency_key text, p_request_hash text, p_created_at timestamptz DEFAULT NULL \)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_organization_rename\( p_organization_id uuid, p_actor_member_id uuid, p_name text, p_expected_version bigint \)/u);
  assert.match(sql, /ALTER FUNCTION public\.agentpass_organization_create_with_owner\(\s*uuid,\s*uuid,\s*uuid,\s*text,\s*text,\s*text,\s*text,\s*timestamptz\s*\) OWNER TO agentpass_migrator/u);
  assert.match(sql, /ALTER FUNCTION public\.agentpass_organization_rename\(\s*uuid,\s*uuid,\s*text,\s*bigint\s*\) OWNER TO agentpass_migrator/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_organization_create_with_owner\([\s\S]*?\) TO agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_organization_rename\([\s\S]*?\) TO agentpass_app/u);
  assert.doesNotMatch(sql, /INSERT INTO public\.(admin_audit_events|outbox_events)/u);
});

test("0107 create preserves the repository idempotency choreography and owner trigger path", async () => {
  const source = await readFile(migrationUrl, "utf8");
  const body = functionBody(source, "agentpass_organization_create_with_owner");

  assert.match(body, /INSERT INTO public\.organizations[\s\S]*?ON CONFLICT \(id\) DO NOTHING[\s\S]*?RETURNING \* INTO organization_row/u);
  assert.match(body, /DELETE FROM public\.idempotency_records[\s\S]*?expires_at <= pg_catalog\.clock_timestamp\(\)/u);
  assert.match(body, /INSERT INTO public\.idempotency_records[\s\S]*?ON CONFLICT \(organization_id, principal_id, idempotency_key\) DO NOTHING/u);
  assert.match(body, /SELECT \*[\s\S]*?FROM public\.idempotency_records[\s\S]*?FOR UPDATE/u);
  assert.match(body, /idempotency_row\.request_hash IS DISTINCT FROM p_request_hash/u);
  assert.match(body, /idempotency_row\.response_status <> 102/u);
  assert.match(body, /'replayed'::text/u);
  assert.match(body, /'not_created'::text/u);
  assert.match(body, /INSERT INTO public\.memberships[\s\S]*?p_owner_membership_id, p_owner_member_id, 'owner', 'active'/u);
  assert.match(body, /RETURNING \* INTO membership_row/u);
  assert.match(body, /agentpass:human:authority:/u);
  assert.match(body, /agentpass:organization:/u);
  assert.match(body, /p_created_at IS NOT NULL AND NOT pg_catalog\.isfinite\(p_created_at\)/u);
});

test("0107 rename preserves tenant role authorization, optimistic versioning, and row return shape", async () => {
  const source = await readFile(migrationUrl, "utf8");
  const body = functionBody(source, "agentpass_organization_rename");

  assert.match(body, /WHERE o\.id = p_organization_id[\s\S]*?FOR UPDATE/u);
  assert.match(body, /m\.organization_id = p_organization_id[\s\S]*?m\.member_id = p_actor_member_id[\s\S]*?m\.status = 'active'/u);
  assert.match(body, /actor_role NOT IN \('owner', 'admin'\)/u);
  assert.match(body, /organization_row\.version IS DISTINCT FROM p_expected_version/u);
  assert.match(body, /version = o\.version \+ 1[\s\S]*?o\.version = p_expected_version/u);
  assert.match(body, /RETURNING o\.\* INTO organization_row/u);
  assert.match(body, /organization_row\.created_at[\s\S]*?organization_row\.updated_at/u);
  assert.doesNotMatch(body, /memberships_last_active_owner/u);
});

test("0107 is catalog-bound to its frozen checksum and does not authorize repository/bootstrap edits", async () => {
  const [source, catalogText] = await Promise.all([readFile(migrationUrl, "utf8"), readFile(catalogUrl, "utf8")]);
  const catalog = JSON.parse(catalogText);
  const entry = catalog.entries.find((item) => item.id === "migration.0107_organization_core_authority");
  assert.deepEqual(entry, {
    id: "migration.0107_organization_core_authority",
    kind: "postgres-migration",
    source: "postgres/0107_organization_core_authority.sql",
    version: 107,
    profile: "migration-tenant",
    purpose: "migration.0107-organization-core-authority",
    implementation_status: "implemented",
    tenant_binding: { required: true, source: "database", paths: ["tables.organizations.id", "tables.memberships.organization_id", "tables.idempotency_records.organization_id"] },
    actor_binding: { required: true, paths: ["tables.memberships.member_id", "tables.organizations.id"] },
    implementation_refs: ["contracts/postgres/0107_organization_core_authority.sql", "apps/cloud-api/src/postgres/organization-repository.mjs"],
    compatibility_fixtures: [
      "apps/cloud-api/test/postgres/organization-core-authority-migration.test.mjs",
      "scripts/postgres/organization-authority-postgres-qualification.integration.test.mjs",
    ],
    sha256: "8d3c79858c4ea7967fff2485b91a9ae44b68f10504bb6bf1c8c39f5a2b75ddc0"
  });
  assert.doesNotMatch(source, /organization-repository\.mjs|roles\.sql/u);
});
