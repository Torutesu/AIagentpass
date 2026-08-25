import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "../../../../");
const MIGRATION = path.join(ROOT, "contracts/postgres/0108_membership_mutation_authority.sql");
const EPOCH_MIGRATION = path.join(ROOT, "contracts/postgres/0056_identity_epoch_invalidation.sql");
const CATALOG = path.join(ROOT, "contracts/catalog-v1.json");

async function read(file) {
  return fs.readFile(file, "utf8");
}

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

test("0108 exposes the exact membership authority entry points", async () => {
  const sql = await read(MIGRATION);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_membership_role_update\(\s*p_organization_id uuid,\s*p_actor_member_id uuid,\s*p_target_member_id uuid,\s*p_role text,\s*p_expected_version bigint,\s*p_revoked_at timestamptz\s*\)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_membership_remove\(\s*p_organization_id uuid,\s*p_actor_member_id uuid,\s*p_target_member_id uuid,\s*p_expected_version bigint,\s*p_removed_at timestamptz\s*\)/u);
  assert.equal((sql.match(/RETURNS TABLE \(/gu) ?? []).length, 2);
  for (const column of ["organization_id uuid", "membership_id uuid", "member_id uuid", "role text", "status text", "version bigint", "created_at timestamptz", "updated_at timestamptz"]) {
    assert.equal(sql.includes(column), true, `missing return column ${column}`);
  }
  assert.ok((sql.match(/SECURITY DEFINER/gu) ?? []).length >= 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/gu) ?? []).length, 2);
});

test("0108 enforces tenant, actor, CAS, owner, and session-revoke boundaries", async () => {
  const sql = await read(MIGRATION);
  for (const predicate of [
    "p_organization_id IS NULL",
    "p_actor_member_id IS NULL",
    "p_target_member_id IS NULL",
    "p_expected_version IS NULL",
    "p_expected_version < 1",
    "p_role NOT IN ('owner', 'admin', 'auditor', 'viewer')",
    "m.organization_id = p_organization_id",
    "m.member_id = p_actor_member_id",
    "m.member_id = p_target_member_id",
    "actor_row.status IS DISTINCT FROM 'active'",
    "actor_row.role NOT IN ('owner', 'admin')",
    "target_row.status IS DISTINCT FROM 'active'",
    "target_row.version IS DISTINCT FROM p_expected_version",
    "memberships_last_active_owner",
    "target.version = p_expected_version"
  ]) assert.match(sql, new RegExp(escaped(predicate), "u"), `missing authority predicate: ${predicate}`);
  assert.equal((sql.match(/agentpass_human_member_session_revoke\(/gu) ?? []).length, 2);
  assert.match(sql, /'membership_role_changed'/u);
  assert.match(sql, /'membership_removed'/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_membership_role_update[\s\S]*TO agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_membership_remove[\s\S]*TO agentpass_app/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_human_membership_role_update[\s\S]*FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_human_membership_remove[\s\S]*FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance/u);
});

test("0108 preserves the reviewed lock order and delegates epoch invalidation to triggers", async () => {
  const [sql, epochSql] = await Promise.all([read(MIGRATION), read(EPOCH_MIGRATION)]);
  const human = sql.indexOf("agentpass:human:authority:");
  const organization = sql.indexOf("agentpass:organization:");
  const sessions = sql.indexOf("agentpass:human:sessions:");
  assert.ok(human >= 0 && human < organization && organization < sessions, "0108 lock order must be human -> organization -> session");
  assert.doesNotMatch(sql, /SET\s+(?:session_epoch|authority_epoch)\s*=/iu);
  assert.match(epochSql, /CREATE TRIGGER memberships_guard_session_epoch/u);
  assert.match(epochSql, /CREATE TRIGGER memberships_invalidate_identity_epoch/u);
  assert.match(sql, /RETURNING target\.\*/u);
});

test("0108 is pinned in the frozen migration catalog", async () => {
  const [sql, catalogBytes] = await Promise.all([read(MIGRATION), read(CATALOG)]);
  const catalog = JSON.parse(catalogBytes);
  const entry = catalog.entries.find((candidate) => candidate?.source === "postgres/0108_membership_mutation_authority.sql");
  assert.ok(entry);
  assert.equal(entry.version, 108);
  assert.equal(entry.sha256, crypto.createHash("sha256").update(sql, "utf8").digest("hex"));
  assert.ok(entry.compatibility_fixtures.includes("apps/cloud-api/test/postgres/human-membership-mutation-authority-migration.test.mjs"));
});
