import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0024_human_session_epochs.sql", import.meta.url);

test("0024 is transactional, forward-only, and adds positive tenant-qualified epochs", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\b(?:DROP\s+(?:TABLE|COLUMN|INDEX|FUNCTION|TRIGGER)|TRUNCATE|DELETE\s+FROM)\b/iu);

  assert.match(sql, /ALTER TABLE organizations[\s\S]*ADD COLUMN authority_epoch bigint NOT NULL DEFAULT 1[\s\S]*organizations_authority_epoch_positive[\s\S]*CHECK \(authority_epoch > 0\)/u);
  assert.match(sql, /ALTER TABLE memberships[\s\S]*ADD COLUMN session_epoch bigint NOT NULL DEFAULT 1[\s\S]*memberships_session_epoch_positive[\s\S]*CHECK \(session_epoch > 0\)/u);
  assert.match(sql, /ADD COLUMN organization_authority_epoch bigint NOT NULL DEFAULT 1[\s\S]*ADD COLUMN membership_session_epoch bigint NOT NULL DEFAULT 1/u);
  assert.doesNotMatch(sql, /FOREIGN KEY \([^)]*(?:authority_epoch|session_epoch)/u, "historical snapshots must not block epoch advancement");
  assert.match(sql, /CREATE INDEX human_sessions_current_epoch_lookup[\s\S]*ON human_sessions \(organization_id, organization_authority_epoch,[\s\S]*membership_session_epoch/u);
  assert.match(sql, /CREATE INDEX human_sessions_membership_epoch_lookup[\s\S]*ON human_sessions \(organization_id, membership_id,[\s\S]*membership_session_epoch/u);
});

test("0024 snapshots the current epochs on insert and makes them immutable", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /CREATE FUNCTION agentpass_bind_human_session_epochs\(\)[\s\S]*FOR SHARE OF organization, membership/u);
  assert.match(sql, /NEW\.organization_authority_epoch := current_authority_epoch/u);
  assert.match(sql, /NEW\.membership_session_epoch := current_session_epoch/u);
  assert.match(sql, /CREATE TRIGGER human_sessions_bind_epochs[\s\S]*BEFORE INSERT OR UPDATE OF id, organization_id, membership_id,[\s\S]*ON human_sessions/u);
  for (const column of ["id", "member_id", "role", "token_hash", "csrf_token_hash", "created_at", "expires_at"]) {
    assert.match(sql, new RegExp(`NEW\\.${column} IS DISTINCT FROM OLD\\.${column}`, "u"));
  }
  assert.match(sql, /human_sessions_epoch_snapshot_immutable[\s\S]*authority snapshots are immutable/u);
  assert.match(sql, /new human sessions require an organization and membership/u);
});

test("0024 bumps every authority transition without replacing last-owner protection", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /CREATE FUNCTION agentpass_bump_membership_session_epoch\(\)[\s\S]*NEW\.status IS DISTINCT FROM OLD\.status[\s\S]*NEW\.role IS DISTINCT FROM OLD\.role[\s\S]*NEW\.session_epoch := OLD\.session_epoch \+ 1/u);
  assert.match(sql, /CREATE TRIGGER memberships_bump_session_epoch[\s\S]*BEFORE UPDATE OF organization_id, role, status, session_epoch ON memberships/u);
  assert.doesNotMatch(sql, /DROP\s+TRIGGER[\s\S]*memberships_protect_last_active_owner/iu);
  assert.match(sql, /runs the last-owner trigger against the same proposed[\s\S]*role\/status row/u);
  assert.doesNotMatch(sql, /\bUPDATE memberships\b/iu);
});

test("0024 exposes an atomic tenant-scoped organization epoch bump and monotonic guard", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /CREATE FUNCTION agentpass_bump_organization_authority_epoch\([\s\S]*request_organization_id uuid[\s\S]*FOR UPDATE[\s\S]*UPDATE organizations[\s\S]*SET authority_epoch = authority_epoch \+ 1[\s\S]*WHERE id = request_organization_id/u);
  assert.match(sql, /CREATE FUNCTION agentpass_guard_organization_authority_epoch\(\)[\s\S]*NEW\.authority_epoch < OLD\.authority_epoch[\s\S]*NEW\.authority_epoch > OLD\.authority_epoch \+ 1/u);
  assert.match(sql, /CREATE TRIGGER organizations_authority_epoch_forward_only[\s\S]*BEFORE UPDATE OF authority_epoch ON organizations/u);
  assert.match(sql, /organization_id and never accepts an arbitrary epoch value/u);
});
