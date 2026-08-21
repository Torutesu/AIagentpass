import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0052_platform_operator_authority.sql", import.meta.url);
const readMigration = () => readFile(migrationUrl, "utf8");

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION ${name}(`);
  assert.notEqual(start, -1, `missing ${name}`);
  const end = sql.indexOf("\n$$;", start);
  assert.notEqual(end, -1, `unterminated ${name}`);
  return sql.slice(start, end + 4);
}

test("0052 is forward-only and never bootstraps authority from legacy promotion evidence", async () => {
  const sql = await readMigration();
  assert.match(sql, /^BEGIN;/u);
  assert.match(sql, /COMMIT;\s*$/u);
  assert.match(sql, /No row\s*\n-- is seeded here:[\s\S]*provisioned/iu);
  assert.match(sql, /does not read or backfill the legacy 0044/iu);
  assert.doesNotMatch(sql, /INSERT INTO platform_principals\s*\([^;]+?\)\s*SELECT/iu);
  assert.doesNotMatch(sql, /FROM\s+platform_promotion_approvals/iu);
});

test("0052 persists distinct principals, generation-bound assignments, and immutable approvals", async () => {
  const sql = await readMigration();
  for (const relation of [
    "platform_principals",
    "platform_operator_assignments",
    "platform_operator_assignment_approvals"
  ]) assert.match(sql, new RegExp(`CREATE TABLE ${relation} \\(`, "u"));
  assert.match(sql, /member_id uuid NOT NULL UNIQUE REFERENCES members\(id\)/u);
  assert.match(sql, /CHECK \(principal_id <> member_id\)/u);
  assert.match(sql, /authority_generation bigint NOT NULL DEFAULT 1 CHECK \(authority_generation > 0\)/u);
  assert.match(sql, /requested_authority_generation bigint NOT NULL CHECK \(requested_authority_generation > 0\)/u);
  assert.match(sql, /CHECK \(operation = capability\)/u);
  assert.match(sql, /approver_authority_generation bigint NOT NULL CHECK \(approver_authority_generation > 0\)/u);
  assert.match(sql, /platform_operator_assignments_one_effective[\s\S]*WHERE status IN \('active', 'suspended'\)/u);
  assert.match(sql, /platform_operator_assignments_one_pending[\s\S]*WHERE status = 'pending'/u);
  assert.match(sql, /NEW\.requested_authority_generation IS DISTINCT FROM OLD\.requested_authority_generation/u);
  assert.match(sql, /platform_operator_assignment_approvals_immutable/u);
  assert.match(sql, /approver_row\.member_id = assignment_row\.member_id/u);
});

test("0052 uses dual control, current approver generations, and target generation fencing", async () => {
  const sql = await readMigration();
  const activate = functionBody(sql, "agentpass_platform_operator_assignment_activate");
  const replace = functionBody(sql, "agentpass_platform_operator_assignment_replace");
  const approve = functionBody(sql, "agentpass_platform_operator_assignment_approve");
  for (const body of [activate, replace]) {
    assert.match(body, /active_approvals < 2/u);
    assert.match(body, /approval\.approver_authority_generation = approver\.authority_generation/u);
    assert.match(body, /approver\.member_id <>/u);
    assert.match(body, /authority_generation IS DISTINCT FROM .*requested_authority_generation/u);
    assert.match(body, /SET authority_generation = authority_generation \+ 1/u);
  }
  assert.match(approve, /p_approval_id uuid/u);
  assert.match(approve, /p_request_digest bytea/u);
  assert.match(approve, /approver_row\.member_id = assignment_row\.member_id/u);
  assert.doesNotMatch(approve, /approver_row\.authority_generation IS DISTINCT FROM assignment_row\.requested_authority_generation/u);
});

test("assignment and principal revocation advance generation once and preserve deterministic lock order", async () => {
  const sql = await readMigration();
  for (const name of [
    "agentpass_platform_operator_assignment_suspend",
    "agentpass_platform_operator_assignment_revoke"
  ]) {
    const body = functionBody(sql, name);
    const principalLock = body.indexOf("FROM platform_principals");
    const assignmentLock = body.indexOf("FROM platform_operator_assignments", body.indexOf("FOR UPDATE") + 1);
    assert.ok(principalLock >= 0 && assignmentLock > principalLock, `${name} must lock principal before assignment`);
    assert.match(body, /SET authority_generation = authority_generation \+ 1/u);
    assert.match(body, /status NOT IN|status <>/u);
  }
  const principalSuspend = functionBody(sql, "agentpass_platform_principal_suspend");
  assert.match(principalSuspend, /SET status = 'revoked'[\s\S]*AND status = 'pending'/u);
  assert.match(principalSuspend, /SET status = 'suspended'[\s\S]*AND status = 'active'/u);
});

test("five-argument lookup uses database time and current human-session epochs without organization-role authority", async () => {
  const sql = await readMigration();
  const lookup = functionBody(sql, "agentpass_platform_operator_assignment_find_active");
  assert.match(lookup, /p_organization_id uuid,[\s\S]*p_member_id uuid,[\s\S]*p_session_id uuid,[\s\S]*p_operation text,[\s\S]*p_capability text/u);
  assert.doesNotMatch(lookup.slice(0, lookup.indexOf("RETURNS jsonb")), /timestamptz|p_now/u);
  assert.match(lookup, /now_value timestamptz := clock_timestamp\(\)/u);
  assert.match(lookup, /organization\.authority_epoch = human_session\.organization_authority_epoch/u);
  assert.match(lookup, /membership\.session_epoch = human_session\.membership_session_epoch/u);
  assert.match(lookup, /membership\.status = 'active'/u);
  assert.match(lookup, /human_session\.revoked_at IS NULL/u);
  assert.match(lookup, /principal\.status = 'active'/u);
  assert.match(lookup, /operator_assignment\.status = 'active'/u);
  assert.doesNotMatch(lookup, /FOR (?:SHARE|UPDATE)/u);
  assert.doesNotMatch(lookup, /operator_assignment\.requested_authority_generation\s*=\s*principal\.authority_generation/u);
  assert.doesNotMatch(lookup, /membership\.role|role IN \('owner'|'admin'/u);
});

test("approval retries return the exact existing approval and reject conflicting replay", async () => {
  const sql = await readMigration();
  const approve = functionBody(sql, "agentpass_platform_operator_assignment_approve");
  assert.match(approve, /FROM platform_operator_assignment_approvals[\s\S]*assignment_id = p_assignment_id[\s\S]*approver_principal_id = p_approver_principal_id/u);
  assert.match(approve, /approval_row\.approval_id IS DISTINCT FROM p_approval_id/u);
  assert.match(approve, /RETURN jsonb_build_object\([\s\S]*'approval_id', approval_row\.approval_id/u);
});

test("0052 exposes only lookup to app and keeps every mutation migrator-only", async () => {
  const sql = await readMigration();
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_find_active\(uuid, uuid, uuid, text, text\) TO agentpass_migrator, agentpass_app/u);
  for (const name of [
    "agentpass_platform_principal_provision",
    "agentpass_platform_operator_assignment_request",
    "agentpass_platform_operator_assignment_approve",
    "agentpass_platform_operator_assignment_activate",
    "agentpass_platform_operator_assignment_suspend",
    "agentpass_platform_operator_assignment_revoke",
    "agentpass_platform_operator_assignment_replace",
    "agentpass_platform_principal_suspend",
    "agentpass_platform_principal_revoke"
  ]) {
    assert.match(sql, new RegExp(`GRANT EXECUTE ON FUNCTION ${name}\\([^;]+ TO agentpass_migrator;`, "u"));
    assert.doesNotMatch(sql, new RegExp(`GRANT EXECUTE ON FUNCTION ${name}\\([^;]+ TO [^;]*agentpass_app`, "u"));
  }
  const definerFunctions = [...sql.matchAll(/CREATE FUNCTION agentpass_platform_(?:principal|operator)[\s\S]*?SECURITY DEFINER/gmu)];
  assert.ok(definerFunctions.length >= 10);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/gmu) ?? []).length >= 13, true);
});
