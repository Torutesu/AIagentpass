import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0047_platform_promotion_issuance.sql", import.meta.url);
const workflowUrl = new URL("../../../../.github/workflows/ci.yml", import.meta.url);

test("C3 promotion authority cannot bypass approval/provider fences through direct INSERT", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const guard = sql.match(/CREATE FUNCTION agentpass_guard_platform_promotion_issuance\(\)[\s\S]*?CREATE TRIGGER platform_promotion_issuances_guard[\s\S]*?EXECUTE FUNCTION agentpass_guard_platform_promotion_issuance\(\);/u)?.[0];

  assert.ok(guard, "the promotion issuance guard must be present");
  assert.match(guard, /IF \(TG_OP = 'INSERT' AND NEW\.state = 'reserved' AND approval_expires_at <= clock_timestamp\(\)\)/u);
  assert.match(guard, /NEW\.state = 'committed'[\s\S]*?provider_state <> 'committed' OR provider_expires_at <= clock_timestamp\(\)/u);
  assert.match(guard, /CREATE TRIGGER platform_promotion_issuances_guard\s+BEFORE INSERT OR UPDATE OR DELETE/u);

  const reservedCheck = sql.match(/CHECK \(\(state = 'reserved'[\s\S]*?\)\n    OR \(state = 'uncertain'/u)?.[0];
  assert.match(reservedCheck ?? "", /provider_operation_id IS NOT NULL/u);
});

test("C3 FORCE RLS exposes only explicit runtime and backup policies", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  for (const relation of ["platform_promotion_approvals", "platform_promotion_issuances", "platform_deployment_state", "platform_promotion_audit_events"]) {
    assert.match(sql, new RegExp(`ALTER TABLE ${relation} ENABLE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ALTER TABLE ${relation} FORCE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`${relation}_backup_select[\\s\\S]*?TO agentpass_backup`, "u"));
  }
  assert.match(sql, /agentpass_app[\s\S]*?agentpass_backup[\s\S]*?CREATE POLICY/u);
});

test("C3 audit rows cannot be truncated and both security digests are database-verified", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const auditGuard = sql.match(/CREATE FUNCTION agentpass_guard_platform_promotion_audit_event\(\)[\s\S]*?CREATE TRIGGER platform_promotion_audit_events_guard[\s\S]*?EXECUTE FUNCTION agentpass_guard_platform_promotion_audit_event\(\);/u)?.[0];

  assert.ok(auditGuard, "the audit append-only guard must be present");
  assert.match(auditGuard, /NEW\.event_hash IS DISTINCT FROM agentpass_platform_promotion_audit_event_hash\(/u);
  assert.match(auditGuard, /platform_promotion_audit_events_event_hash/u);
  assert.match(sql, /CREATE TRIGGER platform_promotion_audit_events_guard\s+BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_audit_events/u);
  assert.doesNotMatch(sql, /CREATE TRIGGER platform_promotion_audit_events_guard\s+BEFORE UPDATE OR DELETE ON platform_promotion_audit_events/u);
  assert.match(sql, /CREATE TRIGGER platform_promotion_audit_events_truncate_guard\s+BEFORE TRUNCATE ON platform_promotion_audit_events\s+FOR EACH STATEMENT\s+EXECUTE FUNCTION agentpass_guard_platform_promotion_audit_event\(\);/u);
  assert.match(sql, /REVOKE TRUNCATE ON TABLE platform_promotion_audit_events FROM agentpass_app, agentpass_backup/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_audit_details_safe\(p_value jsonb\)[\s\S]*?jsonb_each\(p_value\)[\s\S]*?token\)[\s\S]*?-----BEGIN/u);
  assert.match(sql, /agentpass_platform_promotion_audit_details_safe\(details\)/u);

  const issuanceGuard = sql.match(/CREATE FUNCTION agentpass_guard_platform_promotion_issuance\(\)[\s\S]*?CREATE TRIGGER platform_promotion_issuances_guard[\s\S]*?EXECUTE FUNCTION agentpass_guard_platform_promotion_issuance\(\);/u)?.[0];
  assert.ok(issuanceGuard, "the issuance authority guard must be present");
  assert.match(issuanceGuard, /NEW\.authority_digest IS DISTINCT FROM agentpass_platform_promotion_authority_digest\(/u);
  assert.match(issuanceGuard, /platform_promotion_issuances_authority_digest/u);
});

test("C3 direct SQL cannot skip the claim lifecycle or replay a stale deployment generation", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /TG_OP = 'INSERT' AND NEW\.state <> 'reserved'/u);
  assert.match(sql, /platform_promotion_issuances_generation_fence/u);
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\(/u);
  assert.match(sql, /SELECT generation, state[\s\S]*?FROM platform_deployment_state[\s\S]*?FOR UPDATE/u);
  assert.match(sql, /NEW\.generation <> issuance_expected_generation \+ 1/u);
  assert.match(sql, /NEW\.evidence_digest IS DISTINCT FROM issuance_evidence_digest/u);
  assert.match(sql, /platform_deployment_state_rollback/u);
  assert.match(sql, /platform_deployment_disabled_immutable/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, idempotency_key\)/u);
  assert.match(sql, /WHERE state IN \('reserved', 'uncertain'\)/u);
});

test("C3 service ACLs are explicit and do not depend on a post-migration roles.sql replay", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const acl = sql.slice(sql.indexOf("REVOKE ALL PRIVILEGES ON TABLE\n  platform_promotion_approvals"));

  assert.match(acl, /FROM PUBLIC, agentpass_app, agentpass_backup/u);
  assert.match(acl, /GRANT SELECT ON TABLE platform_promotion_approvals,[\s\S]*?TO agentpass_app, agentpass_backup/u);
  assert.match(acl, /GRANT INSERT, UPDATE ON TABLE platform_promotion_issuances, platform_deployment_state TO agentpass_app/u);
  assert.match(acl, /GRANT INSERT ON TABLE platform_promotion_audit_events TO agentpass_app/u);
  assert.match(acl, /GRANT ALL PRIVILEGES ON TABLE[\s\S]*?TO agentpass_migrator/u);
});

test("real qualification contains role, contention, and rollback probes without raw error emission", async () => {
  const script = await readFile(new URL("../../../../scripts/qualification/postgres-c3-migration-0047.mjs", import.meta.url), "utf8");

  assert.match(script, /applyRoleContract/u);
  assert.match(script, /SET SESSION AUTHORIZATION/u);
  assert.match(script, /sourceTree/u);
  assert.match(script, /ciRunId/u);
  assert.match(script, /ciRunAttempt/u);
  assert.match(script, /assertRedactedQualificationEvidence/u);
  assert.match(script, /writeQualificationEvidence/u);
  assert.match(script, /runContentionProbe/u);
  assert.match(script, /generation_contention_single_winner/u);
  assert.match(script, /qualification_rollback_/u);
  assert.match(script, /assertQualificationTablesEmpty/u);
  assert.match(script, /status\.pending\.length !== 0/u);
  assert.match(script, /status\.modified\.length !== 0/u);
  assert.match(script, /status\.dirty === true/u);
  assert.match(script, /TRUNCATE TABLE platform_promotion_audit_events/u);
  assert.match(script, /agentpass_platform_promotion_authority_digest/u);
  assert.match(script, /agentpass_platform_promotion_audit_event_hash/u);
  assert.match(script, /verifyQualificationEvidence/u);
  assert.doesNotMatch(script, /process\.stdout\.write\([^\n]*error\.(?:message|stack)/u);
  assert.match(script, /CI_JOB_ID_PATTERN/u);
  assert.match(script, /expectedCiJobId/u);
  assert.match(script, /ci_job_id/u);
  assert.match(script, /GITHUB_JOB/u);
});

test("CI has one C3 qualification per authority major and preserves the separate integration lane", async () => {
  const workflow = await readFile(workflowUrl, "utf8");

  assert.equal((workflow.match(/AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR:/gu) ?? []).length, 2);
  assert.equal((workflow.match(/AGENTPASS_C3_REQUIRE_REAL_DATABASE: "1"/gu) ?? []).length, 2);
  assert.equal((workflow.match(/test "\$\(git rev-parse HEAD\)" = "\$GITHUB_SHA"/gu) ?? []).length, 2);
  assert.equal((workflow.match(/git rev-parse "\$\{GITHUB_SHA\}\^\{tree\}"/gu) ?? []).length, 8);
  assert.equal((workflow.match(/postgres-c3-migration-0047\.mjs verify/gu) ?? []).length, 2);
  assert.equal((workflow.match(/AGENTPASS_C3_CI_JOB_ID: \$\{\{ github\.job \}\}/gu) ?? []).length, 2);
  assert.equal((workflow.match(/--dbname=agentpass_c3_16/gu) ?? []).length, 2);
  assert.equal((workflow.match(/--dbname=agentpass_c3_17/gu) ?? []).length, 2);
  assert.equal((workflow.match(/archive-secret-scan\.mjs .*c3-migration-0047-evidence\/postgres-(?:16|17)\.json/gu) ?? []).length, 2);
  assert.equal((workflow.match(/docker run --detach --name "\$pitr_container" --user "\$\(id -u\):\$\(id -g\)"/gu) ?? []).length, 2);
  assert.equal((workflow.match(/trap 'docker rm --force "\$pitr_container"[^\n]*' EXIT/gu) ?? []).length, 2);
  assert.doesNotMatch(workflow.slice(workflow.indexOf("  postgres-integration:")), /c3-migration-0047-(?:qualification|adversarial)\.test\.mjs/u);
  assert.match(workflow, /GITHUB_RUN_ID/iu);
  assert.match(workflow, /GITHUB_RUN_ATTEMPT/iu);
  assert.match(workflow, /if-no-files-found: error/iu);
});
