import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0047_platform_promotion_issuance.sql", import.meta.url);
const approvalsMigrationUrl = new URL("../../../../contracts/postgres/0044_platform_promotion_approvals.sql", import.meta.url);
const workflowUrl = new URL("../../../../.github/workflows/external-qualification-runners.yml", import.meta.url);

async function c3Sql() {
  const [approvals, issuance] = await Promise.all([
    readFile(approvalsMigrationUrl, "utf8"),
    readFile(migrationUrl, "utf8"),
  ]);
  return `${approvals}\n${issuance}`;
}

test("C3 promotion authority cannot bypass approval/candidate/signer fences through direct INSERT", async () => {
  const sql = await c3Sql();
  const guard = sql.match(/CREATE FUNCTION agentpass_guard_platform_promotion_issuance\(\)[\s\S]*?CREATE TRIGGER platform_promotion_issuances_guard[\s\S]*?EXECUTE FUNCTION agentpass_guard_platform_promotion_issuance\(\);/u)?.[0];

  assert.ok(guard, "the promotion issuance guard must be present");
  assert.match(guard, /IF TG_OP = 'INSERT'[\s\S]*?approval_row\.decision IS DISTINCT FROM 'approved'/u);
  assert.match(guard, /candidate\.status = 'active'/u);
  assert.match(guard, /key\.state = 'active'/u);
  assert.match(guard, /CREATE TRIGGER platform_promotion_issuances_guard\s+BEFORE INSERT OR UPDATE OR DELETE/u);

  const reservedCheck = sql.match(/CHECK \(\(state = 'reserved'[\s\S]*?\)\n    OR \(state = 'uncertain'/u)?.[0];
  assert.match(reservedCheck ?? "", /claim_token_digest IS NOT NULL/u);
  assert.match(sql, /provider_operation_id text NOT NULL/u);
});

test("C3 approval and issuance relations are structurally tenant/deployment bound", async () => {
  const sql = await c3Sql();

  assert.match(sql, /PRIMARY KEY \(deployment_id, environment\)/u);
  assert.match(sql, /FOREIGN KEY \(deployment_id, environment\)[\s\S]*?REFERENCES platform_promotion_deployments/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, provider_operation_id\)/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, candidate_id, idempotency_key\)/u);
  assert.match(sql, /platform_promotion_issuances_one_open[\s\S]*?WHERE state IN \('reserved', 'uncertain'\)/u);
});

test("C3 public views expose bounded promotion summaries", async () => {
  const sql = await c3Sql();
  assert.match(sql, /CREATE VIEW platform_promotion_approvals_public[\s\S]*?FROM platform_promotion_approvals/u);
  assert.match(sql, /CREATE VIEW platform_promotion_issuances_public[\s\S]*?FROM platform_promotion_issuances/u);
  assert.doesNotMatch(sql, /claim_token_digest,|evidence_bytes,/u);
});

test("C3 direct SQL cannot skip the claim lifecycle or regress deployment generation", async () => {
  const sql = await c3Sql();

  assert.match(sql, /NEW\.current_generation < OLD\.current_generation/u);
  assert.match(sql, /NEW\.current_generation > OLD\.current_generation \+ 1/u);
  assert.match(sql, /NEW\.current_candidate_id IS DISTINCT FROM OLD\.current_candidate_id/u);
  assert.match(sql, /state = 'reserved'[\s\S]*?claim_token_digest IS NOT NULL/u);
  assert.match(sql, /state = 'committed'[\s\S]*?evidence_digest IS NOT NULL/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, candidate_id, idempotency_key\)/u);
  assert.match(sql, /WHERE state IN \('reserved', 'uncertain'\)/u);
});

test("C3 service ACLs are centralized in the role contract", async () => {
  const roles = await readFile(new URL("../../../../scripts/postgres/roles.sql", import.meta.url), "utf8");
  assert.match(roles, /platform_promotion_approvals/u);
  assert.match(roles, /platform_promotion_issuances/u);
  assert.match(roles, /platform_promotion_deployments/u);
  assert.match(roles, /REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC/u);
  assert.match(roles, /GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO agentpass_migrator/u);
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
  const ci = await readFile(new URL("../../../../.github/workflows/ci.yml", import.meta.url), "utf8");

  assert.equal((workflow.match(/postgres-authority-(?:16|17)/gu) ?? []).length >= 4, true);
  assert.equal((workflow.match(/qualification:postgres-c3:external/gu) ?? []).length, 2);
  assert.equal((workflow.match(/external-postgres-(?:16|17)-qualification-/gu) ?? []).length >= 4, true);
  assert.match(workflow, /AGENTPASS_C3_BACKUP_PITR_EVIDENCE/u);
  assert.match(workflow, /GITHUB_RUN_ID/iu);
  assert.match(ci, /postgres-integration:/u);
  assert.doesNotMatch(ci.slice(ci.indexOf("  postgres-integration:")), /c3-migration-0047-(?:qualification|adversarial)\.test\.mjs/u);
  assert.match(workflow, /if-no-files-found: error/iu);
});
