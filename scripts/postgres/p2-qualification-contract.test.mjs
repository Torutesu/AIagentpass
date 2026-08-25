import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { validateTap, verifyEvidence } from "./postgres-qualification-evidence.mjs";

const REPOSITORY_ROOT = path.resolve(new URL("../..", import.meta.url).pathname);
const INTEGRATION_FILE = path.join(REPOSITORY_ROOT, "scripts/postgres/device-audit-postgres-qualification.integration.test.mjs");
const EVIDENCE_FILE = path.join(REPOSITORY_ROOT, "scripts/postgres/postgres-qualification-evidence.mjs");
const CI_FILE = path.join(REPOSITORY_ROOT, ".github/workflows/ci.yml");
const ACTION_FILE = path.join(REPOSITORY_ROOT, ".github/actions/postgres-authority-qualification/action.yml");

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("P2 qualification contract keeps security probes on agentpass_app", () => {
  const integration = fs.readFileSync(INTEGRATION_FILE, "utf8");
  assert.match(integration, /AGENTPASS_TEST_APP_DATABASE_URL/u);
  assert.match(integration, /async function assertTls/u);
  assert.match(integration, /pg_stat_ssl WHERE pid = pg_backend_pid\(\)/u);
  assert.match(integration, /await assertTls\(maintenancePool, "maintenance"\)/u);
  assert.match(integration, /assertIdentity\(appPool, "agentpass_app"\)/u);
  assert.match(integration, /has_table_privilege\(current_user/u);
  assert.match(integration, /await appClient\.query\("BEGIN"\)/u);
  assert.match(integration, /agentpass_authorize_device_audit_tenant/u);
  assert.match(integration, /other-tenant-populated-event/u);
  assert.match(integration, /cross-tenant-write/u);
  assert.match(integration, /set_config\('agentpass\.organization_id'/u);
  assert.match(integration, /const insertEvent = \(values\) => appClient\.query\(`/u);
  assert.match(integration, /await appClient\.query\("SELECT count\(\*\)::int AS count FROM device_audit_events"\)/u);
  assert.doesNotMatch(integration, /const pool = new Pool\(\{ connectionString: DATABASE_URL/u);
});

test("P2 evidence contract records exact administrator and application identities", () => {
  const evidence = fs.readFileSync(EVIDENCE_FILE, "utf8");
  const ci = fs.readFileSync(CI_FILE, "utf8");
  const action = fs.readFileSync(ACTION_FILE, "utf8");
  assert.match(evidence, /SELECT session_user, current_user/u);
  assert.match(evidence, /role_assertions/u);
  assert.match(evidence, /agentpass_app/u);
  assert.match(evidence, /report\.service\.role_assertions/u);
  assert.match(evidence, /device_audit_inbox_authority/u);
  assert.match(evidence, /assert\.equal\(row\.app_can_claim_inbox, false\)/u);
  assert.match(evidence, /assert\.equal\(row\.maintenance_can_settle_inbox, true\)/u);
  assert.match(evidence, /platform_device_audit_tenant_context/u);
  assert.match(evidence, /tenant_authority_functions/u);
  assert.match(action, /AGENTPASS_QUALIFICATION_ADMIN_ROLE="postgres"/u);
  assert.match(action, /AGENTPASS_TEST_MAINTENANCE_DATABASE_URL="\$N1_MAINTENANCE_DATABASE_URL"/u);
  assert.match(evidence, /AGENTPASS_TEST_MAINTENANCE_DATABASE_URL/u);
  assert.match(evidence, /connection: "maintenance"/u);
  assert.match(ci, /uses: \.\/\.github\/actions\/postgres-authority-qualification/u);
  assert.match(action, /scripts\/postgres\/p2-qualification-contract\.test\.mjs/u);
  assert.match(action, /postgres-qualification-evidence\.mjs verify/u);
});

test("P2 TAP validation requires a complete, passing, count-consistent envelope", () => {
  const passingTap = Buffer.from("TAP version 13\n1..1\nok 1 - app role\n");
  assert.deepEqual(validateTap(passingTap), { tests: 1, tap_sha256: digest(passingTap) });

  const nestedPassingTap = Buffer.from([
    "TAP version 13",
    "# Subtest: app role",
    "    1..1",
    "    ok 1 - identity",
    "ok 1 - Subtest: app role",
    "# Subtest: RLS",
    "    1..1",
    "    ok 1 - tenant isolation",
    "ok 2 - Subtest: RLS",
    "1..2",
    "# tests 2",
    "# pass 2",
    ""
  ].join("\n"));
  assert.equal(validateTap(nestedPassingTap).tests, 2);

  for (const invalidTap of [
    "TAP version 13\n1..1\nok 1 - skipped # SKIP missing app URL\n",
    "TAP version 13\n1..1\nok 1 - incomplete # TODO\n",
    "TAP version 13\n1..1\nnot ok 1 - failed\n",
    "TAP version 13\n    not ok 1 - nested failure\n1..1\nok 1 - wrapper\n",
    "TAP version 13\n1..2\nok 1 - only one\n",
    "TAP version 13\n1..1\nok 1 - one\n1..1\n",
    "1..1\nok 1 - no TAP version\n",
    "Bail out! connection failed\n",
  ]) {
    assert.throws(() => validateTap(Buffer.from(invalidTap)));
  }
});

test("P2 TAP evidence hashes the exact valid input bytes deterministically", () => {
  const tap = Buffer.from("TAP version 13\r\n1..1\r\nok 1 - app role\r\n", "utf8");
  const first = validateTap(tap);
  const second = validateTap(Buffer.from(tap));
  assert.deepEqual(first, second);
  assert.equal(first.tap_sha256, digest(tap));
});

test("P2 canonical evidence rejects missing or mismatched role assertions", () => {
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-p2-evidence-"));
  try {
    const tap = Buffer.from("TAP version 13\n1..1\nok 1 - app role\n");
    const report = {
      schema_version: 1,
      kind: "agentpass.postgres.real-service.qualification",
      candidate_id: "p2-contract",
      source_commit: "a".repeat(40),
      schema: {
        head: POSTGRES_SCHEMA_HEAD.version,
        migration_count: POSTGRES_SCHEMA_HEAD.migration_count,
        head_name: POSTGRES_SCHEMA_HEAD.name,
        head_checksum: POSTGRES_SCHEMA_HEAD.checksum,
        migrations_sha256: digest(JSON.stringify(POSTGRES_SCHEMA_HEAD.migrations)),
      },
      service: {
        ssl: true,
        roles: ["agentpass_app", "agentpass_backup", "agentpass_maintenance", "agentpass_migrator", "agentpass_signer"],
        role_assertions: [
          { connection: "admin", expected_role: "postgres", session_user: "postgres", current_user: "postgres", ssl: true },
          { connection: "app", expected_role: "agentpass_app", session_user: "agentpass_app", current_user: "agentpass_app", ssl: true },
          { connection: "maintenance", expected_role: "agentpass_maintenance", session_user: "agentpass_maintenance", current_user: "agentpass_maintenance", ssl: true },
        ],
        forced_rls_relations: 3,
        device_audit_triggers: 2,
        tenant_authority: {
          relation: "platform_device_audit_tenant_context",
          security_definer_functions: 3,
          app_can_select_relation: false,
        },
        device_audit_inbox_authority: {
          app_can_enqueue: true,
          app_can_claim: false,
          app_can_settle: false,
          maintenance_can_claim: true,
          maintenance_can_settle: true,
          maintenance_can_health: true,
        },
      },
      suites: { tap: { tests: 1, tap_sha256: digest(tap) } },
      skipped_tests: 0,
      status: "passed",
    };
    const reportFile = path.join(tempDirectory, "report.json");
    fs.writeFileSync(reportFile, `${JSON.stringify(report)}\n`);
    assert.equal(verifyEvidence(reportFile, report.source_commit).service.role_assertions[1].current_user, "agentpass_app");
    report.service.role_assertions[1].current_user = "postgres";
    fs.writeFileSync(reportFile, `${JSON.stringify(report)}\n`);
    assert.throws(() => verifyEvidence(reportFile, report.source_commit));
  } finally {
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  }
});
