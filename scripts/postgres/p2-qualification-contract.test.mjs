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

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("P2 qualification contract keeps security probes on agentpass_app", () => {
  const integration = fs.readFileSync(INTEGRATION_FILE, "utf8");
  assert.match(integration, /AGENTPASS_TEST_APP_DATABASE_URL/u);
  assert.match(integration, /assertIdentity\(appPool, "agentpass_app"\)/u);
  assert.match(integration, /has_table_privilege\(current_user/u);
  assert.match(integration, /await appClient\.query\("BEGIN"\)/u);
  assert.match(integration, /const insertEvent = \(values\) => appClient\.query\(`/u);
  assert.match(integration, /await appClient\.query\("SELECT count\(\*\)::int AS count FROM device_audit_events"\)/u);
  assert.doesNotMatch(integration, /const pool = new Pool\(\{ connectionString: DATABASE_URL/u);
});

test("P2 evidence contract records exact administrator and application identities", () => {
  const evidence = fs.readFileSync(EVIDENCE_FILE, "utf8");
  const ci = fs.readFileSync(CI_FILE, "utf8");
  assert.match(evidence, /SELECT session_user, current_user/u);
  assert.match(evidence, /role_assertions/u);
  assert.match(evidence, /agentpass_app/u);
  assert.match(evidence, /report\.service\.role_assertions/u);
  assert.match(ci, /AGENTPASS_QUALIFICATION_ADMIN_ROLE="postgres"/u);
  assert.match(ci, /\.service\.role_assertions/u);
  assert.match(ci, /scripts\/postgres\/p2-qualification-contract\.test\.mjs/u);
});

test("P2 TAP validation fails closed on skips, TODOs, and missing plans", () => {
  const passingTap = Buffer.from("TAP version 13\n1..1\nok 1 - app role\n");
  assert.deepEqual(validateTap(passingTap), { tests: 1, tap_sha256: digest(passingTap) });
  for (const invalidTap of [
    "TAP version 13\n1..1\nok 1 - skipped # SKIP missing app URL\n",
    "TAP version 13\n1..1\nok 1 - incomplete # TODO\n",
    "TAP version 13\nok 1 - no plan\n",
    "Bail out! connection failed\n",
  ]) {
    assert.throws(() => validateTap(Buffer.from(invalidTap)));
  }
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
        head_checksum: POSTGRES_SCHEMA_HEAD.checksum,
        migrations_sha256: digest(JSON.stringify(POSTGRES_SCHEMA_HEAD.migrations)),
      },
      service: {
        ssl: true,
        roles: ["agentpass_app", "agentpass_backup", "agentpass_maintenance", "agentpass_migrator", "agentpass_signer"],
        role_assertions: [
          { connection: "admin", expected_role: "postgres", session_user: "postgres", current_user: "postgres" },
          { connection: "app", expected_role: "agentpass_app", session_user: "agentpass_app", current_user: "agentpass_app" },
        ],
        forced_rls_relations: 3,
        device_audit_triggers: 2,
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
