import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { validateTap, verifyEvidence } from "./postgres-qualification-evidence.mjs";

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

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
