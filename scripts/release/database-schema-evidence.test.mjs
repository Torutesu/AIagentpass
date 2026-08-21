import assert from "node:assert/strict";
import test from "node:test";
import { databaseSchemaEvidenceSHA256, verifyDatabaseSchemaEvidence } from "./database-schema-evidence.mjs";

const NOW = Date.parse("2026-08-20T00:00:00.000Z");
const value = () => ({ version: 1, type: "agentpass.database-schema-evidence", environment: "staging", deployment_id: "deployment-1", revision: "revision-1", source_commit: "a".repeat(40), source_tree: "b".repeat(40), database_schema_digest: "c".repeat(64), measured_at: "2026-08-19T23:59:00.000Z", transaction_isolation: "repeatable_read", measurement_id: "readiness-100", readiness_code: "ready" });

test("verifies fresh database schema evidence and exact deployment binding", () => {
  const result = verifyDatabaseSchemaEvidence(value(), { now: NOW, expected: { deployment_id: "deployment-1", source_tree: "b".repeat(40), database_schema_digest: "c".repeat(64) } });
  assert.equal(result.evidence_sha256, databaseSchemaEvidenceSHA256(value(), { now: NOW }));
});

test("rejects stale, wrong-isolation, unknown-field, and substituted evidence", () => {
  assert.throws(() => verifyDatabaseSchemaEvidence({ ...value(), measured_at: "2026-08-19T23:00:00.000Z" }, { now: NOW }), /ERR_DATABASE_SCHEMA_EVIDENCE_STALE/u);
  assert.throws(() => verifyDatabaseSchemaEvidence({ ...value(), transaction_isolation: "read_committed" }, { now: NOW }), /ERR_DATABASE_SCHEMA_EVIDENCE_INPUT/u);
  assert.throws(() => verifyDatabaseSchemaEvidence({ ...value(), extra: true }, { now: NOW }), /ERR_DATABASE_SCHEMA_EVIDENCE_INPUT/u);
  assert.throws(() => verifyDatabaseSchemaEvidence(value(), { now: NOW, expected: { revision: "other" } }), /ERR_DATABASE_SCHEMA_EVIDENCE_BINDING/u);
});
