#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const TYPE = "agentpass.database-schema-evidence";
const KEYS = Object.freeze([
  "version", "type", "environment", "deployment_id", "revision", "source_commit", "source_tree",
  "database_schema_digest", "measured_at", "transaction_isolation", "measurement_id", "readiness_code"
]);
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const SHA = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RUN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const MAX_AGE_MS = 15 * 60 * 1000;

export class DatabaseSchemaEvidenceError extends Error {
  constructor(code) { super(code); this.name = "DatabaseSchemaEvidenceError"; this.code = code; }
}

export function normalizeDatabaseSchemaEvidence(input, { now = Date.now(), maxAgeMs = MAX_AGE_MS } = {}) {
  exactObject(input, KEYS);
  if (input.version !== 1 || input.type !== TYPE || !["staging", "production"].includes(input.environment)
    || !ID.test(input.deployment_id) || !ID.test(input.revision) || !COMMIT.test(input.source_commit)
    || !COMMIT.test(input.source_tree) || !SHA.test(input.database_schema_digest) || !TIME.test(input.measured_at)
    || input.transaction_isolation !== "repeatable_read" || !RUN.test(input.measurement_id)
    || input.readiness_code !== "ready") throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_INPUT");
  const measured = Date.parse(input.measured_at);
  if (!Number.isFinite(measured) || measured > now || now - measured > maxAgeMs) throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_STALE");
  return Object.freeze({ ...input });
}

export function databaseSchemaEvidenceSHA256(input, options = {}) {
  return crypto.createHash("sha256").update(canonicalJson(normalizeDatabaseSchemaEvidence(input, options)), "utf8").digest("hex");
}

export function verifyDatabaseSchemaEvidence(input, { expected = {}, now = Date.now() } = {}) {
  const evidence = normalizeDatabaseSchemaEvidence(input, { now });
  for (const key of ["environment", "deployment_id", "revision", "source_commit", "source_tree", "database_schema_digest"]) {
    if (expected[key] !== undefined && evidence[key] !== expected[key]) throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_BINDING");
  }
  return Object.freeze({ ...evidence, evidence_sha256: databaseSchemaEvidenceSHA256(evidence, { now, maxAgeMs: MAX_AGE_MS }) });
}

export function readDatabaseSchemaEvidence(filePath, options = {}) {
  if (typeof filePath !== "string" || !filePath.startsWith("/")) throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_INPUT");
  try { return verifyDatabaseSchemaEvidence(JSON.parse(fs.readFileSync(filePath, "utf8")), options); } catch (error) {
    if (error instanceof DatabaseSchemaEvidenceError) throw error;
    throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_INPUT");
  }
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new DatabaseSchemaEvidenceError("ERR_DATABASE_SCHEMA_EVIDENCE_INPUT");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [inputPath, expectedJson] = process.argv.slice(2);
  if (!inputPath || expectedJson === undefined) throw new Error("Usage: database-schema-evidence.mjs EVIDENCE.json EXPECTED.json");
  const expected = JSON.parse(expectedJson);
  process.stdout.write(`${JSON.stringify(readDatabaseSchemaEvidence(inputPath, { expected }))}\n`);
}
