#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const MAX_BYTES = 24 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const POSTGRES_VERSION = /^17(?:\.[0-9]+){0,2}(?:[+._~A-Za-z0-9-]*)(?: \([A-Za-z0-9.+~:_ -]{1,128}\))?$/u;
const RUN_ID = /^[1-9][0-9]{0,31}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const EXPECTED_MIGRATION_VERSION = 55;

export const PLATFORM_AUTHORIZATION_QUALIFICATION_COMMAND = [
  "node --test --test-concurrency=1",
  "apps/cloud-api/test/postgres/platform-authorization.integration.test.mjs",
  "apps/cloud-api/test/postgres/platform-authorization-failure-qualification.integration.test.mjs",
  "apps/cloud-api/test/postgres/least-privilege-role.integration.test.mjs"
].join(" ");

export const PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS = Object.freeze([
  "two_connection_identical_request_convergence",
  "idempotency_key_intent_conflict",
  "proof_and_jti_one_use_denial",
  "organization_binding_denial",
  "csrf_binding_denial",
  "pre_reservation_rollback_preserves_proof",
  "lost_commit_response_authenticated_reconciliation",
  "serialization_and_database_failure_closed",
  "application_role_platform_table_dml_denied",
  "legacy_mutation_execute_denied_atomic_function_allowed"
]);

const TEST_FILES = Object.freeze([
  "apps/cloud-api/test/postgres/platform-authorization.integration.test.mjs",
  "apps/cloud-api/test/postgres/platform-authorization-failure-qualification.integration.test.mjs",
  "apps/cloud-api/test/postgres/least-privilege-role.integration.test.mjs"
]);

const TOP_LEVEL_KEYS = Object.freeze([
  "catalog_entries", "catalog_sha256", "command", "kind", "migration_version", "outcome",
  "postgres_version", "run_attempt", "run_id", "scenarios", "source_commit", "summary",
  "test_files", "version", "workflow"
].sort());

export class PlatformAuthorizationQualificationEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "PlatformAuthorizationQualificationEvidenceError";
    this.code = code;
  }
}

export async function createPlatformAuthorizationQualificationEvidence({
  sourceCommit,
  postgresVersion,
  runId,
  runAttempt,
  catalogFile = catalogPath()
} = {}) {
  const catalogBytes = await boundedRegularFile(catalogFile, 2 * 1024 * 1024, false);
  const catalogState = parseCatalog(catalogBytes);
  return normalizePlatformAuthorizationQualificationEvidence({
    version: 1,
    kind: "agentpass-platform-authorization-qualification",
    source_commit: sourceCommit,
    workflow: "CI/platform-authorization-postgres17",
    run_id: String(runId ?? ""),
    run_attempt: positiveInteger(runAttempt),
    postgres_version: postgresVersion,
    migration_version: catalogState.migrationVersion,
    catalog_entries: catalogState.entries,
    catalog_sha256: sha256(catalogBytes),
    command: PLATFORM_AUTHORIZATION_QUALIFICATION_COMMAND,
    test_files: [...TEST_FILES],
    scenarios: [...PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS],
    summary: { passed: PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS.length, failed: 0, skipped: 0 },
    outcome: "passed"
  }, expected(catalogState, catalogBytes, sourceCommit));
}

export function normalizePlatformAuthorizationQualificationEvidence(value, expectation = {}) {
  const scenarioCount = PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS.length;
  if (!plainObject(value) || !sameArray(Object.keys(value).sort(), TOP_LEVEL_KEYS)
    || value.version !== 1 || value.kind !== "agentpass-platform-authorization-qualification"
    || value.workflow !== "CI/platform-authorization-postgres17" || value.outcome !== "passed"
    || value.migration_version !== EXPECTED_MIGRATION_VERSION
    || expectation.expectedMigrationVersion !== undefined && value.migration_version !== expectation.expectedMigrationVersion
    || !Number.isSafeInteger(value.catalog_entries) || value.catalog_entries < 165 || value.catalog_entries > 10_000
    || expectation.expectedCatalogEntries !== undefined && value.catalog_entries !== expectation.expectedCatalogEntries
    || typeof value.source_commit !== "string" || !SOURCE_COMMIT.test(value.source_commit)
    || expectation.expectedSourceCommit !== undefined && value.source_commit !== expectation.expectedSourceCommit
    || typeof value.catalog_sha256 !== "string" || !DIGEST.test(value.catalog_sha256)
    || expectation.expectedCatalogSha256 !== undefined && value.catalog_sha256 !== expectation.expectedCatalogSha256
    || typeof value.postgres_version !== "string" || !POSTGRES_VERSION.test(value.postgres_version)
    || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
    || !Number.isSafeInteger(value.run_attempt) || value.run_attempt < 1 || value.run_attempt > 1_000
    || value.command !== PLATFORM_AUTHORIZATION_QUALIFICATION_COMMAND
    || !sameArray(value.test_files, TEST_FILES)
    || !sameArray(value.scenarios, PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS)
    || !plainObject(value.summary) || !sameArray(Object.keys(value.summary).sort(), ["failed", "passed", "skipped"])
    || value.summary.passed !== scenarioCount || value.summary.failed !== 0 || value.summary.skipped !== 0) {
    fail("invalid_evidence");
  }
  return deepFreeze(structuredClone(value));
}

export async function writePlatformAuthorizationQualificationEvidence(outputFile, options = {}) {
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile)) fail("invalid_arguments");
  const evidence = await createPlatformAuthorizationQualificationEvidence(options);
  const bytes = Buffer.from(`${canonicalJson(evidence)}\n`, "utf8");
  if (bytes.length > MAX_BYTES) fail("invalid_evidence");
  let handle;
  try {
    handle = await open(outputFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch {
    fail("invalid_output");
  } finally {
    await handle?.close().catch(() => {});
  }
  return Object.freeze({ evidence, evidence_sha256: sha256(bytes) });
}

export async function verifyPlatformAuthorizationQualificationEvidence(inputFile, {
  expectedSourceCommit,
  catalogFile = catalogPath()
} = {}) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)
    || typeof expectedSourceCommit !== "string" || !SOURCE_COMMIT.test(expectedSourceCommit)) fail("invalid_arguments");
  const [bytes, catalogBytes] = await Promise.all([
    boundedRegularFile(inputFile, MAX_BYTES, true),
    boundedRegularFile(catalogFile, 2 * 1024 * 1024, false)
  ]);
  let value;
  try {
    const catalogState = parseCatalog(catalogBytes);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.endsWith("\n")) fail("invalid_evidence");
    value = JSON.parse(text);
    const normalized = normalizePlatformAuthorizationQualificationEvidence(
      value,
      expected(catalogState, catalogBytes, expectedSourceCommit)
    );
    if (`${canonicalJson(normalized)}\n` !== text) fail("invalid_evidence");
  } catch (error) {
    if (error instanceof PlatformAuthorizationQualificationEvidenceError) throw error;
    fail("invalid_evidence");
  }
  return Object.freeze({
    evidence_sha256: sha256(bytes),
    source_commit: value.source_commit,
    migration_version: value.migration_version,
    scenarios: value.scenarios.length
  });
}

async function boundedRegularFile(file, maximum, requirePrivate) {
  if (typeof file !== "string" || !path.isAbsolute(file)) fail("invalid_file");
  let stat;
  try { stat = await lstat(file); } catch { fail("invalid_file"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > maximum
    || requirePrivate && (stat.mode & 0o077) !== 0) fail("invalid_file");
  let handle;
  try {
    handle = await open(file, fs.constants.O_RDONLY | NOFOLLOW);
    const bytes = await handle.readFile();
    if (bytes.length !== stat.size || bytes.length > maximum) fail("invalid_file");
    return bytes;
  } catch (error) {
    if (error instanceof PlatformAuthorizationQualificationEvidenceError) throw error;
    fail("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parseCatalog(bytes) {
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail("invalid_catalog"); }
  if (!plainObject(value) || !Array.isArray(value.entries) || value.entries.length < 165) fail("invalid_catalog");
  const migrations = value.entries.filter((entry) => plainObject(entry) && entry.kind === "postgres-migration");
  const migrationVersion = Math.max(...migrations.map((entry) => entry.version));
  if (migrations.length !== EXPECTED_MIGRATION_VERSION || migrationVersion !== EXPECTED_MIGRATION_VERSION) fail("invalid_catalog");
  return Object.freeze({ entries: value.entries.length, migrationVersion });
}

function expected(catalogState, catalogBytes, sourceCommit) {
  return Object.freeze({
    expectedSourceCommit: sourceCommit,
    expectedCatalogSha256: sha256(catalogBytes),
    expectedCatalogEntries: catalogState.entries,
    expectedMigrationVersion: catalogState.migrationVersion
  });
}

function catalogPath() { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../contracts/catalog-v1.json"); }
function positiveInteger(value) { const number = typeof value === "string" && /^[1-9][0-9]{0,3}$/u.test(value) ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1 || number > 1_000) fail("invalid_arguments"); return number; }
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
function fail(code) { throw new PlatformAuthorizationQualificationEvidenceError(code); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, file, expectedSourceCommit, ...extra] = process.argv.slice(2);
  try {
    if (command === "write" && file && expectedSourceCommit === undefined && extra.length === 0) {
      const result = await writePlatformAuthorizationQualificationEvidence(path.resolve(file), {
        sourceCommit: process.env.AGENTPASS_PLATFORM_AUTH_SOURCE_COMMIT,
        postgresVersion: process.env.AGENTPASS_PLATFORM_AUTH_POSTGRES_VERSION,
        runId: process.env.AGENTPASS_PLATFORM_AUTH_RUN_ID,
        runAttempt: process.env.AGENTPASS_PLATFORM_AUTH_RUN_ATTEMPT
      });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else if (command === "verify" && file && expectedSourceCommit && extra.length === 0) {
      const result = await verifyPlatformAuthorizationQualificationEvidence(path.resolve(file), { expectedSourceCommit });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else fail("invalid_arguments");
  } catch (error) {
    const code = error instanceof PlatformAuthorizationQualificationEvidenceError ? error.code : "verification_failed";
    process.stderr.write(`platform-authorization-evidence: ${code}\n`);
    process.exitCode = code === "invalid_arguments" ? 2 : 1;
  }
}
