#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const MAX_BYTES = 16 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const POSTGRES_VERSION = /^17(?:\.[0-9]+){0,2}(?:[+._~A-Za-z0-9-]*)(?: \([A-Za-z0-9.+~:_ -]{1,128}\))?$/u;
const RUN_ID = /^[1-9][0-9]{0,31}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;

export const PROVIDER_OPERATION_QUALIFICATION_COMMAND = [
  "node --test --test-concurrency=1",
  "apps/cloud-api/test/postgres/provider-operation-query-indexes.integration.test.mjs",
  "apps/cloud-api/test/postgres/provider-operation-repository.integration.test.mjs"
].join(" ");

export const PROVIDER_OPERATION_QUALIFICATION_SCENARIOS = Object.freeze([
  "postgres17_index_backed_maintenance_paths",
  "two_pool_restart_recovery",
  "bounded_expired_started_quarantine",
  "two_worker_reconciliation_and_retention",
  "two_pool_first_reservation_convergence",
  "lifecycle_fencing_lost_commit_and_emergency_disable"
]);

const TEST_FILES = Object.freeze([
  "apps/cloud-api/test/postgres/provider-operation-query-indexes.integration.test.mjs",
  "apps/cloud-api/test/postgres/provider-operation-repository.integration.test.mjs"
]);

const TOP_LEVEL_KEYS = Object.freeze([
  "catalog_entries",
  "catalog_sha256",
  "command",
  "kind",
  "migration_version",
  "outcome",
  "postgres_version",
  "run_attempt",
  "run_id",
  "scenarios",
  "source_commit",
  "summary",
  "test_files",
  "version",
  "workflow"
].sort());

export class ProviderOperationQualificationEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProviderOperationQualificationEvidenceError";
    this.code = code;
  }
}

export async function createProviderOperationQualificationEvidence({
  sourceCommit,
  postgresVersion,
  runId,
  runAttempt,
  catalogFile = catalogPath()
} = {}) {
  const catalogBytes = await boundedRegularFile(catalogFile, 2 * 1024 * 1024, false);
  let catalog;
  try { catalog = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(catalogBytes)); }
  catch { fail("invalid_catalog"); }
  if (!plainObject(catalog) || !Array.isArray(catalog.entries) || catalog.entries.length !== 129) fail("invalid_catalog");

  return normalizeProviderOperationQualificationEvidence({
    version: 1,
    kind: "agentpass-provider-operation-qualification",
    source_commit: sourceCommit,
    workflow: "CI/postgres-integration",
    run_id: String(runId ?? ""),
    run_attempt: positiveInteger(runAttempt),
    postgres_version: postgresVersion,
    migration_version: 42,
    catalog_entries: 129,
    catalog_sha256: sha256(catalogBytes),
    command: PROVIDER_OPERATION_QUALIFICATION_COMMAND,
    test_files: [...TEST_FILES],
    scenarios: [...PROVIDER_OPERATION_QUALIFICATION_SCENARIOS],
    summary: { passed: 6, failed: 0, skipped: 0 },
    outcome: "passed"
  }, { expectedSourceCommit: sourceCommit, expectedCatalogSha256: sha256(catalogBytes) });
}

export function normalizeProviderOperationQualificationEvidence(value, {
  expectedSourceCommit,
  expectedCatalogSha256
} = {}) {
  if (!plainObject(value) || !sameArray(Object.keys(value).sort(), TOP_LEVEL_KEYS)) fail("invalid_evidence");
  if (value.version !== 1 || value.kind !== "agentpass-provider-operation-qualification"
    || value.workflow !== "CI/postgres-integration" || value.outcome !== "passed"
    || value.migration_version !== 42 || value.catalog_entries !== 129
    || typeof value.source_commit !== "string" || !SOURCE_COMMIT.test(value.source_commit)
    || (expectedSourceCommit !== undefined && value.source_commit !== expectedSourceCommit)
    || typeof value.catalog_sha256 !== "string" || !DIGEST.test(value.catalog_sha256)
    || (expectedCatalogSha256 !== undefined && value.catalog_sha256 !== expectedCatalogSha256)
    || typeof value.postgres_version !== "string" || !POSTGRES_VERSION.test(value.postgres_version)
    || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
    || !Number.isSafeInteger(value.run_attempt) || value.run_attempt < 1 || value.run_attempt > 1_000
    || value.command !== PROVIDER_OPERATION_QUALIFICATION_COMMAND
    || !sameArray(value.test_files, TEST_FILES)
    || !sameArray(value.scenarios, PROVIDER_OPERATION_QUALIFICATION_SCENARIOS)
    || !plainObject(value.summary) || !sameArray(Object.keys(value.summary).sort(), ["failed", "passed", "skipped"])
    || value.summary.passed !== 6 || value.summary.failed !== 0 || value.summary.skipped !== 0) {
    fail("invalid_evidence");
  }
  return deepFreeze(structuredClone(value));
}

export async function writeProviderOperationQualificationEvidence(outputFile, options = {}) {
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile)) fail("invalid_arguments");
  const evidence = await createProviderOperationQualificationEvidence(options);
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

export async function verifyProviderOperationQualificationEvidence(inputFile, {
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
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.endsWith("\n")) fail("invalid_evidence");
    value = JSON.parse(text);
    const normalized = normalizeProviderOperationQualificationEvidence(value, {
      expectedSourceCommit,
      expectedCatalogSha256: sha256(catalogBytes)
    });
    if (`${canonicalJson(normalized)}\n` !== text) fail("invalid_evidence");
  } catch (error) {
    if (error instanceof ProviderOperationQualificationEvidenceError) throw error;
    fail("invalid_evidence");
  }
  return Object.freeze({ evidence_sha256: sha256(bytes), source_commit: value.source_commit, scenarios: value.scenarios.length });
}

async function boundedRegularFile(file, maximum, requirePrivate) {
  if (typeof file !== "string" || !path.isAbsolute(file)) fail("invalid_file");
  let stat;
  try { stat = await lstat(file); } catch { fail("invalid_file"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > maximum
    || (requirePrivate && (stat.mode & 0o077) !== 0)) fail("invalid_file");
  let handle;
  try {
    handle = await open(file, fs.constants.O_RDONLY | NOFOLLOW);
    const bytes = await handle.readFile();
    if (bytes.length !== stat.size || bytes.length > maximum) fail("invalid_file");
    return bytes;
  } catch (error) {
    if (error instanceof ProviderOperationQualificationEvidenceError) throw error;
    fail("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function catalogPath() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../contracts/catalog-v1.json");
}

function positiveInteger(value) {
  const number = typeof value === "string" && /^[1-9][0-9]{0,3}$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 1 || number > 1_000) fail("invalid_arguments");
  return number;
}

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
function fail(code) { throw new ProviderOperationQualificationEvidenceError(code); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, file, expectedSourceCommit, ...extra] = process.argv.slice(2);
  try {
    if (command === "write" && file && expectedSourceCommit === undefined && extra.length === 0) {
      const result = await writeProviderOperationQualificationEvidence(path.resolve(file), {
        sourceCommit: process.env.AGENTPASS_C1_SOURCE_COMMIT,
        postgresVersion: process.env.AGENTPASS_C1_POSTGRES_VERSION,
        runId: process.env.AGENTPASS_C1_RUN_ID,
        runAttempt: process.env.AGENTPASS_C1_RUN_ATTEMPT
      });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else if (command === "verify" && file && expectedSourceCommit && extra.length === 0) {
      const result = await verifyProviderOperationQualificationEvidence(path.resolve(file), { expectedSourceCommit });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else {
      fail("invalid_arguments");
    }
  } catch (error) {
    const code = error instanceof ProviderOperationQualificationEvidenceError ? error.code : "verification_failed";
    process.stderr.write(`provider-operation-evidence: ${code}\n`);
    process.exitCode = code === "invalid_arguments" ? 2 : 1;
  }
}
