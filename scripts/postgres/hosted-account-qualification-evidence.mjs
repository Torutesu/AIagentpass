#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { derivePostgresSchemaHead, POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const MAX_EVIDENCE_BYTES = 32 * 1024;
const MAX_TAP_BYTES = 2 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const POSTGRES_VERSION = /^17(?:\.[0-9]+){0,2}(?:[+._~A-Za-z0-9-]*)(?: \([A-Za-z0-9.+~:_ -]{1,128}\))?$/u;
const RUN_ID = /^[1-9][0-9]{0,31}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;

export const HOSTED_ACCOUNT_TEST_FILES = Object.freeze([
  "apps/cloud-api/test/postgres/human-session-ceiling.integration.test.mjs",
  "apps/cloud-api/test/postgres/human-session-epochs-integration.test.mjs",
  "apps/cloud-api/test/postgres/hosted-identity-atomic-completion.integration.test.mjs",
  "apps/cloud-api/test/postgres/hosted-first-organization-atomic.integration.test.mjs",
  "apps/cloud-api/test/postgres/hosted-webauthn-claim-lease.integration.test.mjs",
  "apps/cloud-api/test/postgres/hosted-bootstrap-status-csrf.integration.test.mjs",
  "apps/cloud-api/test/postgres/hosted-webauthn-process-loss.integration.test.mjs"
]);

const HOSTED_ACCOUNT_SOURCE_FILES = Object.freeze([
  ...HOSTED_ACCOUNT_TEST_FILES,
  "apps/cloud-api/test/support/hosted-webauthn-process-loss-child.mjs"
]);

export const HOSTED_ACCOUNT_QUALIFICATION_SCENARIOS = Object.freeze([
  "session_ceiling_contention",
  "session_epoch_atomic_rotation",
  "identity_atomic_completion",
  "first_organization_atomic",
  "webauthn_claim_lease",
  "bootstrap_status_csrf",
  "webauthn_process_loss_and_response_recovery"
]);

export const HOSTED_ACCOUNT_QUALIFICATION_COMMAND = [
  "node --test --test-concurrency=1 --test-reporter=tap",
  ...HOSTED_ACCOUNT_TEST_FILES
].join(" ");

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
  "source_tree_sha256",
  "summary",
  "tap_sha256",
  "test_files",
  "version",
  "workflow"
].sort());

export class HostedAccountQualificationEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "HostedAccountQualificationEvidenceError";
    this.code = code;
  }
}

export async function createHostedAccountQualificationEvidence({
  sourceCommit,
  postgresVersion,
  runId,
  runAttempt,
  tapFile,
  catalogFile = path.join(ROOT, "contracts/catalog-v1.json"),
  repositoryRoot = ROOT
} = {}) {
  const [tapBytes, catalogBytes, sourceTreeSha256] = await Promise.all([
    boundedRegularFile(tapFile, MAX_TAP_BYTES, false),
    boundedRegularFile(catalogFile, 2 * 1024 * 1024, false),
    sourceTreeDigest(repositoryRoot)
  ]);
  const summary = parsePassingTap(tapBytes);
  const catalog = parseCatalog(catalogBytes);
  return normalizeHostedAccountQualificationEvidence({
    version: 1,
    kind: "agentpass-hosted-account-qualification",
    source_commit: sourceCommit,
    workflow: "CI/postgres-integration",
    run_id: String(runId ?? ""),
    run_attempt: positiveInteger(runAttempt),
    postgres_version: postgresVersion,
    migration_version: catalog.migrationVersion,
    catalog_entries: catalog.entries,
    catalog_sha256: sha256(catalogBytes),
    source_tree_sha256: sourceTreeSha256,
    command: HOSTED_ACCOUNT_QUALIFICATION_COMMAND,
    test_files: [...HOSTED_ACCOUNT_TEST_FILES],
    scenarios: [...HOSTED_ACCOUNT_QUALIFICATION_SCENARIOS],
    tap_sha256: sha256(tapBytes),
    summary,
    outcome: "passed"
  }, {
    expectedSourceCommit: sourceCommit,
    expectedCatalogSha256: sha256(catalogBytes),
    expectedCatalogEntries: catalog.entries,
    expectedMigrationVersion: catalog.migrationVersion,
    expectedSourceTreeSha256: sourceTreeSha256
  });
}

export function normalizeHostedAccountQualificationEvidence(value, expected = {}) {
  if (!plainObject(value) || !sameArray(Object.keys(value).sort(), TOP_LEVEL_KEYS)) fail("invalid_evidence");
  if (value.version !== 1 || value.kind !== "agentpass-hosted-account-qualification"
    || value.workflow !== "CI/postgres-integration" || value.outcome !== "passed"
    || typeof value.source_commit !== "string" || !SOURCE_COMMIT.test(value.source_commit)
    || (expected.expectedSourceCommit !== undefined && value.source_commit !== expected.expectedSourceCommit)
    || typeof value.postgres_version !== "string" || !POSTGRES_VERSION.test(value.postgres_version)
    || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
    || !Number.isSafeInteger(value.run_attempt) || value.run_attempt < 1 || value.run_attempt > 1_000
    || !Number.isSafeInteger(value.migration_version) || value.migration_version < 1 || value.migration_version > 9_999
    || (expected.expectedMigrationVersion !== undefined && value.migration_version !== expected.expectedMigrationVersion)
    || !Number.isSafeInteger(value.catalog_entries) || value.catalog_entries < 1 || value.catalog_entries > 10_000
    || (expected.expectedCatalogEntries !== undefined && value.catalog_entries !== expected.expectedCatalogEntries)
    || !digestMatches(value.catalog_sha256, expected.expectedCatalogSha256)
    || !digestMatches(value.source_tree_sha256, expected.expectedSourceTreeSha256)
    || !DIGEST.test(value.tap_sha256)
    || value.command !== HOSTED_ACCOUNT_QUALIFICATION_COMMAND
    || !sameArray(value.test_files, HOSTED_ACCOUNT_TEST_FILES)
    || !sameArray(value.scenarios, HOSTED_ACCOUNT_QUALIFICATION_SCENARIOS)
    || !validSummary(value.summary)) fail("invalid_evidence");
  return deepFreeze(structuredClone(value));
}

export async function writeHostedAccountQualificationEvidence(outputFile, options = {}) {
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile)) fail("invalid_arguments");
  const evidence = await createHostedAccountQualificationEvidence(options);
  const bytes = Buffer.from(`${canonicalJson(evidence)}\n`, "utf8");
  if (bytes.length > MAX_EVIDENCE_BYTES) fail("invalid_evidence");
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

export async function verifyHostedAccountQualificationEvidence(inputFile, {
  expectedSourceCommit,
  catalogFile = path.join(ROOT, "contracts/catalog-v1.json"),
  repositoryRoot = ROOT
} = {}) {
  if (typeof expectedSourceCommit !== "string" || !SOURCE_COMMIT.test(expectedSourceCommit)) fail("invalid_arguments");
  const [bytes, catalogBytes, sourceTreeSha256] = await Promise.all([
    boundedRegularFile(inputFile, MAX_EVIDENCE_BYTES, true),
    boundedRegularFile(catalogFile, 2 * 1024 * 1024, false),
    sourceTreeDigest(repositoryRoot)
  ]);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.endsWith("\n")) fail("invalid_evidence");
    const value = JSON.parse(text);
    const catalog = parseCatalog(catalogBytes);
    const normalized = normalizeHostedAccountQualificationEvidence(value, {
      expectedSourceCommit,
      expectedCatalogSha256: sha256(catalogBytes),
      expectedCatalogEntries: catalog.entries,
      expectedMigrationVersion: catalog.migrationVersion,
      expectedSourceTreeSha256: sourceTreeSha256
    });
    if (`${canonicalJson(normalized)}\n` !== text) fail("invalid_evidence");
    return Object.freeze({ evidence_sha256: sha256(bytes), source_commit: normalized.source_commit, tests: normalized.summary.tests });
  } catch (error) {
    if (error instanceof HostedAccountQualificationEvidenceError) throw error;
    fail("invalid_evidence");
  }
}

function parsePassingTap(bytes) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { fail("invalid_tap"); }
  if (/(^|[\t\r\n ])# (?:SKIP|TODO)([\t\r\n ]|$)|^Bail out!/mu.test(text)) fail("incomplete_qualification");
  const tests = tapCount(text, "tests");
  const passed = tapCount(text, "pass");
  const failed = tapCount(text, "fail", 0);
  const skipped = tapCount(text, "skipped", 0);
  const todo = tapCount(text, "todo", 0);
  if (tests < HOSTED_ACCOUNT_TEST_FILES.length || passed !== tests || failed !== 0 || skipped !== 0 || todo !== 0) fail("failed_qualification");
  return Object.freeze({ tests, passed, failed, skipped, todo });
}

function tapCount(text, label, fallback) {
  const matches = [...text.matchAll(new RegExp(`^# ${label} ([0-9]+)$`, "gmu"))];
  if (matches.length === 0) {
    if (fallback !== undefined) return fallback;
    fail("invalid_tap");
  }
  const value = Number(matches.at(-1)[1]);
  if (!Number.isSafeInteger(value)) fail("invalid_tap");
  return value;
}

async function sourceTreeDigest(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) fail("invalid_arguments");
  const digest = crypto.createHash("sha256");
  for (const relative of HOSTED_ACCOUNT_SOURCE_FILES) {
    const bytes = await boundedRegularFile(path.join(repositoryRoot, relative), 2 * 1024 * 1024, false);
    digest.update(relative).update("\0").update(bytes).update("\0");
  }
  return digest.digest("hex");
}

function parseCatalog(bytes) {
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail("invalid_catalog"); }
  if (!plainObject(value) || !Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > 10_000) fail("invalid_catalog");
  let head;
  try { head = derivePostgresSchemaHead({ catalog: value, migrations: POSTGRES_SCHEMA_HEAD.migrations }); }
  catch { fail("invalid_catalog"); }
  return Object.freeze({ entries: value.entries.length, migrationVersion: head.version });
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
    if (error instanceof HostedAccountQualificationEvidenceError) throw error;
    fail("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function positiveInteger(value) {
  const number = typeof value === "string" && /^[1-9][0-9]{0,3}$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 1 || number > 1_000) fail("invalid_arguments");
  return number;
}
function validSummary(value) { return plainObject(value) && sameArray(Object.keys(value).sort(), ["failed", "passed", "skipped", "tests", "todo"]) && Number.isSafeInteger(value.tests) && value.tests >= HOSTED_ACCOUNT_TEST_FILES.length && value.passed === value.tests && value.failed === 0 && value.skipped === 0 && value.todo === 0; }
function digestMatches(value, expected) { return typeof value === "string" && DIGEST.test(value) && (expected === undefined || value === expected); }
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
function fail(code) { throw new HostedAccountQualificationEvidenceError(code); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, file, second, ...extra] = process.argv.slice(2);
  try {
    if (command === "write" && file && second && extra.length === 0) {
      const result = await writeHostedAccountQualificationEvidence(path.resolve(file), {
        tapFile: path.resolve(second),
        sourceCommit: process.env.AGENTPASS_HOSTED_ACCOUNT_SOURCE_COMMIT,
        postgresVersion: process.env.AGENTPASS_HOSTED_ACCOUNT_POSTGRES_VERSION,
        runId: process.env.AGENTPASS_HOSTED_ACCOUNT_RUN_ID,
        runAttempt: process.env.AGENTPASS_HOSTED_ACCOUNT_RUN_ATTEMPT
      });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else if (command === "verify" && file && second && extra.length === 0) {
      const result = await verifyHostedAccountQualificationEvidence(path.resolve(file), { expectedSourceCommit: second });
      process.stdout.write(`${result.evidence_sha256}\n`);
    } else fail("invalid_arguments");
  } catch (error) {
    process.stderr.write(`${error instanceof HostedAccountQualificationEvidenceError ? error.code : "qualification_evidence_failed"}\n`);
    process.exitCode = 1;
  }
}
