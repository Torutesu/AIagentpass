#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const PRODUCTION_READINESS_GATE_SCHEMA_VERSION = 1;
export const PRODUCTION_READINESS_GATE_KIND = "agentpass.production-readiness-gate";
export const PRODUCTION_READINESS_MAX_TTL_MS = 30 * 24 * 60 * 60 * 1_000;

const SHA1 = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const FORBIDDEN_PRODUCTION_MARKER = /(?:^|[^a-z])(local|static|mock|fixture|sandbox|simulator|emulator|fake)(?:$|[^a-z])/iu;

// This inventory is policy, not caller input. Adding or removing a row is a
// code/documentation change and therefore cannot silently weaken a release.
export const REQUIRED_PRODUCTION_EVIDENCE_ROWS = Object.freeze([
  Object.freeze({ kind: "release", slot: "candidate" }),
  Object.freeze({ kind: "ci", slot: "canonical" }),
  Object.freeze({ kind: "qualification", slot: "aggregate" }),
  Object.freeze({ kind: "external", slot: "aggregate" }),
  Object.freeze({ kind: "postgresql", slot: "protected" }),
  Object.freeze({ kind: "kms", slot: "protected" }),
  Object.freeze({ kind: "webauthn", slot: "external" }),
  Object.freeze({ kind: "macos", slot: "apple_silicon" }),
  Object.freeze({ kind: "macos", slot: "intel_t2" }),
  Object.freeze({ kind: "staging", slot: "readiness" }),
  Object.freeze({ kind: "deployment", slot: "rollback" })
]);

const TOP_LEVEL_KEYS = Object.freeze(["candidate", "evidence", "kind", "reviewer", "schema_version"]);
const CANDIDATE_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "source_commit", "source_tree"]);
const EVIDENCE_KEYS = Object.freeze([
  "artifact_sha256", "candidate_id", "expires_at", "kind", "name", "produced_at", "provenance",
  "qualified", "run", "sha256", "slot", "source_commit", "source_tree", "status"
]);
const PROVENANCE_KEYS = Object.freeze(["environment", "execution_class", "runner_class", "source"]);
const RUN_KEYS = Object.freeze(["job_id", "run_attempt", "run_id"]);
const REVIEWER_KEYS = Object.freeze([
  "artifact_sha256", "candidate_id", "evidence_sha256", "expires_at", "id", "independent",
  "report_sha256", "reviewed_at", "source_commit", "source_tree"
]);

export class ProductionReadinessGateError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProductionReadinessGateError";
    this.code = code;
  }
}

function fail(code) {
  throw new ProductionReadinessGateError(code);
}

function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("invalid_schema");
  }
  return value;
}

function exactKeys(value, keys, label) {
  plainObject(value, label);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail("unknown_field");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail("invalid_schema");
  }
}

function text(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) fail("invalid_value");
  return value;
}

function digest(value) {
  text(value, SHA256);
  if (value === "0".repeat(64)) fail("not_proven");
  return value;
}

function timestamp(value, nowMs, { allowFuture = false } = {}) {
  text(value, ISO_UTC);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail("invalid_timestamp");
  if (!allowFuture && parsed > nowMs) fail("not_proven");
  return parsed;
}

function slotKey(row) {
  return `${row.kind}:${row.slot}`;
}

function assertNoProductionMarker(value) {
  if (typeof value === "string") {
    if (FORBIDDEN_PRODUCTION_MARKER.test(value)) fail("non_production_evidence");
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertNoProductionMarker(item);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) assertNoProductionMarker(item);
  }
}

function normalizeCandidate(value) {
  exactKeys(value, CANDIDATE_KEYS, "candidate");
  const candidate = {
    artifact_sha256: digest(value.artifact_sha256),
    candidate_id: text(value.candidate_id, CANDIDATE_ID),
    source_commit: text(value.source_commit, SHA1),
    source_tree: text(value.source_tree, SHA1)
  };
  if (candidate.candidate_id !== `release-pkg-sha256-v1-${candidate.artifact_sha256}`) fail("binding_mismatch");
  return Object.freeze(candidate);
}

function normalizeRun(value) {
  exactKeys(value, RUN_KEYS, "evidence.run");
  return Object.freeze({
    job_id: text(value.job_id, IDENTIFIER),
    run_attempt: text(value.run_attempt, RUN_ID),
    run_id: text(value.run_id, RUN_ID)
  });
}

function normalizeProvenance(value) {
  exactKeys(value, PROVENANCE_KEYS, "evidence.provenance");
  if (value.environment !== "production" || value.execution_class !== "protected_external" || value.source !== "external"
    || !["managed_provider", "physical_hardware", "protected_runner"].includes(value.runner_class)) {
    fail("production_provenance_required");
  }
  return Object.freeze({ ...value });
}

function normalizeEvidenceRow(value, expected, candidate, nowMs, seenNames, seenDigests, seenRuns) {
  exactKeys(value, EVIDENCE_KEYS, "evidence row");
  if (value.kind !== expected.kind || value.slot !== expected.slot) fail("missing_or_duplicate_row");
  if (value.status !== "passed" || value.qualified !== true) fail("evidence_not_passed");
  const row = {
    artifact_sha256: digest(value.artifact_sha256),
    candidate_id: text(value.candidate_id, CANDIDATE_ID),
    expires_at: text(value.expires_at, ISO_UTC),
    kind: text(value.kind, IDENTIFIER),
    name: text(value.name, NAME),
    produced_at: text(value.produced_at, ISO_UTC),
    provenance: normalizeProvenance(value.provenance),
    qualified: true,
    run: normalizeRun(value.run),
    sha256: digest(value.sha256),
    slot: text(value.slot, IDENTIFIER),
    source_commit: text(value.source_commit, SHA1),
    source_tree: text(value.source_tree, SHA1),
    status: "passed"
  };
  if (row.candidate_id !== candidate.candidate_id || row.artifact_sha256 !== candidate.artifact_sha256
    || row.source_commit !== candidate.source_commit || row.source_tree !== candidate.source_tree) fail("binding_mismatch");
  const producedMs = timestamp(row.produced_at, nowMs);
  const expiresMs = timestamp(row.expires_at, nowMs, { allowFuture: true });
  if (expiresMs <= nowMs || expiresMs <= producedMs || expiresMs - producedMs > PRODUCTION_READINESS_MAX_TTL_MS) fail("evidence_expired");
  const runKey = `${row.run.run_id}:${row.run.run_attempt}:${row.run.job_id}`;
  if (seenNames.has(row.name) || seenDigests.has(row.sha256) || seenRuns.has(runKey)) fail("duplicate_row");
  seenNames.add(row.name);
  seenDigests.add(row.sha256);
  seenRuns.add(runKey);
  return Object.freeze(row);
}

function normalizeReviewer(value, candidate, evidence, nowMs, runJobs, evidenceNames) {
  exactKeys(value, REVIEWER_KEYS, "reviewer");
  const reviewer = {
    artifact_sha256: digest(value.artifact_sha256),
    candidate_id: text(value.candidate_id, CANDIDATE_ID),
    evidence_sha256: digest(value.evidence_sha256),
    expires_at: text(value.expires_at, ISO_UTC),
    id: text(value.id, IDENTIFIER),
    independent: value.independent,
    report_sha256: digest(value.report_sha256),
    reviewed_at: text(value.reviewed_at, ISO_UTC),
    source_commit: text(value.source_commit, SHA1),
    source_tree: text(value.source_tree, SHA1)
  };
  if (reviewer.independent !== true) fail("independent_review_required");
  if (reviewer.candidate_id !== candidate.candidate_id || reviewer.artifact_sha256 !== candidate.artifact_sha256
    || reviewer.source_commit !== candidate.source_commit || reviewer.source_tree !== candidate.source_tree) fail("binding_mismatch");
  if (runJobs.has(reviewer.id) || evidenceNames.has(reviewer.id)) fail("independent_review_required");
  const reviewedMs = timestamp(reviewer.reviewed_at, nowMs);
  const expiresMs = timestamp(reviewer.expires_at, nowMs, { allowFuture: true });
  if (expiresMs <= nowMs || expiresMs <= reviewedMs || expiresMs - reviewedMs > PRODUCTION_READINESS_MAX_TTL_MS) fail("review_expired");
  if (reviewer.evidence_sha256 !== productionReadinessEvidenceSHA256(evidence)) fail("review_binding_mismatch");
  return Object.freeze(reviewer);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

export function productionReadinessEvidenceSHA256(evidence) {
  return sha256(canonicalJson(evidence));
}

export function productionReadinessGateSHA256(gate) {
  return sha256(canonicalJson(gate));
}

export function normalizeProductionReadinessGate(value, { now = Date.now() } = {}) {
  const nowMs = now instanceof Date ? now.getTime() : now;
  if (!Number.isFinite(nowMs)) fail("invalid_clock");
  exactKeys(value, TOP_LEVEL_KEYS, "production readiness gate");
  if (value.schema_version !== PRODUCTION_READINESS_GATE_SCHEMA_VERSION || value.kind !== PRODUCTION_READINESS_GATE_KIND) fail("invalid_schema");
  const candidate = normalizeCandidate(value.candidate);
  if (!Array.isArray(value.evidence) || value.evidence.length !== REQUIRED_PRODUCTION_EVIDENCE_ROWS.length) fail("missing_or_duplicate_row");
  const seenNames = new Set();
  const seenDigests = new Set();
  const seenRuns = new Set();
  const evidence = value.evidence.map((row, index) => normalizeEvidenceRow(
    row, REQUIRED_PRODUCTION_EVIDENCE_ROWS[index], candidate, nowMs, seenNames, seenDigests, seenRuns
  ));
  assertNoProductionMarker(evidence);
  const reviewer = normalizeReviewer(value.reviewer, candidate, evidence, nowMs, new Set(evidence.map((row) => row.run.job_id)), seenNames);
  return Object.freeze({
    candidate,
    evidence: Object.freeze(evidence),
    kind: PRODUCTION_READINESS_GATE_KIND,
    reviewer,
    schema_version: PRODUCTION_READINESS_GATE_SCHEMA_VERSION
  });
}

export function verifyProductionReadinessGate(value, options = {}) {
  const normalized = normalizeProductionReadinessGate(value, options);
  const result = {
    candidate_id: normalized.candidate.candidate_id,
    evidence_count: normalized.evidence.length,
    gate_sha256: productionReadinessGateSHA256(normalized),
    production_ready: true,
    reviewer_id: normalized.reviewer.id,
    status: "passed"
  };
  return Object.freeze(result);
}

// JSON.parse accepts duplicate object members and silently keeps the last one.
// This scanner rejects them before parsing and then requires the exact
// canonical representation, including no trailing newline.
export function parseProductionReadinessJson(textValue) {
  if (typeof textValue !== "string" || Buffer.byteLength(textValue, "utf8") > MAX_JSON_BYTES) fail("invalid_json");
  let offset = 0;
  const whitespace = () => { while (offset < textValue.length && /[ \t\r\n]/u.test(textValue[offset])) offset += 1; };
  const invalid = () => fail("invalid_json");
  const parseString = () => {
    const start = offset;
    if (textValue[offset++] !== '"') invalid();
    while (offset < textValue.length) {
      const character = textValue[offset++];
      if (character === '"') {
        try { return JSON.parse(textValue.slice(start, offset)); } catch { invalid(); }
      }
      if (character === "\\") {
        if (offset >= textValue.length) invalid();
        const escaped = textValue[offset++];
        if (escaped === "u") {
          if (!/^[0-9a-f]{4}$/iu.test(textValue.slice(offset, offset + 4))) invalid();
          offset += 4;
        } else if (!/["\\/bfnrt]/u.test(escaped)) invalid();
      } else if (character.charCodeAt(0) < 0x20) invalid();
    }
    invalid();
  };
  const parseValue = () => {
    whitespace();
    if (textValue[offset] === '"') { parseString(); return; }
    if (textValue[offset] === "{") { parseObject(); return; }
    if (textValue[offset] === "[") { parseArray(); return; }
    const literal = textValue.slice(offset).match(/^(?:true|false|null)/u);
    if (literal) { offset += literal[0].length; return; }
    const number = textValue.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!number) invalid();
    offset += number[0].length;
  };
  const parseArray = () => {
    offset += 1; whitespace();
    if (textValue[offset] === "]") { offset += 1; return; }
    while (true) {
      parseValue(); whitespace();
      if (textValue[offset] === "]") { offset += 1; return; }
      if (textValue[offset++] !== ",") invalid();
    }
  };
  const parseObject = () => {
    offset += 1; whitespace(); const keys = new Set();
    if (textValue[offset] === "}") { offset += 1; return; }
    while (true) {
      if (textValue[offset] !== '"') invalid();
      const key = parseString();
      if (keys.has(key)) fail("duplicate_field");
      keys.add(key); whitespace();
      if (textValue[offset++] !== ":") invalid();
      parseValue(); whitespace();
      if (textValue[offset] === "}") { offset += 1; return; }
      if (textValue[offset++] !== ",") invalid();
      whitespace();
    }
  };
  parseValue(); whitespace();
  if (offset !== textValue.length) invalid();
  let value;
  try { value = JSON.parse(textValue); } catch { invalid(); }
  if (canonicalJson(value) !== textValue) fail("noncanonical_json");
  return value;
}

function readProtectedJson(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) fail("invalid_path");
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail("missing_input"); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_JSON_BYTES)) fail("invalid_input");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail("invalid_input");
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    if (identity(before) !== identity(after)) fail("invalid_input");
    return parseProductionReadinessJson(bytes.toString("utf8"));
  } finally {
    fs.closeSync(fd);
  }
}

export function readProductionReadinessGate(file) {
  return readProtectedJson(file);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "verify") {
    process.stderr.write('{"status":"not_proven","reason":"invalid_arguments"}\n');
    process.exitCode = 2;
    return;
  }
  try {
    const input = readProductionReadinessGate(args[1]);
    process.stdout.write(`${canonicalJson(verifyProductionReadinessGate(input))}\n`);
  } catch (error) {
    const reason = error instanceof ProductionReadinessGateError ? error.code : "verification_failed";
    process.stderr.write(`${canonicalJson({ reason, status: "not_proven" })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) await main();
