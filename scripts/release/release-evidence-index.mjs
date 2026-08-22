#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const RELEASE_EVIDENCE_INDEX_SCHEMA_VERSION = 1;
export const RELEASE_EVIDENCE_INDEX_KIND = "agentpass.release-evidence-index";

const SHA1 = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{1,127}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const MAX_EVIDENCE_VALIDITY_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_JSON_BYTES = 16 * 1024 * 1024;

const TOP_LEVEL_KEYS = Object.freeze(["candidate", "evidence", "kind", "reviewer", "schema_version"]);
const CANDIDATE_KEYS = Object.freeze(["artifact_name", "artifact_sha256", "candidate_id", "release_manifest_sha256", "source_commit", "source_tree"]);
const EVIDENCE_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "expires_at", "kind", "name", "produced_at", "qualified", "run", "sha256", "slot", "source_commit", "source_tree", "status"]);
const RUN_KEYS = Object.freeze(["job_id", "run_attempt", "run_id"]);
const REVIEWER_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "evidence_sha256", "expires_at", "id", "independent", "report_sha256", "reviewed_at", "source_commit", "source_tree"]);

// These are deliberately fixed. A promotion cannot silently omit a lane by
// changing a caller-provided list of required evidence.
export const REQUIRED_EVIDENCE_SLOTS = Object.freeze([
  Object.freeze({ kind: "release", slot: "candidate" }),
  Object.freeze({ kind: "qualification", slot: "aggregate" }),
  Object.freeze({ kind: "ci", slot: "canonical" }),
  Object.freeze({ kind: "external", slot: "aggregate" }),
  Object.freeze({ kind: "external", slot: "child" }),
  Object.freeze({ kind: "macos", slot: "apple_silicon" }),
  Object.freeze({ kind: "macos", slot: "intel_t2" }),
  Object.freeze({ kind: "staging", slot: "readiness" }),
  Object.freeze({ kind: "staging", slot: "rollback" }),
  Object.freeze({ kind: "deployment", slot: "cutover" }),
  Object.freeze({ kind: "operations_review", slot: "independent" })
]);

const FORBIDDEN_MARKER = /(?:^|[^a-z])(not_proven|not_run|unknown|mock|fixture|fake|simulator|emulator|local)(?:$|[^a-z])/iu;

export class ReleaseEvidenceIndexError extends Error {
  constructor(code, message = code) {
    super(`${code}: ${message}`);
    this.name = "ReleaseEvidenceIndexError";
    this.code = code;
  }
}

function fail(code, message = code) {
  throw new ReleaseEvidenceIndexError(code, message);
}

function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("invalid_shape", `${label} must be a plain object`);
  }
  return value;
}

function exactKeys(value, keys, label) {
  plainObject(value, label);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    fail("invalid_schema", `${label} fields are not exact`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) {
      fail("invalid_schema", `${label} contains an accessor or non-enumerable field`);
    }
  }
}

function string(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail("invalid_value", `${label} is invalid`);
  return value;
}

function digest(value, label) {
  string(value, SHA256, label);
  if (value === "0".repeat(64)) fail("not_proven", `${label} is a zero digest`);
  return value;
}

function timestamp(value, label) {
  string(value, ISO_UTC, label);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) fail("invalid_timestamp", `${label} is invalid`);
  return parsed.getTime();
}

function runTuple(value, label) {
  exactKeys(value, RUN_KEYS, label);
  string(String(value.run_id), RUN_ID, `${label}.run_id`);
  string(String(value.run_attempt), RUN_ID, `${label}.run_attempt`);
  string(String(value.job_id), RUN_ID, `${label}.job_id`);
  return Object.freeze({ run_id: String(value.run_id), run_attempt: String(value.run_attempt), job_id: String(value.job_id) });
}

function candidate(value, label = "candidate") {
  exactKeys(value, CANDIDATE_KEYS, label);
  string(value.artifact_name, SAFE_NAME, `${label}.artifact_name`);
  digest(value.artifact_sha256, `${label}.artifact_sha256`);
  string(value.candidate_id, CANDIDATE_ID, `${label}.candidate_id`);
  string(value.release_manifest_sha256, SHA256, `${label}.release_manifest_sha256`);
  string(value.source_commit, SHA1, `${label}.source_commit`);
  string(value.source_tree, SHA1, `${label}.source_tree`);
  if (value.candidate_id !== `release-pkg-sha256-v1-${value.artifact_sha256}`) fail("candidate_binding_mismatch", "candidate_id is not derived from artifact_sha256");
  return Object.freeze({ ...value });
}

function slotKey(kind, slot) {
  return `${kind}:${slot}`;
}

function expectedSlot(index) {
  return REQUIRED_EVIDENCE_SLOTS[index];
}

function assertNoForbiddenMarkers(value, pathName = "evidence") {
  if (typeof value === "string") {
    if (FORBIDDEN_MARKER.test(value)) fail("not_proven", `${pathName} contains a non-production marker`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoForbiddenMarkers(item, `${pathName}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) assertNoForbiddenMarkers(item, `${pathName}.${key}`);
  }
}

function normalizeEvidence(value, expected, expectedCandidate, nowMs, seenNames, seenDigests, seenRuns) {
  exactKeys(value, EVIDENCE_KEYS, "evidence item");
  const expectedKey = slotKey(expected.kind, expected.slot);
  if (value.kind !== expected.kind || value.slot !== expected.slot) fail("missing_or_duplicate_evidence", `evidence slot ${expectedKey} is not in the required position`);
  string(value.name, SAFE_NAME, `${expectedKey}.name`);
  if (seenNames.has(value.name)) fail("duplicate_evidence", `evidence name is duplicated: ${value.name}`);
  seenNames.add(value.name);
  digest(value.sha256, `${expectedKey}.sha256`);
  if (seenDigests.has(value.sha256)) fail("duplicate_evidence", `evidence digest is reused: ${value.name}`);
  seenDigests.add(value.sha256);
  if (value.status !== "passed" || value.qualified !== true) fail("not_proven", `${expectedKey} is not passed and qualified`);
  string(value.candidate_id, CANDIDATE_ID, `${expectedKey}.candidate_id`);
  string(value.artifact_sha256, SHA256, `${expectedKey}.artifact_sha256`);
  string(value.source_commit, SHA1, `${expectedKey}.source_commit`);
  string(value.source_tree, SHA1, `${expectedKey}.source_tree`);
  const producedMs = timestamp(value.produced_at, `${expectedKey}.produced_at`);
  const expiresMs = timestamp(value.expires_at, `${expectedKey}.expires_at`);
  if (producedMs > nowMs) fail("invalid_timestamp", `${expectedKey} was produced in the future`);
  if (expiresMs <= nowMs || expiresMs <= producedMs) fail("evidence_expired", `${expectedKey} is expired or has an invalid expiry`);
  if (expiresMs - producedMs > MAX_EVIDENCE_VALIDITY_MS) fail("invalid_expiry_window", `${expectedKey} validity exceeds the policy window`);
  const run = runTuple(value.run, `${expectedKey}.run`);
  const runKey = `${run.run_id}:${run.run_attempt}:${run.job_id}`;
  if (seenRuns.has(runKey)) fail("duplicate_run", `run tuple is reused by ${expectedKey}`);
  seenRuns.add(runKey);
  if (value.candidate_id !== expectedCandidate.candidate_id || value.artifact_sha256 !== expectedCandidate.artifact_sha256
    || value.source_commit !== expectedCandidate.source_commit || value.source_tree !== expectedCandidate.source_tree) {
    fail("candidate_binding_mismatch", `${expectedKey} is not bound to the index candidate`);
  }
  return Object.freeze({
    ...value,
    run
  });
}

function normalizeReviewer(value, expected, evidence, nowMs) {
  exactKeys(value, REVIEWER_KEYS, "reviewer");
  string(value.id, IDENTIFIER, "reviewer.id");
  digest(value.report_sha256, "reviewer.report_sha256");
  if (value.independent !== true) fail("reviewer_separation_required", "reviewer is not independent");
  if (value.candidate_id !== expected.candidate_id || value.artifact_sha256 !== expected.artifact_sha256
    || value.source_commit !== expected.source_commit || value.source_tree !== expected.source_tree) {
    fail("candidate_binding_mismatch", "reviewer is not bound to the index candidate");
  }
  const expectedEvidenceSha256 = sha256Canonical(evidence);
  if (value.evidence_sha256 !== expectedEvidenceSha256) fail("review_binding_mismatch", "reviewer does not cover the complete evidence list");
  const reviewedMs = timestamp(value.reviewed_at, "reviewer.reviewed_at");
  const expiresMs = timestamp(value.expires_at, "reviewer.expires_at");
  if (reviewedMs > nowMs || expiresMs <= nowMs || expiresMs <= reviewedMs || expiresMs - reviewedMs > MAX_EVIDENCE_VALIDITY_MS) {
    fail("review_expired", "reviewer approval is expired or outside the policy window");
  }
  return Object.freeze({ ...value });
}

function resolveExpectedCandidate(options, indexCandidate) {
  const supplied = options.expectedCandidate ?? options.expected;
  if (supplied !== undefined) return candidate(supplied, "expected candidate");
  const fields = ["candidateId", "expectedCandidateId", "artifactName", "expectedArtifactName", "artifactSha256", "expectedArtifactSha256", "releaseManifestSha256", "expectedReleaseManifestSha256", "sourceCommit", "expectedSourceCommit", "sourceTree", "expectedSourceTree"];
  if (fields.some((key) => options[key] !== undefined)) {
    return candidate({
      artifact_name: options.artifactName ?? options.expectedArtifactName,
      artifact_sha256: options.artifactSha256 ?? options.expectedArtifactSha256,
      candidate_id: options.candidateId ?? options.expectedCandidateId,
      release_manifest_sha256: options.releaseManifestSha256 ?? options.expectedReleaseManifestSha256,
      source_commit: options.sourceCommit ?? options.expectedSourceCommit,
      source_tree: options.sourceTree ?? options.expectedSourceTree
    }, "expected candidate");
  }
  return indexCandidate;
}

export function verifyReleaseEvidenceIndex(value, { expectedCandidate, expected, now = new Date(), ...options } = {}) {
  exactKeys(value, TOP_LEVEL_KEYS, "release evidence index");
  if (value.schema_version !== RELEASE_EVIDENCE_INDEX_SCHEMA_VERSION || value.kind !== RELEASE_EVIDENCE_INDEX_KIND) fail("invalid_schema", "release evidence index schema is unsupported");
  assertNoForbiddenMarkers(value);
  const indexCandidate = candidate(value.candidate);
  const expectedValue = resolveExpectedCandidate({ expectedCandidate, expected, ...options }, indexCandidate);
  for (const key of CANDIDATE_KEYS) if (indexCandidate[key] !== expectedValue[key]) fail("candidate_binding_mismatch", `candidate.${key} differs from the expected candidate`);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(nowMs)) fail("invalid_timestamp", "verification time is invalid");
  if (!Array.isArray(value.evidence) || value.evidence.length !== REQUIRED_EVIDENCE_SLOTS.length) fail("missing_or_duplicate_evidence", "required evidence inventory is incomplete");
  const seenNames = new Set();
  const seenDigests = new Set();
  const seenRuns = new Set();
  const evidence = value.evidence.map((item, index) => normalizeEvidence(item, expectedSlot(index), indexCandidate, nowMs, seenNames, seenDigests, seenRuns));
  const seenSlots = new Set(evidence.map((item) => slotKey(item.kind, item.slot)));
  if (seenSlots.size !== REQUIRED_EVIDENCE_SLOTS.length) fail("duplicate_evidence", "required evidence slots contain duplicates");
  const reviewer = normalizeReviewer(value.reviewer, indexCandidate, evidence, nowMs);
  return Object.freeze({
    schema_version: RELEASE_EVIDENCE_INDEX_SCHEMA_VERSION,
    kind: RELEASE_EVIDENCE_INDEX_KIND,
    candidate: indexCandidate,
    evidence: Object.freeze(evidence),
    reviewer
  });
}

export const verifyEvidenceIndex = verifyReleaseEvidenceIndex;

export function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

export function releaseEvidenceIndexSHA256(value) {
  return sha256Canonical(value);
}

export const evidenceIndexSHA256 = releaseEvidenceIndexSHA256;

// JSON.parse accepts duplicate object members and silently keeps the last one.
// The CLI therefore scans object keys before parsing so an operator cannot
// submit an ambiguous evidence index or expected-candidate file.
function parseDuplicateSafeJson(text, label) {
  let offset = 0;
  const whitespace = () => { while (offset < text.length && /[ \t\r\n]/u.test(text[offset])) offset += 1; };
  const invalid = () => fail("invalid_json", `${label} is not valid JSON`);
  const parseString = () => {
    const start = offset;
    if (text[offset++] !== '"') invalid();
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '"') {
        try { return JSON.parse(text.slice(start, offset)); } catch { invalid(); }
      }
      if (character === "\\") {
        if (offset >= text.length) invalid();
        const escaped = text[offset++];
        if (escaped === "u") { if (!/^[0-9a-f]{4}$/iu.test(text.slice(offset, offset + 4))) invalid(); offset += 4; }
        else if (!/["\\/bfnrt]/u.test(escaped)) invalid();
      } else if (character.charCodeAt(0) < 0x20) invalid();
    }
    invalid();
  };
  const parseValue = () => {
    whitespace();
    if (text[offset] === '"') { parseString(); return; }
    if (text[offset] === "{") { parseObject(); return; }
    if (text[offset] === "[") { parseArray(); return; }
    const literal = text.slice(offset).match(/^(?:true|false|null)/u);
    if (literal) { offset += literal[0].length; return; }
    const number = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!number) invalid();
    offset += number[0].length;
  };
  const parseArray = () => {
    offset += 1; whitespace();
    if (text[offset] === "]") { offset += 1; return; }
    while (true) { parseValue(); whitespace(); if (text[offset] === "]") { offset += 1; return; } if (text[offset++] !== ",") invalid(); }
  };
  const parseObject = () => {
    offset += 1; whitespace(); const keys = new Set();
    if (text[offset] === "}") { offset += 1; return; }
    while (true) {
      if (text[offset] !== '"') invalid();
      const key = parseString();
      if (keys.has(key)) fail("duplicate_field", `${label} contains a duplicate field`);
      keys.add(key); whitespace(); if (text[offset++] !== ":") invalid(); parseValue(); whitespace();
      if (text[offset] === "}") { offset += 1; return; }
      if (text[offset++] !== ",") invalid(); whitespace();
    }
  };
  parseValue(); whitespace();
  if (offset !== text.length) invalid();
  let value;
  try { value = JSON.parse(text); } catch { invalid(); }
  if (canonicalJson(value) !== text) fail("noncanonical_json", `${label} is not canonical JSON`);
  return value;
}

function readProtectedJson(file, label) {
  if (typeof file !== "string" || !path.isAbsolute(file)) fail("invalid_path", `${label} path must be absolute`);
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch { fail("missing_evidence", `${label} is unavailable`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_JSON_BYTES)) fail("invalid_file", `${label} must be a regular bounded file`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail("invalid_file", `${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    if (identity(before) !== identity(after)) fail("invalid_file", `${label} changed while reading`);
    return parseDuplicateSafeJson(bytes.toString("utf8"), label);
  } finally {
    fs.closeSync(fd);
  }
}

export function readReleaseEvidenceIndex(file) {
  return readProtectedJson(file, "release evidence index");
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 3 || args[0] !== "verify") {
    process.stderr.write("Usage: release-evidence-index.mjs verify INDEX.json EXPECTED-CANDIDATE.json\n");
    process.exitCode = 2;
    return;
  }
  try {
    const index = readReleaseEvidenceIndex(args[1]);
    const expected = candidate(readProtectedJson(args[2], "expected candidate"), "expected candidate");
    const normalized = verifyReleaseEvidenceIndex(index, { expectedCandidate: expected, now: new Date() });
    process.stdout.write(`${canonicalJson({ status: "passed", index_sha256: releaseEvidenceIndexSHA256(normalized), candidate: normalized.candidate })}`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ status: "not_proven", reason: error instanceof ReleaseEvidenceIndexError ? error.code : "verification_failed" })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) await main();
