#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { open, lstat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const W16_DRILL_SCHEMA_VERSION = 36;
export const W16_DRILL_MAX_BYTES = 16_384;
export const W16_DRILL_MAX_DURATION_MS = 30 * 60 * 1000;
export const W16_DRILL_SCENARIOS = Object.freeze([
  "provider_outage",
  "worker_restart",
  "limiter_outage",
  "uncertain_adjudication",
  "dead_letter_redrive",
  "prune_failure"
]);

const ROOT_KEYS = Object.freeze([
  "aggregate_observations",
  "alert_policy_digest",
  "completed_at",
  "duration_ms",
  "image_digest",
  "outcome",
  "scenarios",
  "schema_version",
  "source_commit",
  "started_at"
].sort());
const SCENARIO_KEYS = Object.freeze(["name", "outcome"].sort());
const AGGREGATE_KEYS = Object.freeze([
  "active_claims",
  "active_leases",
  "alert_policy_rule_count",
  "critical_alerts_observed",
  "duplicate_provider_acceptances",
  "failed_count",
  "forbidden_material_findings",
  "passed_count",
  "scenario_count",
  "unauthorized_mutations",
  "warning_alerts_observed"
].sort());
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const UTC_TIMESTAMP = /^(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.(?<milliseconds>[0-9]{3}))?Z$/u;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/iu;
const URL = /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s]+/iu;
const SECRET_VALUE = /(?:-----BEGIN [^-\n]+ KEY-----|\b(?:bearer|basic)\s+[A-Za-z0-9+/._=-]+|\b(?:sk|gh[pousr]|xox[baprs])_[A-Za-z0-9_-]{8,}|(?:password|credential|secret|token|authorization|dsn)\s*[:=])/iu;
const NOFOLLOW = fs.constants.O_NOFOLLOW;

export class W16DrillEvidenceError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "W16DrillEvidenceError";
    this.code = code;
  }
}

function invalid(code, message = code) {
  throw new W16DrillEvidenceError(code, message);
}

function plainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected, label) {
  if (!plainObject(value)) invalid("invalid_evidence", `${label} has invalid shape`);
  const actual = Object.keys(value).sort();
  if (!sameArray(actual, expected)) invalid("invalid_evidence", `${label} has missing or unknown fields`);
}

function sameArray(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function integer(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function nonZero(value) {
  return !/^0+$/.test(value.replace("sha256:", ""));
}

function rejectUnsafeMaterial(value) {
  if (Array.isArray(value)) {
    for (const item of value) rejectUnsafeMaterial(item);
    return;
  }
  if (plainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (UUID.test(key) || URL.test(key) || SECRET_VALUE.test(key)) invalid("invalid_evidence", "forbidden evidence material");
      rejectUnsafeMaterial(child);
    }
    return;
  }
  if (typeof value === "string" && (UUID.test(value) || URL.test(value) || SECRET_VALUE.test(value))) {
    invalid("invalid_evidence", "forbidden evidence material");
  }
}

function parseUtc(value, label) {
  if (typeof value !== "string" || value.length > 24) invalid("invalid_evidence", `${label} is invalid`);
  const match = UTC_TIMESTAMP.exec(value);
  if (!match) invalid("invalid_evidence", `${label} is invalid`);
  const normalized = `${match.groups.date}.${match.groups.milliseconds ?? "000"}Z`;
  const milliseconds = Date.parse(normalized);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== normalized) {
    invalid("invalid_evidence", `${label} is invalid`);
  }
  return milliseconds;
}

function rejectDuplicateJsonKeys(text) {
  let offset = 0;
  const whitespace = () => {
    while (offset < text.length && /[ \t\r\n]/u.test(text[offset])) offset += 1;
  };
  const fail = () => invalid("invalid_evidence", "evidence JSON is invalid");
  const parseString = () => {
    const start = offset;
    if (text[offset] !== '"') fail();
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      offset += 1;
      if (character === '"') {
        try { return JSON.parse(text.slice(start, offset)); } catch { fail(); }
      }
      if (character === "\\") {
        if (offset >= text.length) fail();
        const escaped = text[offset];
        offset += 1;
        if (escaped === "u") {
          if (!/^[0-9a-f]{4}$/iu.test(text.slice(offset, offset + 4))) fail();
          offset += 4;
        } else if (!(escaped === '"' || escaped === "\\" || escaped === "/" || escaped === "b" || escaped === "f" || escaped === "n" || escaped === "r" || escaped === "t")) {
          fail();
        }
      } else if (character.charCodeAt(0) < 0x20) {
        fail();
      }
    }
    fail();
  };
  const parseValue = () => {
    whitespace();
    const character = text[offset];
    if (character === '"') { parseString(); return; }
    if (character === "{") { parseObject(); return; }
    if (character === "[") { parseArray(); return; }
    if (text.startsWith("true", offset)) { offset += 4; return; }
    if (text.startsWith("false", offset)) { offset += 5; return; }
    if (text.startsWith("null", offset)) { offset += 4; return; }
    const number = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!number) fail();
    offset += number[0].length;
  };
  const parseArray = () => {
    offset += 1;
    whitespace();
    if (text[offset] === "]") { offset += 1; return; }
    while (true) {
      parseValue();
      whitespace();
      if (text[offset] === "]") { offset += 1; return; }
      if (text[offset] !== ",") fail();
      offset += 1;
      whitespace();
    }
  };
  const parseObject = () => {
    offset += 1;
    const keys = new Set();
    whitespace();
    if (text[offset] === "}") { offset += 1; return; }
    while (true) {
      const key = parseString();
      if (keys.has(key)) invalid("invalid_evidence", "evidence JSON has duplicate fields");
      keys.add(key);
      whitespace();
      if (text[offset] !== ":") fail();
      offset += 1;
      parseValue();
      whitespace();
      if (text[offset] === "}") { offset += 1; return; }
      if (text[offset] !== ",") fail();
      offset += 1;
      whitespace();
    }
  };
  parseValue();
  whitespace();
  if (offset !== text.length) fail();
}

function normalizeOptions(options) {
  if (options === undefined) return { maxDurationMs: W16_DRILL_MAX_DURATION_MS };
  if (!plainObject(options)) invalid("invalid_arguments");
  const allowed = new Set(["expectedCommitSha", "expectedImageDigest", "expectedAlertPolicyDigest", "maxDurationMs"]);
  if (Reflect.ownKeys(options).some((key) => typeof key !== "string" || !allowed.has(key))) invalid("invalid_arguments");
  return {
    expectedCommitSha: options.expectedCommitSha,
    expectedImageDigest: options.expectedImageDigest,
    expectedAlertPolicyDigest: options.expectedAlertPolicyDigest,
    maxDurationMs: options.maxDurationMs ?? W16_DRILL_MAX_DURATION_MS
  };
}

function validateExpectedBinding(value, pattern, label) {
  if (value === undefined) return;
  if (typeof value !== "string" || !pattern.test(value) || !nonZero(value)) invalid("invalid_arguments", `${label} is invalid`);
}

function normalizeEvidence(value, options) {
  exactKeys(value, ROOT_KEYS, "evidence");
  rejectUnsafeMaterial(value);
  if (value.schema_version !== W16_DRILL_SCHEMA_VERSION) invalid("invalid_evidence", "unsupported schema version");
  if (typeof value.source_commit !== "string" || !COMMIT.test(value.source_commit) || !nonZero(value.source_commit)) invalid("invalid_evidence", "source binding is invalid");
  if (typeof value.image_digest !== "string" || !DIGEST.test(value.image_digest) || !nonZero(value.image_digest)) invalid("invalid_evidence", "image binding is invalid");
  if (typeof value.alert_policy_digest !== "string" || !DIGEST.test(value.alert_policy_digest) || !nonZero(value.alert_policy_digest)) invalid("invalid_evidence", "alert policy binding is invalid");
  if (options.expectedCommitSha !== undefined && value.source_commit !== options.expectedCommitSha) invalid("source_mismatch", "source binding mismatch");
  if (options.expectedImageDigest !== undefined && value.image_digest !== options.expectedImageDigest) invalid("source_mismatch", "image binding mismatch");
  if (options.expectedAlertPolicyDigest !== undefined && value.alert_policy_digest !== options.expectedAlertPolicyDigest) invalid("source_mismatch", "alert policy binding mismatch");

  const startedAt = parseUtc(value.started_at, "start timestamp");
  const completedAt = parseUtc(value.completed_at, "completion timestamp");
  const duration = completedAt - startedAt;
  if (duration < 1 || duration !== value.duration_ms || duration > options.maxDurationMs) invalid("invalid_evidence", "duration is invalid or unbounded");
  if (value.outcome !== "passed") invalid("invalid_evidence", "outcome is not passed");

  if (!Array.isArray(value.scenarios) || value.scenarios.length !== W16_DRILL_SCENARIOS.length) invalid("invalid_evidence", "scenario set is invalid");
  const scenarios = value.scenarios.map((scenario, index) => {
    exactKeys(scenario, SCENARIO_KEYS, `scenario ${index}`);
    if (scenario.name !== W16_DRILL_SCENARIOS[index] || scenario.outcome !== "passed") invalid("invalid_evidence", "scenario set is invalid");
    return scenario.name;
  });
  if (new Set(scenarios).size !== W16_DRILL_SCENARIOS.length) invalid("invalid_evidence", "scenario set is not unique");

  exactKeys(value.aggregate_observations, AGGREGATE_KEYS, "aggregate observations");
  const aggregate = value.aggregate_observations;
  if (aggregate.scenario_count !== 6 || aggregate.passed_count !== 6 || aggregate.failed_count !== 0
    || aggregate.alert_policy_rule_count !== 10
    || aggregate.warning_alerts_observed !== 10
    || aggregate.critical_alerts_observed !== 10
    || aggregate.unauthorized_mutations !== 0
    || aggregate.duplicate_provider_acceptances !== 0
    || aggregate.forbidden_material_findings !== 0
    || aggregate.active_claims !== 0 || aggregate.active_leases !== 0) {
    invalid("invalid_evidence", "aggregate observations are not a passed, drained drill");
  }
  return { startedAt, completedAt, duration };
}

function statIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeMs, stat.ctimeMs].join(":");
}

async function readEvidenceFile(inputFile) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)) invalid("invalid_arguments");
  if (!Number.isInteger(NOFOLLOW)) invalid("invalid_file");
  let listed;
  try { listed = await lstat(inputFile); } catch { invalid("invalid_file"); }
  if (!listed.isFile() || listed.isSymbolicLink() || listed.nlink !== 1 || listed.size < 1 || listed.size > W16_DRILL_MAX_BYTES || (listed.mode & 0o077) !== 0 || (listed.mode & 0o400) === 0) {
    invalid("invalid_file");
  }
  let handle;
  try {
    handle = await open(inputFile, fs.constants.O_RDONLY | NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > W16_DRILL_MAX_BYTES || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0 || statIdentity(before) !== statIdentity(listed)) {
      invalid("invalid_file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || bytes.length > W16_DRILL_MAX_BYTES || statIdentity(before) !== statIdentity(after)) invalid("invalid_file");
    return bytes;
  } catch (error) {
    if (error instanceof W16DrillEvidenceError) throw error;
    invalid("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
}

/**
 * Verify one W1.6 staging-drill evidence file without returning its contents.
 * Optional expected* bindings make the check suitable for a release/staging gate.
 */
export async function verifyW16DrillEvidence(inputFile, options = undefined) {
  const normalizedOptions = normalizeOptions(options);
  if (!integer(normalizedOptions.maxDurationMs, 1, W16_DRILL_MAX_DURATION_MS)) invalid("invalid_arguments", "max duration is invalid");
  validateExpectedBinding(normalizedOptions.expectedCommitSha, COMMIT, "expected commit");
  validateExpectedBinding(normalizedOptions.expectedImageDigest, DIGEST, "expected image digest");
  validateExpectedBinding(normalizedOptions.expectedAlertPolicyDigest, DIGEST, "expected alert policy digest");
  const bytes = await readEvidenceFile(inputFile);
  let evidence;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    rejectDuplicateJsonKeys(text);
    evidence = JSON.parse(text);
  } catch {
    invalid("invalid_evidence");
  }
  const timing = normalizeEvidence(evidence, normalizedOptions);
  return Object.freeze({
    ok: true,
    evidence_sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    schema_version: W16_DRILL_SCHEMA_VERSION,
    source_commit: evidence.source_commit,
    image_digest: evidence.image_digest,
    alert_policy_digest: evidence.alert_policy_digest,
    started_at: evidence.started_at,
    completed_at: evidence.completed_at,
    duration_ms: timing.duration,
    outcome: evidence.outcome,
    scenario_count: evidence.scenarios.length,
    alert_policy_rule_count: evidence.aggregate_observations.alert_policy_rule_count,
    warning_alerts_observed: evidence.aggregate_observations.warning_alerts_observed,
    critical_alerts_observed: evidence.aggregate_observations.critical_alerts_observed,
    active_claims: evidence.aggregate_observations.active_claims,
    active_leases: evidence.aggregate_observations.active_leases
  });
}

function parseCli(argv) {
  if (argv.length < 1) invalid("invalid_arguments");
  const inputFile = argv[0];
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!value || !["--commit-sha", "--image-digest", "--alert-policy-digest", "--max-duration-ms"].includes(flag)) invalid("invalid_arguments");
    if (flag === "--commit-sha") options.expectedCommitSha = value;
    else if (flag === "--image-digest") options.expectedImageDigest = value;
    else if (flag === "--alert-policy-digest") options.expectedAlertPolicyDigest = value;
    else options.maxDurationMs = Number(value);
    index += 1;
  }
  return { inputFile, options };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { inputFile, options } = parseCli(process.argv.slice(2));
    const result = await verifyW16DrillEvidence(inputFile, options);
    process.stdout.write(`${result.evidence_sha256}\n`);
  } catch (error) {
    const code = ["invalid_arguments", "invalid_file", "invalid_evidence", "source_mismatch"].includes(error?.code) ? error.code : "verification_failed";
    process.stderr.write(`w16-drill-evidence-verify: ${code}\n`);
    process.exitCode = code === "invalid_arguments" ? 2 : 1;
  }
}
