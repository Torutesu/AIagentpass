#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const W16_ALERT_POLICY_MAX_BYTES = 64 * 1024;
export const W16_ALERT_NAMES = Object.freeze([
  "owner_recovery_pending_queue_age",
  "owner_recovery_pending_queue_count",
  "owner_recovery_uncertain_delivery_count",
  "owner_recovery_uncertain_delivery_age",
  "owner_recovery_dead_letters",
  "owner_recovery_redrive_failures",
  "owner_recovery_prune_failures",
  "human_auth_rate_limit_denials",
  "human_auth_rate_limit_unavailability",
  "owner_recovery_state_latency"
]);

const ROOT_KEYS = Object.freeze(["alerts", "kind", "label_policy", "metric_namespace", "schema_version"]);
const LABEL_POLICY_KEYS = Object.freeze(["labels", "mode"]);
const ALERT_KEYS = Object.freeze(["aggregation", "metric", "name", "sample_count_metric", "thresholds", "unit"]);
const THRESHOLD_KEYS = Object.freeze(["comparison", "severity", "unit", "value", "window_seconds"]);
const SEVERITIES = Object.freeze(["warning", "critical"]);
const COMPARISONS = new Set([">=", ">", "<=", "<"]);
const MAX_WINDOW_SECONDS = 86_400;
const MIN_WINDOW_SECONDS = 60;
const MAX_COUNT = 1_000_000;
const MAX_DURATION_MS = 86_400_000;
const FORBIDDEN_KEY = /(?:tenant|organization|member|event|request|session|user|url|dsn|credential|secret|token|password|private|authorization|cookie|email|ip|repository|destination|webhook|api[_-]?key|access[_-]?token|bearer)/iu;
const FORBIDDEN_VALUE = /(?:https?:\/\/|postgres(?:ql)?|mysql|redis|file:\/\/|-----BEGIN|(?:secret|credential|password|token|dsn|bearer|private[_-]?key)\s*[:=]?|\{\{[^}]+\}\}|\$\{[^}]+\})/iu;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const ALERT_RULES = Object.freeze([
  rule("owner_recovery_pending_queue_age", "owner_recovery_outbox_oldest_pending_age_ms", "max", null, "milliseconds", 86_400_000, 300_000, 900_000, 300),
  rule("owner_recovery_pending_queue_count", "owner_recovery_outbox_pending_count", "max", null, "events", 1_000_000, 10, 100, 300),
  rule("owner_recovery_uncertain_delivery_count", "owner_recovery_outbox_uncertain_count", "max", null, "events", 1_000_000, 1, 10, 300),
  rule("owner_recovery_uncertain_delivery_age", "owner_recovery_outbox_oldest_uncertain_age_ms", "max", null, "milliseconds", 86_400_000, 300_000, 1_800_000, 300),
  rule("owner_recovery_dead_letters", "owner_recovery_outbox_dead_letter_count", "max", null, "events", 1_000_000, 1, 10, 300),
  rule("owner_recovery_redrive_failures", "owner_recovery_outbox_redrive_failure_total", "increase", null, "events", 1_000_000, 1, 5, 900),
  rule("owner_recovery_prune_failures", "owner_recovery_outbox_prune_failure_total", "increase", null, "events", 1_000_000, 1, 3, 900),
  rule("human_auth_rate_limit_denials", "human_auth_rate_limit_denial_total", "increase", null, "events", 1_000_000, 20, 100, 300),
  rule("human_auth_rate_limit_unavailability", "human_auth_rate_limit_unavailable_total", "increase", null, "events", 1_000_000, 1, 3, 300),
  rule("owner_recovery_state_latency", "owner_recovery_state_latency_total_ms", "mean", "owner_recovery_state_latency_count", "milliseconds", 86_400_000, 1_000, 5_000, 900)
]);

function rule(name, metric, aggregation, sampleCountMetric, unit, maxValue, warning, critical, windowSeconds) {
  return Object.freeze({ name, metric, aggregation, sampleCountMetric, unit, maxValue, warning, critical, windowSeconds, comparison: ">=" });
}

export class W16AlertPolicyError extends Error {
  constructor(code = "invalid_policy") {
    super("invalid W1.6 alert policy");
    this.name = "W16AlertPolicyError";
    this.code = code;
  }
}

export function parseStrictW16AlertsJson(text) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") === 0 || Buffer.byteLength(text, "utf8") > W16_ALERT_POLICY_MAX_BYTES) throw invalid();
  scanJsonForDuplicateKeys(text);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw invalid();
  }
  return value;
}

export function validateW16AlertPolicy(value) {
  rejectForbiddenMaterial(value);
  if (!plainObject(value) || !sameKeys(value, ROOT_KEYS) || value.schema_version !== 1 || value.kind !== "agentpass.owner_recovery_alert_policy" || value.metric_namespace !== "agentpass") throw invalid();
  if (!plainObject(value.label_policy) || !sameKeys(value.label_policy, LABEL_POLICY_KEYS) || value.label_policy.mode !== "none" || !Array.isArray(value.label_policy.labels) || value.label_policy.labels.length !== 0) throw invalid();
  if (!Array.isArray(value.alerts) || value.alerts.length !== ALERT_RULES.length) throw invalid();
  value.alerts.forEach((alert, index) => validateAlert(alert, ALERT_RULES[index]));
  return value;
}

export async function validateW16AlertsFile(inputFile) {
  return (await inspectW16AlertsFile(inputFile)).policy;
}

export async function inspectW16AlertsFile(inputFile) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)) throw invalid("invalid_arguments");
  let stat;
  try {
    stat = await lstat(inputFile);
  } catch {
    throw invalid("invalid_file");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > W16_ALERT_POLICY_MAX_BYTES || (stat.mode & 0o022) !== 0) throw invalid("invalid_file");
  let handle;
  let bytes;
  try {
    handle = await open(inputFile, fs.constants.O_RDONLY | NOFOLLOW);
    const before = await handle.stat();
    if (!sameFile(stat, before) || before.nlink !== 1 || (before.mode & 0o022) !== 0) throw invalid("invalid_file");
    bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameFile(before, after)) throw invalid("invalid_file");
  } catch {
    throw invalid("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
  if (bytes.length !== stat.size || bytes.length > W16_ALERT_POLICY_MAX_BYTES) throw invalid("invalid_file");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw invalid("invalid_policy");
  }
  const policy = validateW16AlertPolicy(parseStrictW16AlertsJson(text));
  return Object.freeze({
    policy,
    policy_digest: `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`
  });
}

function sameFile(left, right) {
  return left.isFile() && right.isFile()
    && left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function validateAlert(value, expected) {
  if (!plainObject(value) || !sameKeys(value, ALERT_KEYS) || value.name !== expected.name || value.metric !== expected.metric || value.aggregation !== expected.aggregation || value.sample_count_metric !== expected.sampleCountMetric || value.unit !== expected.unit) throw invalid();
  if (!Array.isArray(value.thresholds) || value.thresholds.length !== 2) throw invalid();
  value.thresholds.forEach((threshold, index) => validateThreshold(threshold, expected, SEVERITIES[index], index));
  const [warning, critical] = value.thresholds;
  if (warning.comparison !== critical.comparison) throw invalid();
  if ([">=", ">"].includes(warning.comparison) && warning.value >= critical.value) throw invalid();
  if (["<=", "<"].includes(warning.comparison) && warning.value <= critical.value) throw invalid();
  if (critical.window_seconds < warning.window_seconds) throw invalid();
}

function validateThreshold(value, expected, severity, index) {
  if (!plainObject(value) || !sameKeys(value, THRESHOLD_KEYS) || value.severity !== severity || value.unit !== expected.unit || !COMPARISONS.has(value.comparison)) throw invalid();
  if (!Number.isSafeInteger(value.value) || value.value < 1 || value.value > expected.maxValue) throw invalid();
  if (!Number.isSafeInteger(value.window_seconds) || value.window_seconds < MIN_WINDOW_SECONDS || value.window_seconds > MAX_WINDOW_SECONDS) throw invalid();
  if (index === 0 && value.value !== expected.warning) throw invalid();
  if (index === 1 && value.value !== expected.critical) throw invalid();
  if (value.comparison !== expected.comparison || value.window_seconds !== expected.windowSeconds) throw invalid();
}

function rejectForbiddenMaterial(value, seen = new Set()) {
  if (typeof value === "string") {
    if (FORBIDDEN_VALUE.test(value)) throw invalid();
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw invalid();
    seen.add(value);
    value.forEach((item) => rejectForbiddenMaterial(item, seen));
    return;
  }
  if (!plainObject(value)) return;
  if (seen.has(value)) throw invalid();
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEY.test(key)) throw invalid();
    rejectForbiddenMaterial(child, seen);
  }
}

function scanJsonForDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/[ \t\r\n]/u.test(text[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === '"') {
        index += 1;
        try { return JSON.parse(text.slice(start, index)); } catch { throw invalid(); }
      }
      index += 1;
    }
    throw invalid();
  };
  const value = () => {
    whitespace();
    if (text[index] === "{") return object();
    if (text[index] === "[") return array();
    if (text[index] === '"') { string(); return; }
    const start = index;
    while (index < text.length && !/[ \t\r\n,\]}]/u.test(text[index])) index += 1;
    if (start === index) throw invalid();
    try { JSON.parse(text.slice(start, index)); } catch { throw invalid(); }
  };
  const object = () => {
    index += 1;
    const keys = new Set();
    whitespace();
    if (text[index] === "}") { index += 1; return; }
    while (true) {
      whitespace();
      if (text[index] !== '"') throw invalid();
      const key = string();
      if (keys.has(key)) throw invalid();
      keys.add(key);
      whitespace();
      if (text[index++] !== ":") throw invalid();
      value();
      whitespace();
      if (text[index] === "}") { index += 1; return; }
      if (text[index++] !== ",") throw invalid();
    }
  };
  const array = () => {
    index += 1;
    whitespace();
    if (text[index] === "]") { index += 1; return; }
    while (true) {
      value();
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      if (text[index++] !== ",") throw invalid();
    }
  };
  value();
  whitespace();
  if (index !== text.length) throw invalid();
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function sameKeys(value, expected) { return Object.keys(value).sort().join("\u0000") === [...expected].sort().join("\u0000"); }
function invalid(code = "invalid_policy") { return new W16AlertPolicyError(code); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !path.isAbsolute(args[0])) {
    process.stderr.write("w16-alerts: invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const result = await inspectW16AlertsFile(args[0]);
      process.stdout.write(`${result.policy_digest}\n`);
    } catch (error) {
      process.stderr.write(`w16-alerts: ${error?.code === "invalid_arguments" ? "invalid_arguments" : "invalid_policy"}\n`);
      process.exitCode = 1;
    }
  }
}
