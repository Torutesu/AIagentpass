#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const OPERATIONS_READINESS_SCHEMA_VERSION = 1;
export const OPERATIONS_READINESS_KIND = "agentpass.operations-readiness-checklist";
export const OPERATIONS_READINESS_CHECKS = Object.freeze(["rollback", "pitr", "revoke_emergency_stop", "alerting", "tenant_isolation"]);
export const NOT_PROVEN = Object.freeze({
  status: "not_proven",
  reason: "protected_external_evidence_unavailable",
  required: OPERATIONS_READINESS_CHECKS
});

const MAX_BYTES = 64 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SAFE_TEXT = /^[A-Za-z0-9][A-Za-z0-9 ._:/+@-]{0,255}$/u;
const ROOT_KEYS = ["candidate_id", "checks", "completed_at", "evidence_origin", "execution_mode", "kind", "schema_version", "source_commit", "started_at"];
const CHECK_KEYS = ["assertions", "candidate_id", "evidence_digest", "evidence_origin", "observed_at", "source_commit", "status"];
const ASSERTION_KEYS = Object.freeze({
  rollback: ["authority_not_widened", "deployment_rollback_verified", "health_gate_verified", "previous_revision_rejected", "rollback_artifact_digest"],
  pitr: ["backup_artifact_digest", "backup_manifest_verified", "pitr_restore_verified", "recovery_target_bound", "schema_head_match", "tenant_integrity_verified"],
  revoke_emergency_stop: ["ack_quorum_verified", "emergency_stop_propagation_verified", "existing_capability_denied", "new_capability_denied", "revoke_propagation_verified", "terminal_state_verified"],
  alerting: ["alert_rules_verified", "counter_reset_fail_closed", "delivery_verified", "escalation_verified", "policy_digest", "secret_free_evidence"],
  tenant_isolation: ["admin_scope_verified", "cross_tenant_denied", "no_cross_tenant_rows", "pair_count", "rls_policy_verified", "same_tenant_allowed", "tenant_pair_matrix_verified"]
});

export class OperationsReadinessError extends Error {
  constructor(code, message = code) { super(message); this.name = "OperationsReadinessError"; this.code = code; }
}
function invalid(code, message = code) { throw new OperationsReadinessError(code, message); }
function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) invalid("invalid_shape", `${label} must be a plain object`);
  return value;
}
function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key))) invalid("unknown_field", `${label} contains a non-enumerable or symbol field`);
  const left = actual.sort(); const right = [...expected].sort();
  if (left.length !== right.length || left.some((key, index) => key !== right[index])) invalid("unknown_field", `${label} has an unknown or missing field`);
}
function safeString(value, label, pattern = SAFE_TEXT) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f\u2028\u2029\r\n]/u.test(value) || !pattern.test(value)) invalid("invalid_value", `${label} is invalid`);
  return value;
}
function digest(value, label) { return safeString(value, label, SHA256); }
function timestamp(value, label) {
  safeString(value, label, ISO_UTC);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) invalid("invalid_timestamp", `${label} is invalid`);
  return value;
}

// JSON.parse cannot detect duplicate members; this small scanner rejects them before parsing.
function parseDuplicateSafeJson(text) {
  let offset = 0;
  const whitespace = () => { while (offset < text.length && /[ \t\r\n]/u.test(text[offset])) offset += 1; };
  const fail = () => invalid("invalid_json", "evidence JSON is invalid");
  const parseString = () => {
    const start = offset; if (text[offset++] !== '"') fail();
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '"') { try { return JSON.parse(text.slice(start, offset)); } catch { fail(); } }
      if (character === "\\") {
        if (offset >= text.length) fail(); const escaped = text[offset++];
        if (escaped === "u") { if (!/^[0-9a-f]{4}$/iu.test(text.slice(offset, offset + 4))) fail(); offset += 4; }
        else if (!/["\\/bfnrt]/u.test(escaped)) fail();
      } else if (character.charCodeAt(0) < 0x20) fail();
    }
    fail();
  };
  const parseValue = () => {
    whitespace();
    if (text[offset] === '"') { parseString(); return; }
    if (text[offset] === "{") { parseObject(); return; }
    if (text[offset] === "[") { parseArray(); return; }
    const literal = text.slice(offset).match(/^(?:true|false|null)/u);
    if (literal) { offset += literal[0].length; return; }
    const number = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!number) fail(); offset += number[0].length;
  };
  const parseArray = () => {
    offset += 1; whitespace(); if (text[offset] === "]") { offset += 1; return; }
    while (true) { parseValue(); whitespace(); if (text[offset] === "]") { offset += 1; return; } if (text[offset++] !== ",") fail(); }
  };
  const parseObject = () => {
    offset += 1; whitespace(); const keys = new Set(); if (text[offset] === "}") { offset += 1; return; }
    while (true) {
      const key = parseString(); if (keys.has(key)) invalid("duplicate_field", "evidence JSON has duplicate fields"); keys.add(key);
      whitespace(); if (text[offset++] !== ":") fail(); parseValue(); whitespace();
      if (text[offset] === "}") { offset += 1; return; } if (text[offset++] !== ",") fail();
    }
  };
  parseValue(); whitespace(); if (offset !== text.length) fail(); return JSON.parse(text);
}

function validateAssertions(name, assertions) {
  exactKeys(assertions, ASSERTION_KEYS[name], `${name} assertions`);
  for (const [key, value] of Object.entries(assertions)) {
    if (key.endsWith("_digest") || key === "policy_digest") digest(value, `${name}.${key}`);
    else if (key === "pair_count") { if (!Number.isSafeInteger(value) || value < 2 || value > 100000) invalid("invalid_assertion", `${name}.${key} is invalid`); }
    else if (value !== true) invalid("not_proven", `${name}.${key} is not proven`);
  }
}

export function verifyOperationsReadiness(value, { expectedCandidateId, expectedSourceCommit } = {}) {
  exactKeys(value, ROOT_KEYS, "checklist");
  if (value.schema_version !== OPERATIONS_READINESS_SCHEMA_VERSION || value.kind !== OPERATIONS_READINESS_KIND) invalid("invalid_schema", "unsupported checklist schema");
  if (!CANDIDATE.test(value.candidate_id) || !COMMIT.test(value.source_commit)) invalid("invalid_binding", "candidate or source binding is invalid");
  if (expectedCandidateId !== value.candidate_id || expectedSourceCommit !== value.source_commit) invalid("source_mismatch", "candidate or source binding mismatch");
  if (value.execution_mode !== "protected_external" || value.evidence_origin !== "protected_external") invalid("not_proven", "protected external evidence is required");
  const started = Date.parse(timestamp(value.started_at, "started_at")); const completed = Date.parse(timestamp(value.completed_at, "completed_at"));
  if (!(completed > started) || completed - started > 24 * 60 * 60 * 1000) invalid("invalid_time_window", "checklist time window is invalid");
  exactKeys(value.checks, OPERATIONS_READINESS_CHECKS, "checks");
  for (const name of OPERATIONS_READINESS_CHECKS) {
    const check = value.checks[name]; exactKeys(check, CHECK_KEYS, `${name} check`);
    if (check.status !== "verified" || check.evidence_origin !== "protected_external") invalid("not_proven", `${name} is not verified by protected evidence`);
    if (check.candidate_id !== value.candidate_id || check.source_commit !== value.source_commit) invalid("source_mismatch", `${name} binding mismatch`);
    digest(check.evidence_digest, `${name}.evidence_digest`); timestamp(check.observed_at, `${name}.observed_at`); validateAssertions(name, check.assertions);
  }
  return Object.freeze({ status: "closed", candidate_id: value.candidate_id, source_commit: value.source_commit, checks: OPERATIONS_READINESS_CHECKS,
    evidence_sha256: crypto.createHash("sha256").update(`${canonicalJson(value)}\n`, "utf8").digest("hex") });
}

export function readOperationsReadinessEvidence(file, options) {
  if (typeof file !== "string" || !path.isAbsolute(file)) invalid("invalid_evidence_file", "evidence path must be absolute");
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch { invalid("not_proven", "protected external evidence is unavailable"); }
  let text;
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_BYTES)) invalid("invalid_evidence_file", "evidence must be a regular file");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) invalid("invalid_evidence_file", "evidence changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if ([before.dev, before.ino, before.mode, before.nlink, before.size, before.mtimeNs, before.ctimeNs].join(":")
      !== [after.dev, after.ino, after.mode, after.nlink, after.size, after.mtimeNs, after.ctimeNs].join(":")) invalid("invalid_evidence_file", "evidence changed while reading");
    text = bytes.toString("utf8");
  } finally { fs.closeSync(fd); }
  if (!text.endsWith("\n")) invalid("noncanonical_evidence", "evidence must end with one newline");
  const value = parseDuplicateSafeJson(text); if (`${canonicalJson(value)}\n` !== text) invalid("noncanonical_evidence", "evidence is not canonical JSON");
  return verifyOperationsReadiness(value, options);
}

function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "verify" || !path.isAbsolute(args[1]) || !CANDIDATE.test(args[2]) || !COMMIT.test(args[3])) { output(NOT_PROVEN); process.exitCode = 2; return; }
  try { output(readOperationsReadinessEvidence(args[1], { expectedCandidateId: args[2], expectedSourceCommit: args[3] })); }
  catch (error) { output({ status: "not_proven", reason: error instanceof OperationsReadinessError ? error.code : "verification_failed" }); process.exitCode = 2; }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
