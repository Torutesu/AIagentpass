#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { open, lstat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_BYTES = 4_096;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const KEYS = Object.freeze([
  "accepted_binding_ids", "accepted_event_digests", "active_leases", "final_state_classes",
  "max_attempts", "pending_claims", "prune_race_winner", "race_winner", "scenarios", "version"
].sort());
const SCENARIOS = Object.freeze([
  "stale_acknowledgements",
  "lease_expiry_pending_provider",
  "retry_suppress_cas",
  "prune_redrive_cas",
  "two_worker_exact_binding"
]);
const FINAL_STATES = new Set(["dead_letter", "published", "suppressed", "uncertain"]);

export async function verifyW15Evidence(inputFile) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)) throw invalid("invalid_arguments");
  let stat;
  try { stat = await lstat(inputFile); }
  catch { throw invalid("invalid_file"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > MAX_BYTES || (stat.mode & 0o077) !== 0) {
    throw invalid("invalid_file");
  }
  let handle;
  let bytes;
  try {
    handle = await open(inputFile, fs.constants.O_RDONLY | NOFOLLOW);
    bytes = await handle.readFile();
  } catch {
    throw invalid("invalid_file");
  } finally {
    await handle?.close().catch(() => {});
  }
  if (bytes.length !== stat.size || bytes.length > MAX_BYTES) throw invalid("invalid_file");
  let evidence;
  try { evidence = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw invalid("invalid_evidence"); }
  normalizeEvidence(evidence);
  return Object.freeze({
    evidence_sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    accepted_event_count: evidence.accepted_event_digests.length,
    final_state_count: evidence.final_state_classes.length
  });
}

function normalizeEvidence(value) {
  if (!plainObject(value) || !sameArray(Object.keys(value).sort(), KEYS) || value.version !== 1) throw invalid("invalid_evidence");
  if (!sameArray(value.scenarios, SCENARIOS)) throw invalid("invalid_evidence");
  if (!["retry", "suppress"].includes(value.race_winner) || !["prune", "redrive"].includes(value.prune_race_winner)) throw invalid("invalid_evidence");
  if (!integer(value.max_attempts, 1, 100) || value.pending_claims !== 0 || value.active_leases !== 0) throw invalid("invalid_evidence");
  if (!Array.isArray(value.final_state_classes) || value.final_state_classes.length !== 4
    || value.final_state_classes.some((item) => typeof item !== "string" || !FINAL_STATES.has(item))
    || !sorted(value.final_state_classes)) throw invalid("invalid_evidence");
  if (!Array.isArray(value.accepted_event_digests) || value.accepted_event_digests.length < 2 || value.accepted_event_digests.length > 3
    || value.accepted_event_digests.some((item) => typeof item !== "string" || !/^[0-9a-f]{16}$/u.test(item))
    || new Set(value.accepted_event_digests).size !== value.accepted_event_digests.length
    || !sorted(value.accepted_event_digests)) throw invalid("invalid_evidence");
  if (!Array.isArray(value.accepted_binding_ids)
    || value.accepted_binding_ids.length !== value.accepted_event_digests.length
    || value.accepted_binding_ids.some((item) => item !== "race-matrix-provider")) throw invalid("invalid_evidence");
  return value;
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function integer(value, min, max) { return Number.isSafeInteger(value) && value >= min && value <= max; }
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function sorted(value) { return value.every((item, index) => index === 0 || value[index - 1].localeCompare(item) <= 0); }
function invalid(code) { const error = new Error(code); error.code = code; return error; }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [inputFile, ...extra] = process.argv.slice(2);
  if (!inputFile || extra.length !== 0) {
    process.stderr.write("w15-evidence-verify: invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const result = await verifyW15Evidence(inputFile);
      process.stdout.write(`${result.evidence_sha256}\n`);
    } catch (error) {
      const code = ["invalid_arguments", "invalid_file", "invalid_evidence"].includes(error?.code) ? error.code : "verification_failed";
      process.stderr.write(`w15-evidence-verify: ${code}\n`);
      process.exitCode = 1;
    }
  }
}
