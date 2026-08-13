#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const CONTAINER_ID = /^[0-9a-f]{12,64}$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const USERINFO_URL = /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu;
const SENSITIVE_VALUE = /(?:credential|cookie|csrf|nonce|signature|private[-_ ]?key|public[-_ ]?key|secret|password|bearer|authorization|token|\bkey)\s*[:=]\s*\S+/iu;
const SENSITIVE_COMMAND_OPTION = /(?:^|[-_])(credential|cookie|csrf|nonce|signature|private[-_ ]?key|public[-_ ]?key|secret|password|bearer|authorization|token|keys?)(?:=|$)/iu;
const DIGESTED_ARTIFACTS = new WeakSet();

export const P0B_REQUIRED_COMMAND_IDS = Object.freeze(["browser-e2e"]);
export const P0B_REQUIRED_GATE_IDS = Object.freeze(["browser-flow"]);

export const P0B_QUALIFICATION_SCHEMA_VERSION = 1;

export class QualificationReportError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "QualificationReportError";
    this.code = code;
  }
}

function invalid(code, message = code) {
  throw new QualificationReportError(code, message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid("invalid_shape", `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid("unknown_field", `${label} has an unknown or missing field`);
}

function optionalKeys(value, allowed, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid("invalid_shape", `${label} must be an object`);
  if (Object.keys(value).some((key) => !allowed.has(key))) invalid("unknown_field", `${label} has an unknown field`);
}

function stringValue(value, label, { maximum = 1024, pattern } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\u0000") || USERINFO_URL.test(value) || SENSITIVE_VALUE.test(value) || /-----BEGIN [^-\n]+ KEY-----/u.test(value)) {
    invalid("unsafe_string", `${label} is invalid`);
  }
  if (pattern && !pattern.test(value)) invalid("invalid_value", `${label} is invalid`);
  return value;
}

function safeCommandArgument(value) {
  stringValue(value, "command argument", { maximum: 4096 });
  if (SENSITIVE_COMMAND_OPTION.test(value)) invalid("sensitive_command_argument", "command arguments must not carry secrets");
  return value;
}

function digestBytes(value, label) {
  if (typeof value === "string") return { sha256: sha256(Buffer.from(value, "utf8")), bytes: Buffer.byteLength(value, "utf8") };
  if (value instanceof Uint8Array) return { sha256: sha256(value), bytes: value.byteLength };
  invalid("invalid_output", `${label} must be text or bytes`);
}

function digestAndSize(value, digest, bytes, label) {
  const actual = value === undefined ? undefined : digestBytes(value, label);
  if (actual) {
    if (digest !== undefined && digest !== actual.sha256) invalid("digest_mismatch", `${label} digest does not match`);
    if (bytes !== undefined && bytes !== actual.bytes) invalid("size_mismatch", `${label} size does not match`);
    return actual;
  }
  if (!SHA256.test(digest ?? "") || !Number.isSafeInteger(bytes) || bytes < 0) invalid("missing_output_digest", `${label} digest and size are required`);
  return { sha256: digest, bytes };
}

function normalizeTimestamp(value, label) {
  stringValue(value, label, { maximum: 24, pattern: ISO_UTC });
  if (!Number.isFinite(Date.parse(value))) invalid("invalid_timestamp", `${label} is invalid`);
  return value;
}

function normalizeCommand(command, index) {
  optionalKeys(command, new Set(["id", "argv", "cwd", "result"]), `command ${index}`);
  const id = stringValue(command.id, `command ${index} id`, { maximum: 80, pattern: /^[a-z0-9][a-z0-9._-]{1,79}$/u });
  if (!Array.isArray(command.argv) || command.argv.length === 0 || command.argv.length > 128) invalid("invalid_command", "command argv is invalid");
  const argv = command.argv.map(safeCommandArgument);
  const cwd = stringValue(command.cwd, `command ${index} cwd`, { maximum: 1024 });
  optionalKeys(command.result, new Set(["status", "exit_code", "signal", "duration_ms", "stdout", "stderr", "stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes", "reason"]), `command ${index} result`);
  const result = command.result;
  if (result === null || typeof result !== "object" || Array.isArray(result)) invalid("invalid_command_result", "command result is invalid");
  const inputStatus = result.status;
  const skipped = inputStatus === "skipped";
  const status = skipped ? "failed" : inputStatus;
  if (status !== "passed" && status !== "failed") invalid("invalid_command_result", "command result status is invalid");
  if (!Number.isSafeInteger(result.exit_code) || result.exit_code < 0 || result.exit_code > 255) invalid("invalid_command_result", "command exit code is invalid");
  if (result.signal !== null && result.signal !== undefined && !/^[A-Z][A-Z0-9]{0,15}$/u.test(result.signal)) invalid("invalid_command_result", "command signal is invalid");
  if (!Number.isSafeInteger(result.duration_ms) || result.duration_ms < 0 || result.duration_ms > 7 * 24 * 60 * 60 * 1000) invalid("invalid_command_result", "command duration is invalid");
  const stdout = digestAndSize(result.stdout, result.stdout_sha256, result.stdout_bytes, "stdout");
  const stderr = digestAndSize(result.stderr, result.stderr_sha256, result.stderr_bytes, "stderr");
  const reason = skipped ? "command_skipped" : status === "failed" ? stringValue(result.reason ?? "command_failed", "command failure reason", { maximum: 128, pattern: /^[a-z][a-z0-9._-]{1,127}$/u }) : null;
  return {
    id,
    argv,
    cwd,
    result: {
      status,
      exit_code: result.exit_code,
      signal: result.signal ?? null,
      duration_ms: result.duration_ms,
      stdout_sha256: stdout.sha256,
      stdout_bytes: stdout.bytes,
      stderr_sha256: stderr.sha256,
      stderr_bytes: stderr.bytes,
      reason
    }
  };
}

function normalizePostgres(value) {
  exactKeys(value, ["image", "image_digest", "container_id", "container_started_at", "server_version"], "postgres metadata");
  const image = stringValue(value.image, "PostgreSQL image", { maximum: 256 });
  if (image.includes("@") || /\s/u.test(image)) invalid("unsafe_postgres_metadata", "PostgreSQL image is invalid");
  if (!IMAGE_DIGEST.test(value.image_digest)) invalid("unsafe_postgres_metadata", "PostgreSQL image digest is invalid");
  if (!CONTAINER_ID.test(value.container_id)) invalid("unsafe_postgres_metadata", "PostgreSQL container id is invalid");
  const containerStartedAt = normalizeTimestamp(value.container_started_at, "PostgreSQL container start time");
  const serverVersion = stringValue(value.server_version, "PostgreSQL server version", { maximum: 64, pattern: /^\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$/u });
  return { image, image_digest: value.image_digest, container_id: value.container_id, container_started_at: containerStartedAt, server_version: serverVersion };
}

function normalizeBrowser(value) {
  exactKeys(value, ["name", "version", "engine"], "browser metadata");
  const name = stringValue(value.name, "browser name", { maximum: 64, pattern: /^[A-Za-z][A-Za-z0-9 ._-]{1,63}$/u });
  const version = stringValue(value.version, "browser version", { maximum: 64, pattern: /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/u });
  const engine = stringValue(value.engine, "browser engine", { maximum: 64, pattern: /^[A-Za-z][A-Za-z0-9 ._-]{1,63}$/u });
  return { name, version, engine };
}

function normalizeArtifacts(value, { requireDigestProvenance = false } = {}) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) invalid("invalid_artifacts", "at least one artifact digest is required");
  if (requireDigestProvenance && value.some((artifact) => !DIGESTED_ARTIFACTS.has(artifact))) {
    invalid("untrusted_artifact", "artifacts must be produced by digestArtifactFile");
  }
  const names = new Set();
  return value.map((artifact, index) => {
    exactKeys(artifact, ["name", "kind", "sha256", "bytes"], `artifact ${index}`);
    const name = stringValue(artifact.name, `artifact ${index} name`, { maximum: 128, pattern: SAFE_NAME });
    const kind = stringValue(artifact.kind, `artifact ${index} kind`, { maximum: 64, pattern: SAFE_NAME });
    if (names.has(name)) invalid("duplicate_artifact", "artifact names must be unique");
    names.add(name);
    if (!SHA256.test(artifact.sha256)) invalid("invalid_artifact_digest", "artifact digest is invalid");
    if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || artifact.bytes > MAX_ARTIFACT_BYTES) invalid("invalid_artifact_size", "artifact size is invalid");
    return { name, kind, sha256: artifact.sha256, bytes: artifact.bytes };
  });
}

function normalizeGates(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) invalid("invalid_gates", "at least one qualification gate is required");
  const names = new Set();
  return value.map((gate, index) => {
    optionalKeys(gate, new Set(["id", "status", "evidence_sha256", "reason"]), `gate ${index}`);
    const id = stringValue(gate.id, `gate ${index} id`, { maximum: 80, pattern: /^[a-z0-9][a-z0-9._-]{1,79}$/u });
    if (names.has(id)) invalid("duplicate_gate", "gate ids must be unique");
    names.add(id);
    const skipped = gate.status === "skipped";
    const status = skipped ? "failed" : gate.status;
    if (status !== "passed" && status !== "failed") invalid("invalid_gate_status", "gate status is invalid");
    const evidence = gate.evidence_sha256;
    if (evidence !== undefined && !SHA256.test(evidence)) invalid("invalid_gate_evidence", "gate evidence digest is invalid");
    const reason = skipped ? "gate_skipped" : status === "failed" ? stringValue(gate.reason ?? "gate_failed", "gate failure reason", { maximum: 128, pattern: /^[a-z][a-z0-9._-]{1,127}$/u }) : null;
    if (status === "passed" && !evidence) invalid("missing_gate_evidence", "passed gates require evidence digest");
    return { id, status, evidence_sha256: evidence ?? null, reason };
  });
}

function requireCanonicalIds(value, required, label, code) {
  if (!Array.isArray(value) || value.length !== required.length || value.some((item, index) => item?.id !== required[index])) {
    invalid(code, `${label} must contain the canonical required ids in order`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function statIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeMs, stat.ctimeMs].join(":");
}

/** RFC 8785-shaped canonical JSON for the report's restricted JSON values. */
export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid("non_finite_number", "canonical JSON cannot contain a non-finite number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  invalid("non_json_value", "canonical JSON cannot contain this value");
}

function reportCore(report) {
  const { report_digest: ignored, ...core } = report;
  void ignored;
  return core;
}

function reportDigest(report) {
  return `sha256:${sha256(Buffer.from(canonicalJson(reportCore(report)), "utf8"))}`;
}

function normalizeQualificationInput(input, { requireDigestProvenance = true } = {}) {
  exactKeys(input, ["source_commit", "started_at", "completed_at", "commands", "postgres", "browser", "artifacts", "gates"], "qualification input");
  const sourceCommit = stringValue(input.source_commit, "source commit", { maximum: 64, pattern: COMMIT });
  const startedAt = normalizeTimestamp(input.started_at, "qualification start time");
  const completedAt = normalizeTimestamp(input.completed_at, "qualification completion time");
  if (Date.parse(completedAt) < Date.parse(startedAt)) invalid("invalid_time_window", "qualification completion precedes start");
  if (!Array.isArray(input.commands) || input.commands.length === 0 || input.commands.length > 512) invalid("invalid_commands", "at least one command is required");
  requireCanonicalIds(input.commands, P0B_REQUIRED_COMMAND_IDS, "commands", "invalid_command_ids");
  const commands = input.commands.map(normalizeCommand);
  const postgres = normalizePostgres(input.postgres);
  const browser = normalizeBrowser(input.browser);
  const artifacts = normalizeArtifacts(input.artifacts, { requireDigestProvenance });
  requireCanonicalIds(input.gates, P0B_REQUIRED_GATE_IDS, "gates", "invalid_gate_ids");
  const gates = normalizeGates(input.gates);
  return { sourceCommit, startedAt, completedAt, commands, postgres, browser, artifacts, gates };
}

function makeQualificationReport({ sourceCommit, startedAt, completedAt, commands, postgres, browser, artifacts, gates }) {
  const failedCommands = commands.filter(({ result }) => result.status !== "passed").map(({ id }) => id);
  const failedGates = gates.filter(({ status }) => status !== "passed").map(({ id }) => id);
  const passed = failedCommands.length === 0 && failedGates.length === 0;
  const report = {
    schema_version: P0B_QUALIFICATION_SCHEMA_VERSION,
    qualification: "p0b",
    source_commit: sourceCommit,
    started_at: startedAt,
    completed_at: completedAt,
    commands,
    postgres,
    browser,
    artifacts,
    gates,
    overall: { status: passed ? "passed" : "failed", failed_commands: failedCommands, failed_gates: failedGates },
    report_digest: ""
  };
  report.report_digest = reportDigest(report);
  return Object.freeze(report);
}

export function buildP0BQualificationReport(input, options = {}) {
  optionalKeys(options, new Set(["repositoryRoot"]), "qualification options");
  const normalized = normalizeQualificationInput(input);
  if (options.repositoryRoot !== undefined) {
    const resolvedCommit = resolveSourceCommit(options.repositoryRoot);
    if (normalized.sourceCommit !== resolvedCommit) invalid("source_commit_mismatch", "source commit does not match the repository HEAD");
  }
  return makeQualificationReport(normalized);
}

export function serializeP0BQualificationReport(report) {
  if (report === null || typeof report !== "object" || report.report_digest !== reportDigest(report)) invalid("invalid_report_digest", "qualification report digest is invalid");
  const bytes = Buffer.from(`${canonicalJson(report)}\n`, "utf8");
  if (bytes.length > MAX_REPORT_BYTES) invalid("report_too_large", "qualification report is too large");
  parseP0BQualificationReport(bytes);
  return bytes;
}

export function parseP0BQualificationReport(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_REPORT_BYTES) invalid("invalid_report", "qualification report bytes are invalid");
  let value;
  try { value = JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { invalid("invalid_json", "qualification report is not JSON"); }
  if (canonicalJson(value) + "\n" !== Buffer.from(bytes).toString("utf8")) invalid("noncanonical_json", "qualification report is not canonical JSON");
  exactKeys(value, ["schema_version", "qualification", "source_commit", "started_at", "completed_at", "commands", "postgres", "browser", "artifacts", "gates", "overall", "report_digest"], "qualification report");
  if (value.schema_version !== P0B_QUALIFICATION_SCHEMA_VERSION || value.qualification !== "p0b") invalid("invalid_schema", "qualification report schema is invalid");
  if (value.report_digest !== reportDigest(value)) invalid("invalid_report_digest", "qualification report digest is invalid");
  const rebuilt = makeQualificationReport(normalizeQualificationInput({
    source_commit: value.source_commit,
    started_at: value.started_at,
    completed_at: value.completed_at,
    commands: value.commands,
    postgres: value.postgres,
    browser: value.browser,
    artifacts: value.artifacts,
    gates: value.gates
  }, { requireDigestProvenance: false }));
  if (canonicalJson(rebuilt) !== canonicalJson(value)) invalid("report_binding_mismatch", "qualification report binding is invalid");
  return Object.freeze(value);
}

export async function writeP0BQualificationReport(outputFile, report) {
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile)) invalid("invalid_output_path", "qualification output path must be absolute");
  const bytes = serializeP0BQualificationReport(report);
  const directory = path.dirname(outputFile);
  const temporary = path.join(directory, `.${path.basename(outputFile)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let handle;
  try {
    handle = await fsp.open(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fsp.chmod(temporary, 0o600);
    await fsp.rename(temporary, outputFile);
    await fsp.chmod(outputFile, 0o600);
    try {
      const directoryHandle = await fsp.open(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
      try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    } catch {
      // Directory fsync is not available on every supported filesystem. The
      // file itself was fsynced before the atomic rename.
    }
  } catch (error) {
    await handle?.close().catch(() => {});
    await fsp.rm(temporary, { force: true }).catch(() => {});
    if (error instanceof QualificationReportError) throw error;
    throw new QualificationReportError("write_failed", "qualification report could not be written");
  }
}

export async function readP0BQualificationReport(inputFile) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)) invalid("invalid_input_path", "qualification input path must be absolute");
  let handle;
  try {
    handle = await fsp.open(inputFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = await handle.stat();
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid) || stat.size <= 0 || stat.size > MAX_REPORT_BYTES) invalid("unsafe_report_file", "qualification report file metadata is unsafe");
    const bytes = await handle.readFile();
    return parseP0BQualificationReport(bytes);
  } catch (error) {
    if (error instanceof QualificationReportError) throw error;
    throw new QualificationReportError("read_failed", "qualification report could not be read");
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function digestArtifactFile(inputFile, { name, kind = "artifact" } = {}) {
  if (typeof inputFile !== "string" || !path.isAbsolute(inputFile)) invalid("invalid_artifact_path", "artifact path must be absolute");
  const artifactName = stringValue(name ?? path.basename(inputFile), "artifact name", { maximum: 128, pattern: SAFE_NAME });
  const artifactKind = stringValue(kind, "artifact kind", { maximum: 64, pattern: SAFE_NAME });
  let handle;
  try {
    handle = await fsp.open(inputFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > MAX_ARTIFACT_BYTES) invalid("unsafe_artifact_file", "artifact file metadata is unsafe");
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const count = await handle.read(buffer, 0, buffer.length, null);
      if (count.bytesRead === 0) break;
      hash.update(buffer.subarray(0, count.bytesRead));
      bytes += count.bytesRead;
    }
    const after = await handle.stat();
    if (bytes !== stat.size || statIdentity(stat) !== statIdentity(after)) invalid("artifact_changed", "artifact changed while being read");
    const artifact = Object.freeze({ name: artifactName, kind: artifactKind, sha256: hash.digest("hex"), bytes });
    DIGESTED_ARTIFACTS.add(artifact);
    return artifact;
  } catch (error) {
    if (error instanceof QualificationReportError) throw error;
    throw new QualificationReportError("artifact_read_failed", "artifact could not be read");
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function resolveSourceCommit(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) invalid("invalid_repository_path", "repository path must be absolute");
  const result = spawnSync("git", ["-C", repositoryRoot, "rev-parse", "--verify", "HEAD"], { encoding: "utf8", shell: false, stdio: ["ignore", "pipe", "ignore"] });
  const commit = result.status === 0 ? result.stdout.trim() : "";
  if (!COMMIT.test(commit)) invalid("source_commit_unavailable", "source commit could not be resolved");
  return commit;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const [inputFile, outputFile] = process.argv.slice(2);
  if (!inputFile || !outputFile || !path.isAbsolute(inputFile) || !path.isAbsolute(outputFile)) {
    process.stderr.write("qualification_report_invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const input = JSON.parse(await fsp.readFile(inputFile, "utf8"));
      const report = buildP0BQualificationReport(input);
      await writeP0BQualificationReport(outputFile, report);
      process.stdout.write(`${report.report_digest}\n`);
      process.exitCode = report.overall.status === "passed" ? 0 : 1;
    } catch (error) {
      process.stderr.write(`${error instanceof QualificationReportError ? error.code : "qualification_report_failed"}\n`);
      process.exitCode = 1;
    }
  }
}
