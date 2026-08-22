#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { EXTERNAL_QUALIFICATION_GATES } from "./ci-preflight.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;

export class ArtifactProvenanceError extends Error {
  constructor(message) {
    super(message);
    this.name = "ArtifactProvenanceError";
  }
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ArtifactProvenanceError(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ArtifactProvenanceError(`${label} has unknown or missing fields`);
}

function regularFile(file, label) {
  const resolved = path.resolve(file);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0) throw new ArtifactProvenanceError(`${label} is not a protected regular file`);
  return { resolved, bytes: fs.readFileSync(resolved) };
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function requireSha(value, label) {
  if (typeof value !== "string" || !SHA.test(value)) throw new ArtifactProvenanceError(`${label} must be an exact source SHA`);
  return value;
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new ArtifactProvenanceError(`${label} must be a SHA-256 digest`);
  return value;
}

function requireRunId(value, label) {
  if (!RUN_ID.test(String(value ?? ""))) throw new ArtifactProvenanceError(`${label} must be a GitHub ID`);
  return String(value);
}

/**
 * GitHub's artifact API exposes the digest of the uploaded archive. The
 * actions/download-artifact action expands that archive and therefore does
 * not expose the archive bytes to the caller. Callers must download the
 * archive through the artifact API into `archivePath` and compare the digest
 * before trusting the expanded directory.
 */
export function verifyGithubArtifactArchive({ metadata, archivePath, expectedName, expectedRunId, expectedSourceCommit, expectedSourceTree } = {}) {
  exactKeys(metadata, ["artifact_id", "name", "digest", "run_id", "run_attempt", "head_sha", "source_tree"], "GitHub artifact metadata");
  if (typeof metadata.name !== "string" || metadata.name.length === 0 || (expectedName !== undefined && metadata.name !== expectedName)) throw new ArtifactProvenanceError("GitHub artifact name is mismatched");
  if (!ARTIFACT_DIGEST.test(metadata.digest)) throw new ArtifactProvenanceError("GitHub artifact archive digest is invalid");
  requireRunId(metadata.artifact_id, "GitHub artifact ID");
  requireRunId(metadata.run_id, "GitHub artifact run ID");
  requireRunId(metadata.run_attempt, "GitHub artifact run attempt");
  requireSha(metadata.head_sha, "GitHub artifact source commit");
  requireSha(metadata.source_tree, "GitHub artifact source tree");
  if (expectedRunId !== undefined && metadata.run_id !== requireRunId(expectedRunId, "expected GitHub artifact run ID")) throw new ArtifactProvenanceError("GitHub artifact run binding is mismatched");
  if (expectedSourceCommit !== undefined && metadata.head_sha !== requireSha(expectedSourceCommit, "expected source commit")) throw new ArtifactProvenanceError("GitHub artifact source commit is mismatched");
  if (expectedSourceTree !== undefined && metadata.source_tree !== requireSha(expectedSourceTree, "expected source tree")) throw new ArtifactProvenanceError("GitHub artifact source tree is mismatched");
  const archive = regularFile(archivePath, "GitHub artifact archive");
  const archiveSha256 = sha256(archive.bytes);
  if (`sha256:${archiveSha256}` !== metadata.digest) throw new ArtifactProvenanceError(`GitHub artifact archive digest mismatch for ${metadata.name}`);
  return Object.freeze({
    artifact_id: metadata.artifact_id,
    name: metadata.name,
    run_id: metadata.run_id,
    run_attempt: metadata.run_attempt,
    source_commit: metadata.head_sha,
    source_tree: metadata.source_tree,
    archive_sha256: archiveSha256,
    archive_bytes: archive.bytes.length
  });
}

function childKey(gate, checkId) {
  return `${gate}:${checkId}`;
}

function normalizeChildEvidence(value, { expectedSourceCommit, expectedSourceTree, expectedReleaseArtifactSha256 } = {}) {
  exactKeys(value, ["schema_version", "kind", "source_commit", "source_tree", "artifact_sha256", "children"], "child evidence bundle");
  if (value.schema_version !== 1 || value.kind !== "agentpass-external-qualification-child-evidence") throw new ArtifactProvenanceError("child evidence bundle kind/version is invalid");
  requireSha(value.source_commit, "child evidence bundle source commit");
  requireSha(value.source_tree, "child evidence bundle source tree");
  requireDigest(value.artifact_sha256, "child evidence bundle release artifact");
  if (value.source_commit !== expectedSourceCommit || value.source_tree !== expectedSourceTree || value.artifact_sha256 !== expectedReleaseArtifactSha256) throw new ArtifactProvenanceError("child evidence bundle is not bound to the selected source/tree/artifact");
  if (!Array.isArray(value.children)) throw new ArtifactProvenanceError("child evidence bundle children must be an array");
  return value;
}

/**
 * Recompute every aggregate check digest from the exact redacted child
 * evidence object supplied by the protected qualification handoff. A digest
 * string in the aggregate alone is never treated as evidence.
 */
export function verifyExternalChildEvidence({ aggregate, childEvidence, expectedSourceCommit, expectedSourceTree, expectedReleaseArtifactSha256 } = {}) {
  const bundle = normalizeChildEvidence(childEvidence, { expectedSourceCommit, expectedSourceTree, expectedReleaseArtifactSha256 });
  if (!aggregate || typeof aggregate !== "object" || Array.isArray(aggregate) || !aggregate.gates) throw new ArtifactProvenanceError("external qualification aggregate is invalid");
  const expected = new Map();
  for (const [gateName, contract] of Object.entries(EXTERNAL_QUALIFICATION_GATES)) {
    const gate = aggregate.gates[gateName];
    if (!gate || gate.status === "not_run") continue;
    for (const checkId of contract.required_checks) {
      const check = Array.isArray(gate.checks) ? gate.checks.find((item) => item?.check_id === checkId) : undefined;
      if (!check) throw new ArtifactProvenanceError(`aggregate is missing child-bound check ${gateName}:${checkId}`);
      expected.set(childKey(gateName, checkId), check);
    }
  }
  const seen = new Set();
  for (const [index, child] of bundle.children.entries()) {
    exactKeys(child, ["gate", "check_id", "source_commit", "source_tree", "artifact_sha256", "run_id", "run_attempt", "job_id", "evidence"], `child evidence ${index}`);
    if (typeof child.gate !== "string" || !Object.hasOwn(EXTERNAL_QUALIFICATION_GATES, child.gate)) throw new ArtifactProvenanceError(`child evidence ${index} has an unknown gate`);
    const contract = EXTERNAL_QUALIFICATION_GATES[child.gate];
    if (!contract.required_checks.includes(child.check_id)) throw new ArtifactProvenanceError(`child evidence ${index} has an unknown check`);
    const key = childKey(child.gate, child.check_id);
    if (seen.has(key)) throw new ArtifactProvenanceError(`child evidence is duplicated: ${key}`);
    seen.add(key);
    const check = expected.get(key);
    if (!check) throw new ArtifactProvenanceError(`child evidence is not referenced by the aggregate: ${key}`);
    if (child.source_commit !== expectedSourceCommit || child.source_tree !== expectedSourceTree || child.artifact_sha256 !== expectedReleaseArtifactSha256) throw new ArtifactProvenanceError(`child evidence source/artifact binding is invalid: ${key}`);
    requireRunId(child.run_id, `${key} run ID`);
    requireRunId(child.run_attempt, `${key} run attempt`);
    requireRunId(child.job_id, `${key} job ID`);
    const execution = aggregate.gates[child.gate]?.execution;
    if (!execution || child.run_id !== execution.run_id || child.run_attempt !== execution.run_attempt || child.job_id !== execution.job_id) {
      throw new ArtifactProvenanceError(`child evidence execution binding is mismatched: ${key}`);
    }
    const computed = sha256(Buffer.from(canonicalJson(child.evidence), "utf8"));
    if (check.evidence_sha256 !== computed) throw new ArtifactProvenanceError(`child evidence digest mismatch: ${key}`);
  }
  if (seen.size !== expected.size || [...expected.keys()].some((key) => !seen.has(key))) throw new ArtifactProvenanceError("child evidence inventory is incomplete");
  return Object.freeze({ status: "passed", children: seen.size, source_commit: expectedSourceCommit, source_tree: expectedSourceTree, artifact_sha256: expectedReleaseArtifactSha256 });
}

function readJson(file) {
  const { bytes } = regularFile(file, "JSON input");
  try { return JSON.parse(bytes.toString("utf8")); } catch { throw new ArtifactProvenanceError(`JSON input is invalid: ${file}`); }
}

function usage() {
  return [
    "usage:",
    "  artifact-provenance.mjs archive <metadata.json> <archive.zip> <expected-name> <expected-run-id> <expected-source-commit> <expected-source-tree>",
    "  artifact-provenance.mjs children <aggregate.json> <children.json> <expected-source-commit> <expected-source-tree> <expected-release-artifact-sha256>"
  ].join("\\n");
}

export function runCli(argv = process.argv.slice(2)) {
  const [command, ...args] = argv;
  if (command === "archive" && args.length === 6) return verifyGithubArtifactArchive({ metadata: readJson(args[0]), archivePath: args[1], expectedName: args[2], expectedRunId: args[3], expectedSourceCommit: args[4], expectedSourceTree: args[5] });
  if (command === "children" && args.length === 5) return verifyExternalChildEvidence({ aggregate: readJson(args[0]), childEvidence: readJson(args[1]), expectedSourceCommit: args[2], expectedSourceTree: args[3], expectedReleaseArtifactSha256: args[4] });
  throw new ArtifactProvenanceError(usage());
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
