#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { normalizeDeploymentEvidence, deploymentEvidenceSHA256 } from "./deployment-gate.mjs";

export const EVIDENCE_INDEX_SCHEMA_VERSION = 1;

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const JOB_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{1,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})Z$/u;
const MAX_REVIEW_VALIDITY_MS = 30 * 24 * 60 * 60 * 1_000;

const INDEX_KEYS = Object.freeze(["artifacts", "candidate", "reviewer", "rollback", "runs", "schema_version"]);
const CANDIDATE_KEYS = Object.freeze(["artifact_name", "artifact_sha256", "candidate_id", "release_manifest_sha256", "source_commit", "source_tree"]);
const RUNS_KEYS = Object.freeze(["ci", "qualification", "release", "staging"]);
const RUN_KEYS = Object.freeze(["job_id", "run_attempt", "run_id"]);
const ARTIFACT_KEYS = Object.freeze(["job_id", "name", "run_attempt", "run_id", "sha256"]);
const REVIEWER_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "evidence_sha256", "expires_at", "id", "report_sha256", "reviewed_at", "source_commit", "source_tree"]);
const ROLLBACK_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "completed_at", "current_revision", "deployment_id", "evidence_sha256", "job_id", "rollback_target_revision", "run_attempt", "run_id", "source_commit", "source_tree", "status", "tested"]);

export function verifyEvidenceIndex(value, {
  manifest,
  manifestSha256,
  artifactSha256,
  deploymentEvidence,
  releaseRun,
  releaseJobs,
  qualificationRun,
  qualificationJobs,
  ciRun,
  ciJobs,
  now = new Date()
} = {}) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new TypeError("release manifest is invalid");
  if (!DIGEST.test(manifestSha256 ?? "") || !DIGEST.test(artifactSha256 ?? "")) throw new TypeError("candidate digests are invalid");
  const product = Array.isArray(manifest.artifacts) ? manifest.artifacts.filter((item) => item?.role === "product") : [];
  const candidate = {
    artifact_name: product.length === 1 && typeof product[0].name === "string" ? product[0].name : null,
    artifact_sha256: artifactSha256,
    candidate_id: manifest.candidate_id,
    release_manifest_sha256: manifestSha256,
    source_commit: manifest.source?.commit,
    source_tree: manifest.source?.tree
  };
  if (candidate.artifact_name === null || !SHA.test(candidate.source_commit ?? "") || !SHA.test(candidate.source_tree ?? "")
    || !DIGEST.test(candidate.candidate_id?.replace("release-pkg-sha256-v1-", "") ?? "")
    || candidate.artifact_sha256 !== product[0].sha256
    || candidate.candidate_id !== `release-pkg-sha256-v1-${candidate.artifact_sha256}`) {
    throw new TypeError("release manifest candidate binding is invalid");
  }

  const evidence = normalizeDeploymentEvidence(deploymentEvidence);
  if (evidence.status !== "passed" || evidence.environment !== "staging"
    || evidence.source_commit !== candidate.source_commit || evidence.source_tree !== candidate.source_tree
    || evidence.artifact_sha256 !== candidate.artifact_sha256 || evidence.release_manifest_sha256 !== candidate.release_manifest_sha256) {
    throw new TypeError("staging deployment evidence is not bound to the candidate");
  }

  const expectedRuns = {
    release: assertSuccessfulRun(releaseRun, releaseJobs, "release", candidate.source_commit),
    qualification: assertSuccessfulRun(qualificationRun, qualificationJobs, "qualification", candidate.source_commit),
    ci: assertSuccessfulRun(ciRun, ciJobs, "ci", candidate.source_commit),
    staging: {
      run_id: evidence.run_id,
      run_attempt: evidence.run_attempt,
      job_id: evidence.job_id
    }
  };

  exactObject(value, INDEX_KEYS, "evidence index");
  if (value.schema_version !== EVIDENCE_INDEX_SCHEMA_VERSION) throw new TypeError("evidence index schema version is invalid");
  exactObject(value.candidate, CANDIDATE_KEYS, "evidence index candidate");
  for (const key of CANDIDATE_KEYS) if (value.candidate[key] !== candidate[key]) throw new TypeError("evidence index candidate binding is invalid");
  exactObject(value.runs, RUNS_KEYS, "evidence index runs");
  for (const key of RUNS_KEYS) {
    exactObject(value.runs[key], RUN_KEYS, `evidence index ${key} run`);
    if (value.runs[key].run_id !== expectedRuns[key].run_id || value.runs[key].run_attempt !== expectedRuns[key].run_attempt) throw new TypeError(`evidence index ${key} run binding is invalid`);
    if (key === "staging") {
      if (value.runs[key].job_id !== expectedRuns[key].job_id) throw new TypeError("evidence index staging run binding is invalid");
    } else if (!expectedRuns[key].jobs.some((job) => String(job.id) === value.runs[key].job_id)) {
      throw new TypeError(`evidence index ${key} job binding is invalid`);
    }
  }

  if (!Array.isArray(value.artifacts) || value.artifacts.length !== 1) throw new TypeError("evidence index artifact inventory is invalid");
  exactObject(value.artifacts[0], ARTIFACT_KEYS, "evidence index artifact");
  const artifact = value.artifacts[0];
  if (artifact.name !== candidate.artifact_name || artifact.sha256 !== candidate.artifact_sha256
    || artifact.run_id !== expectedRuns.release.run_id || artifact.run_attempt !== expectedRuns.release.run_attempt) {
    throw new TypeError("evidence index candidate artifact binding is invalid");
  }
  const candidateJob = successfulJobs(releaseJobs).filter((job) => job.name === "signed-candidate");
  if (candidateJob.length !== 1 || artifact.job_id !== String(candidateJob[0].id)) throw new TypeError("evidence index candidate artifact job binding is invalid");

  exactObject(value.reviewer, REVIEWER_KEYS, "evidence index reviewer");
  if (!IDENTIFIER.test(value.reviewer.id) || !DIGEST.test(value.reviewer.report_sha256)
    || value.reviewer.candidate_id !== candidate.candidate_id || value.reviewer.source_commit !== candidate.source_commit
    || value.reviewer.source_tree !== candidate.source_tree || value.reviewer.artifact_sha256 !== candidate.artifact_sha256
    || value.reviewer.evidence_sha256 !== deploymentEvidenceSHA256(evidence)
    || !validTimestamp(value.reviewer.reviewed_at) || !validTimestamp(value.reviewer.expires_at)) {
    throw new TypeError("evidence index reviewer binding is invalid");
  }
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  const reviewedAtMs = Date.parse(value.reviewer.reviewed_at);
  const expiresAtMs = Date.parse(value.reviewer.expires_at);
  if (!Number.isFinite(nowMs) || reviewedAtMs > nowMs || expiresAtMs <= nowMs || expiresAtMs <= reviewedAtMs || expiresAtMs - reviewedAtMs > MAX_REVIEW_VALIDITY_MS) {
    throw new TypeError("evidence index reviewer expiry is invalid");
  }

  exactObject(value.rollback, ROLLBACK_KEYS, "evidence index rollback");
  const expectedRollback = evidence.rollback;
  if (value.rollback.artifact_sha256 !== candidate.artifact_sha256 || value.rollback.candidate_id !== candidate.candidate_id
    || value.rollback.source_commit !== candidate.source_commit || value.rollback.source_tree !== candidate.source_tree
    || value.rollback.completed_at !== expectedRollback.completed_at || value.rollback.current_revision !== expectedRollback.current_revision
    || value.rollback.deployment_id !== expectedRollback.deployment_id || value.rollback.rollback_target_revision !== expectedRollback.rollback_target_revision
    || value.rollback.evidence_sha256 !== deploymentEvidenceSHA256(evidence) || value.rollback.run_id !== expectedRollback.run_id
    || value.rollback.run_attempt !== evidence.run_attempt || value.rollback.job_id !== evidence.job_id
    || value.rollback.status !== "passed" || value.rollback.tested !== true) {
    throw new TypeError("evidence index rollback binding is invalid");
  }
  if (!validTimestamp(value.rollback.completed_at)) throw new TypeError("evidence index rollback timestamp is invalid");
  return Object.freeze({
    schema_version: EVIDENCE_INDEX_SCHEMA_VERSION,
    artifacts: Object.freeze([Object.freeze({ ...artifact })]),
    candidate: Object.freeze({ ...value.candidate }),
    reviewer: Object.freeze({ ...value.reviewer }),
    rollback: Object.freeze({ ...value.rollback }),
    runs: Object.freeze(Object.fromEntries(RUNS_KEYS.map((key) => [key, Object.freeze({ ...value.runs[key] })])))
  });
}

export function evidenceIndexSHA256(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function assertSuccessfulRun(run, jobs, label, expectedSha) {
  if (!run || typeof run !== "object" || Array.isArray(run) || !RUN_ID.test(String(run.id ?? ""))
    || run.status !== "completed" || run.conclusion !== "success" || run.head_sha !== expectedSha
    || !RUN_ID.test(String(run.run_attempt ?? ""))) throw new TypeError(`${label} run is not successful and source-bound`);
  const matches = successfulJobs(jobs).filter((job) => String(job.run_id) === String(run.id) && job.head_sha === expectedSha);
  if (matches.length === 0) throw new TypeError(`${label} run has no source-bound successful job`);
  return { run_id: String(run.id), run_attempt: String(run.run_attempt), jobs: matches };
}

function successfulJobs(value) {
  if (!value || !Array.isArray(value.jobs) || value.total_count !== value.jobs.length) throw new TypeError("run jobs response is incomplete");
  return value.jobs.filter((job) => job && job.status === "completed" && job.conclusion === "success" && JOB_ID.test(String(job.id ?? "")));
}

function validTimestamp(value) {
  return typeof value === "string" && TIMESTAMP.test(value) && new Date(value).toISOString() === value;
}

function exactObject(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError(`${label} is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new TypeError(`${label} fields are invalid`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new TypeError(`${label} property is not a data property`);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [command, indexPath, manifestPath, artifactPath, deploymentEvidencePath, releaseRunPath, releaseJobsPath, qualificationRunPath, qualificationJobsPath, ciRunPath, ciJobsPath] = process.argv.slice(2);
  if (command !== "verify" || process.argv.length !== 13) throw new Error("Usage: evidence-index.mjs verify INDEX.json MANIFEST.json ARTIFACT.pkg DEPLOYMENT-EVIDENCE.json RELEASE-RUN.json RELEASE-JOBS.json QUALIFICATION-RUN.json QUALIFICATION-JOBS.json CI-RUN.json CI-JOBS.json");
  const manifestBytes = fs.readFileSync(manifestPath);
  const artifactBytes = fs.readFileSync(artifactPath);
  const normalized = verifyEvidenceIndex(readJson(indexPath), {
    manifest: JSON.parse(manifestBytes),
    manifestSha256: crypto.createHash("sha256").update(manifestBytes).digest("hex"),
    artifactSha256: crypto.createHash("sha256").update(artifactBytes).digest("hex"),
    deploymentEvidence: readJson(deploymentEvidencePath),
    releaseRun: readJson(releaseRunPath),
    releaseJobs: readJson(releaseJobsPath),
    qualificationRun: readJson(qualificationRunPath),
    qualificationJobs: readJson(qualificationJobsPath),
    ciRun: readJson(ciRunPath),
    ciJobs: readJson(ciJobsPath)
  });
  process.stdout.write(`${canonicalJson(normalized)}\n`);
}
