#!/usr/bin/env node

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { verifyCloudSignerKmsQualificationEvidence } from "../../qualification/cloud-signer-kms.mjs";
import { verifyPlatformAuthQualificationEvidence } from "../../qualification/platform-auth.mjs";
import { verifyPostgresExternalQualificationEvidence } from "../../qualification/run-postgres-c3-external.mjs";
import { verifyPostgresGateEvidence } from "../../qualification/aggregate-postgres-external.mjs";
import { validateWebAuthnEvidence } from "../../qualification/run-webauthn-e2e.mjs";
import { verifyGithubArtifactArchive } from "../artifact-provenance.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ID = /^[1-9][0-9]{0,19}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const CURRENT_JOB = "external-qualification-provenance";
const JOB_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/u;
const ZIP_MEMBER = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\.json$/u;
const NON_JSON_MEMBER = "input/children.bundle";
const EXTERNAL_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DISALLOWED_EXTERNAL_IDENTITY = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest|unknown|unidentified|unspecified|placeholder|redacted|n\/a|none|null)($|[._:/ -])/iu;

export const EXTERNAL_QUALIFICATION_ARTIFACTS = Object.freeze([
  Object.freeze({ job: "kms", prefix: "external-kms-qualification" }),
  Object.freeze({ job: "platform-auth", prefix: "external-platform-auth-qualification" }),
  Object.freeze({ job: "webauthn", prefix: "external-webauthn-qualification" }),
  Object.freeze({ job: "postgres-authority-16", prefix: "external-postgres-16-qualification" }),
  Object.freeze({ job: "postgres-authority-17", prefix: "external-postgres-17-qualification" }),
  Object.freeze({ job: "postgres-gate", prefix: "external-postgres-gate" })
]);

export class ExternalArtifactProvenanceError extends Error {
  constructor(message) {
    super(message);
    this.name = "ExternalArtifactProvenanceError";
  }
}

function fail(message) {
  throw new ExternalArtifactProvenanceError(message);
}

function requirePattern(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} is invalid`);
  return value;
}

function requireId(value, label) {
  return requirePattern(String(value), ID, label);
}

function exactRun(run, { repository, sourceCommit, runId, runAttempt } = {}) {
  if (!run || typeof run !== "object" || Array.isArray(run)) fail("external qualification workflow run is invalid");
  requireId(run.id, "external qualification workflow run ID");
  requireId(run.run_attempt, "external qualification workflow run attempt");
  if (String(run.id) !== runId || String(run.run_attempt) !== runAttempt) fail("external qualification workflow run ID or attempt is mismatched");
  if (run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) fail("external qualification workflow run repository is not canonical");
  requireId(run.repository?.id, "external qualification repository ID");
  requireId(run.head_repository?.id, "external qualification head repository ID");
  if (run.name !== "External qualification runners"
    || run.path !== ".github/workflows/external-qualification-runners.yml"
    || run.event !== "workflow_dispatch"
    || run.head_branch !== "main"
    || run.status !== "completed"
    || run.conclusion !== "success"
    || run.head_sha !== sourceCommit) {
    fail("external qualification workflow run identity or terminal state is mismatched");
  }
  return Object.freeze({ run_id: runId, run_attempt: runAttempt, source_commit: sourceCommit });
}

function exactCanonicalRun(run, { repository, sourceCommit, runId, runAttempt } = {}) {
  if (!run || typeof run !== "object" || Array.isArray(run)) fail("canonical CI workflow run is invalid");
  requireId(run.id, "canonical CI workflow run ID");
  requireId(run.run_attempt, "canonical CI workflow run attempt");
  if (String(run.id) !== runId || String(run.run_attempt) !== runAttempt) fail("canonical CI workflow run ID or attempt is mismatched");
  if (run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) fail("canonical CI workflow run repository is not canonical");
  requireId(run.repository?.id, "canonical CI repository ID");
  requireId(run.head_repository?.id, "canonical CI head repository ID");
  if (run.name !== "CI"
    || run.path !== ".github/workflows/ci.yml"
    || run.event !== "push"
    || run.head_branch !== "main"
    || run.status !== "completed"
    || run.conclusion !== "success"
    || run.head_sha !== sourceCommit) {
    fail("canonical CI workflow run identity or terminal state is mismatched");
  }
  return Object.freeze({ run_id: runId, run_attempt: runAttempt, source_commit: sourceCommit });
}

function exactJobs(envelope, { sourceCommit, runId, runAttempt } = {}) {
  if (!envelope || typeof envelope !== "object" || !Array.isArray(envelope.jobs)) fail("external qualification jobs response is invalid");
  const expected = new Set(["validate", ...EXTERNAL_QUALIFICATION_ARTIFACTS.map(({ job }) => job), CURRENT_JOB]);
  if (!Number.isSafeInteger(envelope.total_count) || envelope.total_count !== envelope.jobs.length || envelope.jobs.length !== expected.size) fail("external qualification job inventory is incomplete or paginated");
  const names = new Set();
  const ids = new Set();
  const byName = new Map();
  for (const [index, job] of envelope.jobs.entries()) {
    if (!job || typeof job !== "object" || Array.isArray(job)) fail(`external qualification job ${index} is invalid`);
    const id = requireId(job.id, `external qualification job ${index} ID`);
    const name = requirePattern(job.name, JOB_NAME, `external qualification job ${index} name`);
    if (ids.has(id) || names.has(name) || !expected.has(name)) fail("external qualification job inventory contains an unexpected or duplicate job");
    ids.add(id);
    names.add(name);
    if (String(job.run_id) !== runId || String(job.run_attempt) !== runAttempt || job.head_sha !== sourceCommit) fail(`external qualification job is not bound to the selected run: ${name}`);
    if (job.workflow_name !== undefined && job.workflow_name !== "External qualification runners") fail(`external qualification job workflow is mismatched: ${name}`);
    if (name === CURRENT_JOB) {
      if (!["queued", "in_progress"].includes(job.status)) fail("external qualification provenance job must still be running while it verifies artifacts");
    } else if (job.status !== "completed" || job.conclusion !== "success") {
      fail(`external qualification dependency is not successful: ${name}`);
    }
    byName.set(name, Object.freeze({ job_id: id, name }));
  }
  if (names.size !== expected.size || [...expected].some((name) => !names.has(name))) fail("external qualification job inventory is missing a required job");
  return Object.freeze(Object.fromEntries([...byName.entries()]));
}

function expectedArtifactName(prefix, sourceCommit, runId, runAttempt) {
  return `${prefix}-${sourceCommit}-${runId}-${runAttempt}`;
}

function readArchiveJsonMembers(archivePath) {
  let listing;
  try {
    listing = execFileSync("unzip", ["-Z1", archivePath], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    fail(`external qualification archive is not a readable ZIP: ${archivePath}`);
  }
  const members = listing.split("\n").filter(Boolean);
  const seen = new Set();
  const jsonMembers = [];
  for (const member of members) {
    if (member.endsWith("/")) continue;
    if ((!ZIP_MEMBER.test(member) && member !== NON_JSON_MEMBER) || member.startsWith("/") || member.includes("..") || member.includes("\\")) fail(`external qualification archive contains an unsafe member: ${member}`);
    if (seen.has(member)) fail(`external qualification archive contains a duplicate member: ${member}`);
    seen.add(member);
    if (ZIP_MEMBER.test(member)) jsonMembers.push(member);
  }
  if (jsonMembers.length === 0) fail(`external qualification archive contains no JSON evidence: ${archivePath}`);
  return jsonMembers.map((member) => {
    const bytes = readArchiveMember(archivePath, member);
    try {
      return Object.freeze({ member, value: JSON.parse(bytes.toString("utf8")) });
    } catch {
      fail(`external qualification archive evidence is not valid JSON: ${member}`);
    }
  });
}

function readArchiveMember(archivePath, member) {
  try {
    return execFileSync("unzip", ["-p", archivePath, member], { encoding: null, maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    fail(`external qualification archive member could not be read: ${member}`);
  }
}

export function validateExternalExecutionBoundary(value, { label = "external qualification evidence" } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is invalid`);
  const execution = value.execution;
  if (!execution || typeof execution !== "object" || Array.isArray(execution)) fail(`${label} execution identity is missing`);
  const legacyKmsExecution = execution.environment === "managed_kms"
    && execution.kind === undefined
    && typeof execution.credential_mode === "string";
  if ((!legacyKmsExecution && execution.kind !== "external_runner") || execution.real_execution !== true) fail(`${label} execution is not a real external run`);
  if (typeof execution.runner_id !== "string" || !EXTERNAL_IDENTIFIER.test(execution.runner_id) || DISALLOWED_EXTERNAL_IDENTITY.test(execution.runner_id)) {
    fail(`${label} runner identity is local, unknown, or invalid`);
  }
  const environmentIdentity = typeof execution.environment === "string"
    ? execution.environment
    : execution.environment?.identity;
  if (typeof environmentIdentity !== "string"
    || !EXTERNAL_IDENTIFIER.test(environmentIdentity)
    || DISALLOWED_EXTERNAL_IDENTITY.test(environmentIdentity)) {
    fail(`${label} environment identity is missing, local, or unknown`);
  }
  return Object.freeze({ runner_id: execution.runner_id, environment_identity: environmentIdentity });
}

function verifyExecutionBinding(value, { member, expectedJobId, expectedJobName, sourceCommit, sourceTree, releaseArtifactSha256, qualificationRunId, qualificationRunAttempt, canonicalRunId, canonicalRunAttempt } = {}) {
  const identity = validateExternalExecutionBoundary(value, { label: member });
  const execution = value.execution;
  const expected = {
    run_id: String(qualificationRunId), run_attempt: String(qualificationRunAttempt), job_id: String(expectedJobId),
    source_commit: sourceCommit, source_tree: sourceTree, ci_run_id: String(canonicalRunId), ci_run_attempt: String(canonicalRunAttempt)
  };
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (execution[key] !== undefined && String(execution[key]) !== expectedValue) fail(`${member} execution ${key} binding is mismatched`);
  }
  for (const [key, expectedValue] of [["qualification_run_id", expected.run_id], ["qualification_run_attempt", expected.run_attempt], ["qualification_job_id", expected.job_id]]) {
    if (execution[key] !== undefined && String(execution[key]) !== expectedValue) fail(`${member} execution ${key} binding is mismatched`);
  }
  if (expectedJobName === "postgres-gate") {
    if (execution.release_artifact_sha256 !== releaseArtifactSha256 || !/^[0-9a-f]{64}$/u.test(execution.artifact_sha256 ?? "")) fail(`${member} aggregate artifact identity is invalid`);
  } else if (value.artifact_sha256 !== undefined && value.artifact_sha256 !== releaseArtifactSha256) {
    fail(`${member} evidence artifact binding is mismatched`);
  }
  return Object.freeze({
    runner_id: identity.runner_id,
    environment_identity: identity.environment_identity,
    run_id: String(qualificationRunId),
    run_attempt: String(qualificationRunAttempt),
    job_id: String(expectedJobId),
    source_commit: sourceCommit,
    source_tree: sourceTree,
    artifact_sha256: releaseArtifactSha256,
    job_name: expectedJobName
  });
}

function verifyPostgresArchiveSemantics(value, archivePath, { jobName, repository, sourceCommit, sourceTree, releaseArtifactSha256, canonicalRunId, canonicalRunAttempt, qualificationRunId, qualificationRunAttempt, expectedJobId } = {}) {
  if (jobName === "platform-auth") {
    try {
      const result = verifyPlatformAuthQualificationEvidence(value, {
        expectedSourceCommit: sourceCommit,
        expectedSourceTree: sourceTree,
        expectedRunId: qualificationRunId,
        expectedJobId: expectedJobId,
        expectedRunAttempt: qualificationRunAttempt,
        expectedCiRunId: canonicalRunId,
        expectedCiRunAttempt: canonicalRunAttempt,
        requireExternalExecution: true
      });
      if (result.status !== "passed" || result.qualified !== true) fail("external Platform Auth qualification is not a passing result");
    } catch (error) {
      if (error instanceof ExternalArtifactProvenanceError) throw error;
      fail(`external Platform Auth qualification evidence is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    return;
  }
  if (jobName === "postgres-authority-16" || jobName === "postgres-authority-17") {
    verifyPostgresExternalQualificationEvidence(value, {
      source_commit: sourceCommit,
      source_tree: sourceTree,
      artifact_sha256: releaseArtifactSha256,
      run_id: qualificationRunId,
      run_attempt: qualificationRunAttempt,
      ci_run_id: canonicalRunId,
      ci_run_attempt: canonicalRunAttempt,
      qualification_run_id: qualificationRunId,
      qualification_run_attempt: qualificationRunAttempt,
      qualification_job_id: expectedJobId,
      job_id: expectedJobId,
      postgres_major: jobName.endsWith("16") ? "16" : "17"
    });
    return;
  }
  if (jobName === "postgres-gate") {
    verifyPostgresGateEvidence(value, {
      sourceCommit,
      sourceTree,
      releaseArtifactSha256,
      runId: qualificationRunId,
      runAttempt: qualificationRunAttempt,
      jobId: expectedJobId,
      ciRunId: canonicalRunId,
      ciRunAttempt: canonicalRunAttempt,
      qualificationJobName: jobName,
      requireControllerBinding: true
    });
    const bundle = readArchiveMember(archivePath, NON_JSON_MEMBER);
    if (crypto.createHash("sha256").update(bundle).digest("hex") !== value.execution.artifact_sha256) fail("external PostgreSQL aggregate child bundle digest is mismatched");
    return;
  }
  if (jobName === "kms") {
    try {
      const result = verifyCloudSignerKmsQualificationEvidence(value, {
        expectedSourceCommit: sourceCommit,
        expectedSourceTree: sourceTree,
        expectedArtifactSha256: releaseArtifactSha256,
        expectedRunId: qualificationRunId,
        expectedJobId: expectedJobId,
        requireProviderIdentityAttestation: true
      });
      if (result.status !== "passed" || result.qualified !== true) fail("external KMS qualification is not a passing result");
    } catch (error) {
      if (error instanceof ExternalArtifactProvenanceError) throw error;
      fail(`external KMS qualification evidence is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    return;
  }
  if (jobName === "webauthn") {
    try {
      const result = validateWebAuthnEvidence(value, {
        AGENTPASS_QUALIFICATION_RUNNER_ID: requirePattern(String(value.execution?.runner_id ?? ""), /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u, "WebAuthn runner ID"),
        AGENTPASS_QUALIFICATION_RUN_ID: qualificationRunId,
        AGENTPASS_QUALIFICATION_JOB_ID: expectedJobId,
        AGENTPASS_QUALIFICATION_RUN_ATTEMPT: qualificationRunAttempt,
        GITHUB_SHA: sourceCommit,
        AGENTPASS_SOURCE_TREE: sourceTree,
        AGENTPASS_QUALIFICATION_ARTIFACT_SHA256: releaseArtifactSha256
      });
      if (result.status !== "passed" || result.qualified !== true) fail("external WebAuthn qualification is not a passing result");
    } catch (error) {
      if (error instanceof ExternalArtifactProvenanceError) throw error;
      fail(`external WebAuthn qualification evidence is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

function verifyArchiveEvidence(archivePath, { repository, sourceCommit, sourceTree, releaseArtifactSha256, canonicalRunId, canonicalRunAttempt, qualificationRunId: expectedQualificationRunId, qualificationRunAttempt: expectedQualificationRunAttempt, expectedJobId, expectedJobName } = {}) {
  const members = readArchiveJsonMembers(archivePath);
  const identities = [];
  for (const { member, value } of members) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(`external qualification evidence is not an object: ${member}`);
    // Some qualification runners wrap their execution binding under `execution`.
    // Normalize that envelope before checking the cross-run binding, without
    // allowing the archive member to provide two conflicting copies.
    const nested = value.execution && typeof value.execution === "object" && !Array.isArray(value.execution)
      ? value.execution
      : null;
    const bindingKeys = ["repository", "source_commit", "source_tree", "artifact_sha256", "run_id", "run_attempt", "job_id", "ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id", "qualification_job_name"];
    for (const key of bindingKeys) {
      if (nested?.[key] !== undefined && value[key] !== undefined
        && String(nested[key]) !== String(value[key])) {
        fail(`external qualification evidence has conflicting ${key} bindings: ${member}`);
      }
    }
    const envelope = nested
      ? { ...value, ...Object.fromEntries(Object.entries(nested).filter(([, nestedValue]) => nestedValue !== undefined)) }
      : value;
    const qualificationRunId = requireId(envelope.qualification_run_id, `${member} qualification run ID`);
    const qualificationRunAttempt = requireId(envelope.qualification_run_attempt, `${member} qualification run attempt`);
    const qualificationJobId = requireId(envelope.qualification_job_id, `${member} qualification job ID`);
    const qualificationJobName = envelope.qualification_job_name === undefined
      ? expectedJobName
      : requirePattern(envelope.qualification_job_name, JOB_NAME, `${member} qualification job name`);
    const ciRunId = requireId(envelope.ci_run_id, `${member} canonical CI run ID`);
    const ciRunAttempt = requireId(envelope.ci_run_attempt, `${member} canonical CI run attempt`);
    if (qualificationRunId !== String(expectedQualificationRunId) || qualificationRunAttempt !== String(expectedQualificationRunAttempt)
      || qualificationJobId !== String(expectedJobId) || qualificationJobName !== expectedJobName) {
      fail(`external qualification evidence qualification job binding is mismatched: ${member}`);
    }
    if (ciRunId !== String(canonicalRunId) || ciRunAttempt !== String(canonicalRunAttempt)) {
      fail(`external qualification evidence canonical CI run binding is mismatched: ${member}`);
    }
    if (envelope.repository !== undefined && envelope.repository !== repository) fail(`external qualification evidence repository is mismatched: ${member}`);
    if (envelope.source_commit !== sourceCommit) fail(`external qualification evidence source commit is mismatched: ${member}`);
    if (envelope.source_tree !== sourceTree) fail(`external qualification evidence source tree is mismatched: ${member}`);
    verifyPostgresArchiveSemantics(value, archivePath, {
      jobName: expectedJobName,
      repository,
      sourceCommit,
      sourceTree,
      releaseArtifactSha256,
      canonicalRunId,
      canonicalRunAttempt,
      qualificationRunId,
      qualificationRunAttempt,
      expectedJobId
    });
    const identity = verifyExecutionBinding(value, {
      member,
      expectedJobId,
      expectedJobName,
      sourceCommit,
      sourceTree,
      releaseArtifactSha256,
      qualificationRunId,
      qualificationRunAttempt,
      canonicalRunId,
      canonicalRunAttempt
    });
    identities.push(identity);
  }
  return Object.freeze({ members: members.map(({ member }) => member), identities });
}

function verifyArtifactList(envelope, { repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory, jobBindings } = {}) {
  if (!envelope || typeof envelope !== "object" || !Array.isArray(envelope.artifacts)) fail("external qualification artifacts response is invalid");
  if (!Number.isSafeInteger(envelope.total_count) || envelope.total_count !== envelope.artifacts.length || envelope.artifacts.length !== EXTERNAL_QUALIFICATION_ARTIFACTS.length) fail("external qualification artifact inventory is incomplete or paginated");
  const seen = new Set();
  const artifacts = [];
  const executionIdentities = [];
  for (const descriptor of EXTERNAL_QUALIFICATION_ARTIFACTS) {
    const name = expectedArtifactName(descriptor.prefix, sourceCommit, runId, runAttempt);
    const matches = envelope.artifacts.filter((artifact) => artifact?.name === name);
    if (matches.length !== 1) fail(`external qualification artifact is missing or duplicated: ${name}`);
    const artifact = matches[0];
    const expectedJob = jobBindings[descriptor.job];
    if (!expectedJob) fail(`external qualification job binding is missing: ${descriptor.job}`);
    const artifactId = requireId(artifact.id, `${name} artifact ID`);
    if (seen.has(artifactId) || artifact.expired !== false || !DIGEST.test(artifact.digest)) fail(`external qualification artifact is expired, duplicated, or has no digest: ${name}`);
    seen.add(artifactId);
    if (String(artifact.workflow_run?.id) !== runId) fail(`external qualification artifact run binding is mismatched: ${name}`);
    if (artifact.workflow_run?.head_sha !== undefined && artifact.workflow_run.head_sha !== sourceCommit) fail(`external qualification artifact source binding is mismatched: ${name}`);
    if (artifact.workflow_run?.run_attempt !== undefined && String(artifact.workflow_run.run_attempt) !== runAttempt) fail(`external qualification artifact attempt binding is mismatched: ${name}`);
    const archivePath = path.join(path.resolve(archiveDirectory), `${name}.zip`);
    const verified = verifyGithubArtifactArchive({
      metadata: {
        artifact_id: artifactId,
        name,
        digest: artifact.digest,
        run_id: runId,
        run_attempt: runAttempt,
        head_sha: sourceCommit,
        source_tree: sourceTree
      },
      archivePath,
      expectedName: name,
      expectedRunId: runId,
      expectedSourceCommit: sourceCommit,
      expectedSourceTree: sourceTree
    });
    const evidence = verifyArchiveEvidence(archivePath, {
      repository,
      sourceCommit,
      sourceTree,
      releaseArtifactSha256,
      qualificationRunId: runId,
      qualificationRunAttempt: runAttempt,
      canonicalRunId,
      canonicalRunAttempt,
      expectedJobId: expectedJob.job_id,
      expectedJobName: expectedJob.name
    });
    artifacts.push(Object.freeze({
      job: descriptor.job,
      job_id: expectedJob.job_id,
      job_name: expectedJob.name,
      artifact_id: verified.artifact_id,
      name: verified.name,
      digest: artifact.digest,
      run_id: verified.run_id,
      run_attempt: verified.run_attempt,
      source_commit: verified.source_commit,
      source_tree: verified.source_tree,
      archive_sha256: verified.archive_sha256,
      archive_bytes: verified.archive_bytes,
      evidence_members: evidence.members,
      execution_identities: evidence.identities
    }));
    executionIdentities.push(...evidence.identities);
  }
  const runnerIds = executionIdentities.map((item) => item.runner_id);
  const environmentIds = executionIdentities.map((item) => item.environment_identity);
  const jobIds = executionIdentities.map((item) => item.job_id);
  if (new Set(runnerIds).size !== runnerIds.length || new Set(environmentIds).size !== environmentIds.length
    || new Set(jobIds).size !== jobIds.length) fail("external qualification execution identities are not distinct");
  if (executionIdentities.some((item) => item.run_id !== String(runId) || item.run_attempt !== String(runAttempt)
    || item.source_commit !== sourceCommit || item.source_tree !== sourceTree || item.artifact_sha256 !== releaseArtifactSha256)) {
    fail("external qualification aggregate execution binding is mismatched");
  }
  return Object.freeze(artifacts);
}

export function verifyExternalQualificationArtifacts({ run, jobs, artifacts, canonicalRun, repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory } = {}) {
  requirePattern(repository, REPOSITORY, "repository");
  requirePattern(sourceCommit, SHA, "source commit");
  requirePattern(sourceTree, SHA, "source tree");
  requirePattern(releaseArtifactSha256, /^[0-9a-f]{64}$/u, "release artifact SHA-256");
  requireId(runId, "run ID");
  requireId(runAttempt, "run attempt");
  requireId(canonicalRunId, "canonical CI run ID");
  requireId(canonicalRunAttempt, "canonical CI run attempt");
  if (String(runId) === String(canonicalRunId)) fail("external qualification and canonical CI workflow runs must be distinct");
  exactRun(run, { repository, sourceCommit, runId, runAttempt });
  exactCanonicalRun(canonicalRun, { repository, sourceCommit, runId: canonicalRunId, runAttempt: canonicalRunAttempt });
  const jobBindings = exactJobs(jobs, { sourceCommit, runId, runAttempt });
  const verified = verifyArtifactList(artifacts, { repository, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, canonicalRunId, canonicalRunAttempt, archiveDirectory, jobBindings });
  const provenanceJob = jobBindings[CURRENT_JOB];
  return Object.freeze({
    schema_version: 1,
    kind: "agentpass-external-qualification-artifact-provenance",
    repository,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    release_artifact_sha256: releaseArtifactSha256,
    run_id: runId,
    run_attempt: runAttempt,
    canonical_ci_run_id: canonicalRunId,
    canonical_ci_run_attempt: canonicalRunAttempt,
    provenance_job_id: provenanceJob.job_id,
    provenance_job_name: provenanceJob.name,
    artifacts: verified,
    evidence_sha256: crypto.createHash("sha256").update(canonicalJson({ repository, source_commit: sourceCommit, source_tree: sourceTree, release_artifact_sha256: releaseArtifactSha256, run_id: runId, run_attempt: runAttempt, canonical_ci_run_id: canonicalRunId, canonical_ci_run_attempt: canonicalRunAttempt, provenance_job_id: provenanceJob.job_id, provenance_job_name: provenanceJob.name, artifacts: verified }), "utf8").digest("hex")
  });
}

function readJson(file, label) {
  try {
    return JSON.parse(fs.readFileSync(path.resolve(file), "utf8"));
  } catch {
    fail(`${label} is not valid JSON: ${file}`);
  }
}

function usage() {
  return "usage: verify-external-artifact-provenance.mjs verify <qualification-run.json> <qualification-jobs.json> <qualification-artifacts.json> <canonical-ci-run.json> <archive-dir> <repository> <source-commit> <source-tree> <release-artifact-sha256> <qualification-run-id> <qualification-run-attempt> <canonical-ci-run-id> <canonical-ci-run-attempt> <output.json>";
}

export function runCli(argv = process.argv.slice(2)) {
  if (argv[0] !== "verify" || argv.length !== 15) throw new ExternalArtifactProvenanceError(usage());
  const result = verifyExternalQualificationArtifacts({
    run: readJson(argv[1], "workflow run"),
    jobs: readJson(argv[2], "workflow jobs"),
    artifacts: readJson(argv[3], "workflow artifacts"),
    canonicalRun: readJson(argv[4], "canonical CI workflow run"),
    archiveDirectory: argv[5],
    repository: argv[6],
    sourceCommit: argv[7],
    sourceTree: argv[8],
    releaseArtifactSha256: argv[9],
    runId: argv[10],
    runAttempt: argv[11],
    canonicalRunId: argv[12],
    canonicalRunAttempt: argv[13]
  });
  fs.writeFileSync(path.resolve(argv[14]), canonicalJson(result), { flag: "wx", mode: 0o600 });
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${canonicalJson(runCli())}\n`);
  } catch (error) {
    process.stderr.write(`external artifact provenance failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
