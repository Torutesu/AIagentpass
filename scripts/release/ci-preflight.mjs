import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanArchives } from "./archive-secret-scan.mjs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { verifyCloudSignerKmsQualificationEvidence } from "../qualification/cloud-signer-kms.mjs";
import { verifyPlatformAuthQualificationEvidence } from "../qualification/platform-auth.mjs";

export const EXACT_CI_LANES = Object.freeze([
  "postgres-authority-16",
  "postgres-authority-17",
  "postgres-integration",
  "browser-e2e",
  "p0b-live-process",
  "test"
]);

/**
 * The aggregate external-qualification envelope is deliberately stricter
 * than the provider-specific reports.  These are the checks that must be
 * present in a real environment for a gate to be considered complete.  The
 * list is part of the release contract: a producer cannot silently reduce a
 * gate to a single happy-path probe.
 */
export const EXTERNAL_QUALIFICATION_GATES = Object.freeze({
  github_actions: Object.freeze({
    environment_kind: "github_actions",
    required_checks: Object.freeze(["canonical_push_run", "exact_six_lanes", "source_sha_binding", "artifact_inventory_binding"])
  }),
  postgresql: Object.freeze({
    environment_kind: "postgresql",
    required_checks: Object.freeze(["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"])
  }),
  kms: Object.freeze({
    environment_kind: "managed_kms",
    required_checks: Object.freeze(["provider_identity", "key_version_binding", "iam_matrix", "rotation_disable", "response_loss_reconciliation", "canary_sign_verify"])
  }),
  webauthn: Object.freeze({
    environment_kind: "webauthn",
    required_checks: Object.freeze(["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"])
  }),
  macos_hardware: Object.freeze({
    environment_kind: "macos_hardware",
    required_checks: Object.freeze(["apple_silicon_signed_notarized", "intel_t2_signed_notarized", "secure_enclave_identity", "negative_identity_entitlement", "lifecycle_recovery"])
  })
});

const SHA = /^[0-9a-f]{40}$/u;
const GITHUB_ID = /^[1-9][0-9]{0,19}$/u;
const GITHUB_ATTEMPT = /^[1-9][0-9]{0,5}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const CI_JOB_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/u;
const PASSING_RESULTS = new Set(["passed", "success", "successful"]);
const EXTERNAL_STATUS = new Set(["passed", "failed", "not_run"]);
const EXTERNAL_REASON = new Set([
  "gate_failed",
  "external_runner_unavailable",
  "evidence_incomplete",
  "invalid_source_binding",
  "invalid_run_binding",
  "invalid_artifact_binding",
  "static_only",
  "secret_scan_failed"
]);
const EXTERNAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const EXTERNAL_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const EXTERNAL_ENVIRONMENT_IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,255}$/u;
const LOCAL_EVIDENCE_MARKER = /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)(?:$|[._:/ -])/iu;
const SECRET_MARKERS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----/u,
  /AGENTPASS_[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE|P12|KEY)/u,
  /(?:aws_secret_access_key|aws_session_token|secret_access_key|session_token|client_secret|private_key_id|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]/iu,
  /(?:password|secret|token|private[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{16,}/iu,
  /["'](?:authorization|credential|assertion|signature|private_key|private_key_id|client_secret|access_token|refresh_token|id_token|session_token|secret_access_key|aws_secret_access_key)["']\s*:/iu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/iu,
  /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u
];
const OPAQUE_ARCHIVE = /\.(?:7z|bz2|dmg|gz|iso|pkg|rar|tar|tgz|zip)$/iu;

export class CiPreflightError extends Error {
  constructor(message) {
    super(message);
    this.name = "CiPreflightError";
  }
}

function githubId(value, label) {
  if (!GITHUB_ID.test(String(value))) throw new CiPreflightError(`${label} is invalid`);
  return String(value);
}

function githubAttempt(value, label) {
  if (!GITHUB_ATTEMPT.test(String(value))) throw new CiPreflightError(`${label} is invalid`);
  return String(value);
}

/**
 * Normalize the run-level identity shared by every GitHub evidence envelope.
 * The API response is treated as untrusted input: the workflow name/path,
 * repository, attempt, status, conclusion, and source SHA are all required.
 */
export function assertGithubRunIdentity(run, {
  expectedRunId,
  expectedSha,
  repository,
  workflowName,
  workflowPath,
  expectedEvent,
  expectedBranch = "main",
  expectedStatus = "completed",
  expectedConclusion = "success",
  expectedRunAttempt
} = {}) {
  if (!plainObject(run)) throw new CiPreflightError("GitHub workflow run envelope is invalid");
  const runId = githubId(run.id, "GitHub workflow run ID");
  const runAttempt = githubAttempt(run.run_attempt, "GitHub workflow run attempt");
  if (expectedRunId !== undefined && runId !== githubId(expectedRunId, "expected GitHub workflow run ID")) throw new CiPreflightError("GitHub workflow run ID is mismatched");
  if (expectedRunAttempt !== undefined && runAttempt !== githubAttempt(expectedRunAttempt, "expected GitHub workflow run attempt")) throw new CiPreflightError("GitHub workflow run attempt is mismatched");
  if (typeof repository !== "string" || repository.length === 0 || run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) throw new CiPreflightError("GitHub workflow run repository is not canonical");
  const repositoryId = githubId(run.repository?.id, "GitHub workflow repository ID");
  const headRepositoryId = githubId(run.head_repository?.id, "GitHub workflow head repository ID");
  const workflowId = githubId(run.workflow_id, "GitHub workflow ID");
  if (run.name !== workflowName || run.path !== workflowPath || run.event !== expectedEvent || run.head_branch !== expectedBranch || run.status !== expectedStatus || run.conclusion !== expectedConclusion) throw new CiPreflightError("GitHub workflow run identity or terminal state is mismatched");
  if (!SHA.test(run.head_sha) || (expectedSha !== undefined && run.head_sha !== expectedSha)) throw new CiPreflightError("GitHub workflow run source SHA is invalid or mismatched");
  return Object.freeze({
    repository,
    repository_id: repositoryId,
    head_repository_id: headRepositoryId,
    workflow: Object.freeze({ id: workflowId, name: workflowName, path: workflowPath }),
    run_id: runId,
    run_attempt: runAttempt,
    head_sha: run.head_sha,
    head_branch: run.head_branch,
    event: run.event,
    status: run.status,
    conclusion: run.conclusion
  });
}

function assertGithubJobsEnvelope(jobs, runIdentity, { jobsTotalCount, expectedJobNames } = {}) {
  if (!Array.isArray(jobs)) throw new CiPreflightError("GitHub workflow jobs envelope is invalid");
  if (jobsTotalCount !== undefined && (!Number.isSafeInteger(jobsTotalCount) || jobsTotalCount !== jobs.length)) throw new CiPreflightError("GitHub workflow jobs response is incomplete or paginated");
  const expected = expectedJobNames === undefined ? undefined : new Set(expectedJobNames);
  if (expected && (expected.size !== expectedJobNames.length || expected.size !== jobs.length)) throw new CiPreflightError("GitHub workflow job inventory is not exact");
  const seenIds = new Set();
  const seenNames = new Set();
  const normalized = jobs.map((job, index) => {
    if (!plainObject(job)) throw new CiPreflightError(`GitHub workflow job ${index} is invalid`);
    const jobId = githubId(job.id, `GitHub workflow job ${index} ID`);
    if (seenIds.has(jobId)) throw new CiPreflightError("GitHub workflow job IDs are duplicated");
    seenIds.add(jobId);
    if (githubId(job.run_id, `GitHub workflow job ${index} run ID`) !== runIdentity.run_id || githubAttempt(job.run_attempt, `GitHub workflow job ${index} run attempt`) !== runIdentity.run_attempt) throw new CiPreflightError(`GitHub workflow job ${index} is not bound to the selected run attempt`);
    if (job.head_sha !== runIdentity.head_sha || job.status !== runIdentity.status || job.conclusion !== runIdentity.conclusion) throw new CiPreflightError(`GitHub workflow job ${index} is not a completed source-bound job`);
    if (typeof job.name !== "string" || job.name.length === 0 || seenNames.has(job.name)) throw new CiPreflightError(`GitHub workflow job ${index} name is invalid or duplicated`);
    seenNames.add(job.name);
    if (expected && !expected.has(job.name)) throw new CiPreflightError(`GitHub workflow job is unexpected: ${job.name}`);
    if (job.workflow_name !== undefined && job.workflow_name !== runIdentity.workflow.name) throw new CiPreflightError(`GitHub workflow job ${index} workflow name is mismatched`);
    return Object.freeze({ job_id: jobId, name: job.name, run_id: runIdentity.run_id, run_attempt: runIdentity.run_attempt, head_sha: runIdentity.head_sha, status: job.status, conclusion: job.conclusion });
  });
  if (expected && [...expected].some((name) => !seenNames.has(name))) throw new CiPreflightError("GitHub workflow job inventory is incomplete");
  return Object.freeze(normalized.sort((left, right) => left.name.localeCompare(right.name)));
}

/**
 * Validate the artifact list returned by GitHub for one exact workflow run.
 * `digest` is the GitHub artifact archive digest, not a digest invented from
 * extracted files. The nested workflow_run metadata must agree with the run
 * envelope on repository IDs, workflow, source, and terminal state.
 */
export function assertGithubArtifacts(artifactsEnvelope, runIdentity, { artifactTotalCount, expectedArtifactNames } = {}) {
  if (!plainObject(artifactsEnvelope) || !Array.isArray(artifactsEnvelope.artifacts)) throw new CiPreflightError("GitHub workflow artifacts envelope is invalid");
  if (artifactTotalCount !== undefined && (!Number.isSafeInteger(artifactTotalCount) || artifactTotalCount !== artifactsEnvelope.artifacts.length)) throw new CiPreflightError("GitHub workflow artifacts response is incomplete or paginated");
  const expected = expectedArtifactNames === undefined ? undefined : new Set(expectedArtifactNames);
  if (expected && (expected.size !== expectedArtifactNames.length || expected.size !== artifactsEnvelope.artifacts.length)) throw new CiPreflightError("GitHub workflow artifact inventory is not exact");
  const seenIds = new Set();
  const seenNames = new Set();
  const normalized = artifactsEnvelope.artifacts.map((artifact, index) => {
    if (!plainObject(artifact)) throw new CiPreflightError(`GitHub workflow artifact ${index} is invalid`);
    const artifactId = githubId(artifact.id, `GitHub workflow artifact ${index} ID`);
    if (seenIds.has(artifactId)) throw new CiPreflightError("GitHub workflow artifact IDs are duplicated");
    seenIds.add(artifactId);
    if (typeof artifact.name !== "string" || artifact.name.length === 0 || seenNames.has(artifact.name)) throw new CiPreflightError(`GitHub workflow artifact ${index} name is invalid or duplicated`);
    seenNames.add(artifact.name);
    if (expected && !expected.has(artifact.name)) throw new CiPreflightError(`GitHub workflow artifact is unexpected: ${artifact.name}`);
    if (artifact.expired !== false || !ARTIFACT_DIGEST.test(artifact.digest)) throw new CiPreflightError(`GitHub workflow artifact ${artifact.name} is expired or has no valid digest`);
    const workflowRun = artifact.workflow_run;
    if (!plainObject(workflowRun)
      || githubId(workflowRun.id, `${artifact.name} workflow run ID`) !== runIdentity.run_id
      || githubId(workflowRun.repository_id, `${artifact.name} repository ID`) !== runIdentity.repository_id
      || githubId(workflowRun.head_repository_id, `${artifact.name} head repository ID`) !== runIdentity.head_repository_id
      || githubId(workflowRun.workflow_id, `${artifact.name} workflow ID`) !== runIdentity.workflow.id
      || workflowRun.head_sha !== runIdentity.head_sha
      || workflowRun.head_branch !== runIdentity.head_branch
      || workflowRun.event !== runIdentity.event
      || workflowRun.status !== runIdentity.status
      || workflowRun.conclusion !== runIdentity.conclusion
      || (workflowRun.run_attempt !== undefined && githubAttempt(workflowRun.run_attempt, `${artifact.name} workflow run attempt`) !== runIdentity.run_attempt)) {
      throw new CiPreflightError(`GitHub workflow artifact ${artifact.name} is not bound to the selected workflow run`);
    }
    return Object.freeze({ artifact_id: artifactId, name: artifact.name, digest: artifact.digest, expired: artifact.expired, repository: runIdentity.repository, workflow: runIdentity.workflow, run_id: runIdentity.run_id, run_attempt: runIdentity.run_attempt, head_sha: runIdentity.head_sha, status: runIdentity.status, conclusion: runIdentity.conclusion });
  });
  if (expected && [...expected].some((name) => !seenNames.has(name))) throw new CiPreflightError("GitHub workflow artifact inventory is incomplete");
  return Object.freeze(normalized.sort((left, right) => left.name.localeCompare(right.name)));
}

export function assertGithubCommit(commit, { repository, expectedSha } = {}) {
  if (!plainObject(commit) || typeof repository !== "string" || repository.length === 0) throw new CiPreflightError("GitHub commit envelope is invalid");
  if (commit.sha !== expectedSha || !SHA.test(commit.sha) || !plainObject(commit.commit) || !SHA.test(commit.commit.tree?.sha)) throw new CiPreflightError("GitHub commit source or tree is invalid or mismatched");
  return Object.freeze({ repository, commit_sha: commit.sha, tree_sha: commit.commit.tree.sha });
}

export function assertGithubWorkflowEvidence(run, jobsEnvelope, artifactsEnvelope, options = {}) {
  if (!plainObject(jobsEnvelope) || !plainObject(artifactsEnvelope)) throw new CiPreflightError("GitHub workflow evidence envelopes are invalid");
  const identity = assertGithubRunIdentity(run, options);
  const jobs = assertGithubJobsEnvelope(jobsEnvelope.jobs, identity, { jobsTotalCount: jobsEnvelope.total_count, expectedJobNames: options.expectedJobNames });
  const artifacts = assertGithubArtifacts(artifactsEnvelope, identity, { artifactTotalCount: artifactsEnvelope.total_count, expectedArtifactNames: options.expectedArtifactNames });
  return Object.freeze({ ...identity, jobs, artifacts });
}

function githubWorkflowIdentity(value, label) {
  if (!plainObject(value)
    || Object.keys(value).some((key) => !["id", "name", "path"].includes(key))
    || !["id", "name", "path"].every((key) => Object.hasOwn(value, key))) {
    throw new CiPreflightError(`${label} is invalid`);
  }
  const id = githubId(value.id, `${label} ID`);
  if (typeof value.name !== "string" || value.name.length === 0 || typeof value.path !== "string" || value.path.length === 0) {
    throw new CiPreflightError(`${label} name or path is invalid`);
  }
  return Object.freeze({ id, name: value.name, path: value.path });
}

export function assertTerminalResults(results, { expectedSha, expectedRunId, expectedRunAttempt, expectedRepository, expectedWorkflow } = {}) {
  if (!Array.isArray(results) || results.length !== EXACT_CI_LANES.length) throw new CiPreflightError("CI terminal results must contain exactly six lanes");
  if (expectedSha !== undefined && !SHA.test(expectedSha)) throw new CiPreflightError("expected source SHA is invalid");
  if (expectedRunId !== undefined && !GITHUB_ID.test(String(expectedRunId))) throw new CiPreflightError("expected CI run ID is invalid");
  const expectedAttempt = expectedRunAttempt === undefined ? undefined : githubAttempt(expectedRunAttempt, "expected CI run attempt");
  if (expectedRepository !== undefined && (typeof expectedRepository !== "string" || expectedRepository.length === 0)) throw new CiPreflightError("expected CI repository is invalid");
  const expectedWorkflowIdentity = expectedWorkflow === undefined ? undefined : githubWorkflowIdentity(expectedWorkflow, "expected CI workflow");
  const seen = new Set();
  const seenJobIds = new Set();
  let commonRunAttempt;
  let commonRepository;
  let commonWorkflow;
  const normalized = results.map((result, index) => {
    if (!plainObject(result)) throw new CiPreflightError(`CI lane ${index} is not an object`);
    const allowed = ["lane", "terminal_result", "head_sha", "run_id", "job_id", "run_attempt", "job_status", "job_conclusion", "repository", "workflow"];
    if (Object.keys(result).some((key) => !allowed.includes(key))) throw new CiPreflightError(`CI lane ${index} has unknown fields`);
    if (allowed.some((key) => !Object.hasOwn(result, key))) throw new CiPreflightError(`CI lane ${index} is missing its complete run/job binding`);
    const lane = result.lane;
    if (!EXACT_CI_LANES.includes(lane) || seen.has(lane)) throw new CiPreflightError("CI lanes must be exact, unique, and canonical");
    seen.add(lane);
    if (!PASSING_RESULTS.has(result.terminal_result)) throw new CiPreflightError(`${lane} is not a passing terminal result`);
    if (!SHA.test(result.head_sha) || (expectedSha !== undefined && result.head_sha !== expectedSha)) throw new CiPreflightError(`${lane} is not bound to the expected source SHA`);
    if (!GITHUB_ID.test(String(result.run_id)) || (expectedRunId !== undefined && String(result.run_id) !== String(expectedRunId))) throw new CiPreflightError(`${lane} is not bound to the expected CI run`);
    if (!GITHUB_ID.test(String(result.job_id)) || seenJobIds.has(String(result.job_id))) throw new CiPreflightError(`${lane} job ID is invalid or duplicated`);
    seenJobIds.add(String(result.job_id));
    const runAttempt = githubAttempt(result.run_attempt, `${lane} run attempt`);
    if (expectedAttempt !== undefined && runAttempt !== expectedAttempt) throw new CiPreflightError(`${lane} is not bound to the expected CI run attempt`);
    if (result.job_status !== "completed") throw new CiPreflightError(`${lane} job status is not completed`);
    if (result.job_conclusion !== "success") throw new CiPreflightError(`${lane} job conclusion is not successful`);
    if (typeof result.repository !== "string" || result.repository.length === 0) throw new CiPreflightError(`${lane} repository binding is invalid`);
    if (expectedRepository !== undefined && result.repository !== expectedRepository) throw new CiPreflightError(`${lane} repository binding is mismatched`);
    const workflow = githubWorkflowIdentity(result.workflow, `${lane} workflow`);
    if (expectedWorkflowIdentity !== undefined && (workflow.id !== expectedWorkflowIdentity.id || workflow.name !== expectedWorkflowIdentity.name || workflow.path !== expectedWorkflowIdentity.path)) throw new CiPreflightError(`${lane} workflow binding is mismatched`);
    if (commonRunAttempt === undefined) commonRunAttempt = runAttempt;
    if (commonRunAttempt !== runAttempt) throw new CiPreflightError("CI lanes are bound to different run attempts");
    if (commonRepository === undefined) commonRepository = result.repository;
    if (commonRepository !== result.repository) throw new CiPreflightError("CI lanes are bound to different repositories");
    if (commonWorkflow === undefined) commonWorkflow = workflow;
    if (commonWorkflow.id !== workflow.id || commonWorkflow.name !== workflow.name || commonWorkflow.path !== workflow.path) throw new CiPreflightError("CI lanes are bound to different workflows");
    return Object.freeze({
      lane,
      terminal_result: "passed",
      head_sha: result.head_sha,
      run_id: String(result.run_id),
      job_id: String(result.job_id),
      run_attempt: runAttempt,
      job_status: result.job_status,
      job_conclusion: result.job_conclusion,
      repository: result.repository,
      workflow
    });
  });
  if (seen.size !== EXACT_CI_LANES.length || EXACT_CI_LANES.some((lane) => !seen.has(lane))) throw new CiPreflightError("CI lane inventory is incomplete");
  normalized.sort((left, right) => EXACT_CI_LANES.indexOf(left.lane) - EXACT_CI_LANES.indexOf(right.lane));
  return Object.freeze(normalized);
}

/**
 * Bind the browser runner's result to the exact CI lane before it becomes a
 * retained artifact.  The runner output is intentionally untrusted: a
 * startup `not_run`, partial execution, or a locally manufactured success is
 * not production E2E evidence.  The digest covers the complete raw result
 * payload and the surrounding fields bind that payload to this CI run.
 */
export function assertBrowserE2eEvidence(input, {
  expectedSourceCommit,
  expectedSourceTree,
  expectedRunId,
  expectedRunAttempt,
  expectedJobId,
  expectedTests
} = {}) {
  if (!plainObject(input)) throw new CiPreflightError("browser E2E evidence must be an object");
  assertExactKeys(input, ["schema_version", "kind", "phase", "status", "qualified", "reason", "executed", "expected", "exit_code"], "browser E2E result");
  if (input.schema_version !== 1 || input.kind !== "agentpass-browser-e2e-result"
    || input.phase !== "tests" || input.status !== "passed" || input.qualified !== true
    || input.reason !== null || !Number.isSafeInteger(input.executed) || input.executed < 1
    || !Number.isSafeInteger(input.expected) || input.expected < 1 || input.executed !== input.expected
    || input.exit_code !== 0) {
    throw new CiPreflightError("browser E2E result is not a complete passing execution");
  }
  if (typeof expectedSourceCommit !== "string" || !SHA.test(expectedSourceCommit)
    || typeof expectedSourceTree !== "string" || !SHA.test(expectedSourceTree)
    || !GITHUB_ID.test(String(expectedRunId)) || !GITHUB_ATTEMPT.test(String(expectedRunAttempt))
    || typeof expectedJobId !== "string" || !CI_JOB_NAME.test(expectedJobId)
    || !Number.isSafeInteger(expectedTests) || expectedTests < 1 || input.expected !== expectedTests) {
    throw new CiPreflightError("browser E2E evidence binding is invalid or incomplete");
  }
  const artifactSha256 = crypto.createHash("sha256").update(canonicalJson(input), "utf8").digest("hex");
  return Object.freeze({
    schema_version: 1,
    kind: "agentpass-browser-e2e-evidence",
    phase: input.phase,
    status: input.status,
    qualified: input.qualified,
    reason: input.reason,
    executed: input.executed,
    expected: input.expected,
    exit_code: input.exit_code,
    source_commit: expectedSourceCommit,
    source_tree: expectedSourceTree,
    ci_run_id: String(expectedRunId),
    ci_run_attempt: String(expectedRunAttempt),
    ci_job_id: expectedJobId,
    artifact_sha256: artifactSha256
  });
}

export function assertGithubCiRun(run, jobs, { expectedSha, repository = undefined, expectedRunId = undefined, workflowPath = ".github/workflows/ci.yml", expectedBranch = "main", jobsTotalCount = undefined } = {}) {
  if (!plainObject(run) || !Array.isArray(jobs)) throw new CiPreflightError("GitHub CI run envelope is invalid");
  const identity = assertGithubRunIdentity(run, {
    expectedSha,
    expectedRunId,
    repository: repository ?? run.repository?.full_name,
    workflowName: "CI",
    workflowPath,
    expectedEvent: "push",
    expectedBranch
  });
  const normalizedJobs = assertGithubJobsEnvelope(jobs, identity, { jobsTotalCount });
  const terminal = normalizedJobs.map((job) => ({
    lane: canonicalLane(job.name),
    terminal_result: job.conclusion === "success" ? "passed" : job.conclusion,
    head_sha: job.head_sha,
    run_id: job.run_id,
    job_id: job.job_id,
    run_attempt: job.run_attempt,
    job_status: job.status,
    job_conclusion: job.conclusion,
    repository: identity.repository,
    workflow: identity.workflow
  }));
  return Object.freeze({ ...identity, terminal_results: assertTerminalResults(terminal, {
    expectedSha: identity.head_sha,
    expectedRunId: identity.run_id,
    expectedRunAttempt: identity.run_attempt,
    expectedRepository: identity.repository,
    expectedWorkflow: identity.workflow
  }) });
}

/**
 * Read protected JSON evidence without losing the bytes that were uploaded.
 * Object parsing alone would allow a pretty-printed or reordered substitute to
 * pass a semantic verifier and then be retained as release evidence.
 */
export function readCanonicalJson(file) {
  let text;
  let value;
  try {
    text = fs.readFileSync(path.resolve(file), "utf8");
    value = JSON.parse(text);
  } catch {
    throw new CiPreflightError(`protected JSON evidence is not readable JSON: ${file}`);
  }
  if (text !== canonicalJson(value)) throw new CiPreflightError(`protected JSON evidence is not canonical: ${file}`);
  return value;
}

const RELEASE_TAR = /\.(?:tar|tgz|tar\.gz|tar\.bz2)$/iu;
const RELEASE_PKG = /\.pkg$/iu;
const RELEASE_OPAQUE = /\.(?:7z|bz2|dmg|gz|iso|rar|zip)$/iu;
const MAX_RELEASE_FILE_BYTES = 16 * 1024 * 1024 * 1024;

/**
 * Scan a release tree, including tar variants and the expanded contents of
 * Apple installer packages. The returned paths are relative to the supplied
 * root so the evidence is reproducible between the candidate and promotion
 * jobs. `exclude` is deliberately an exact relative path, used for the
 * evidence file itself to avoid a self-referential digest.
 */
export function scanReleaseArtifacts(rootInput, { exclude = [] } = {}) {
  if (typeof rootInput !== "string" || rootInput.length === 0) throw new CiPreflightError("release artifact root is required");
  if (!Array.isArray(exclude) || exclude.some((value) => typeof value !== "string" || value.length === 0 || path.isAbsolute(value))) throw new CiPreflightError("release artifact exclusions are invalid");
  const root = path.resolve(rootInput);
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new CiPreflightError("release artifact root must be a directory");
  const excluded = new Set(exclude.map((value) => value.split(path.sep).join("/")));
  const entries = [];
  visitReleaseTree(root, root, excluded, entries);
  entries.sort((left, right) => left.path.localeCompare(right.path));
  return Object.freeze({ version: 1, clean: true, files: Object.freeze(entries.map((entry) => Object.freeze(entry))) });
}

function visitReleaseTree(root, current, excluded, entries) {
  for (const name of fs.readdirSync(current).sort()) {
    const target = path.join(current, name);
    const relative = path.relative(root, target).split(path.sep).join("/");
    if (excluded.has(relative)) continue;
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new CiPreflightError(`release artifact contains an unsupported entry: ${relative}`);
    if (stat.isDirectory()) {
      visitReleaseTree(root, target, excluded, entries);
      continue;
    }
    if (RELEASE_PKG.test(name)) entries.push(scanPkgArtifact(root, target, relative));
    else if (RELEASE_TAR.test(name)) entries.push(scanArchiveArtifact(target, relative));
    else if (RELEASE_OPAQUE.test(name)) throw new CiPreflightError(`release artifact format requires a dedicated scanner: ${relative}`);
    else entries.push(scanPlainArtifact(target, relative));
  }
}

function scanPlainArtifact(file, relative) {
  return scanStableArtifact(file, relative, "file", (snapshot) => scanArchives([snapshot]));
}

function scanArchiveArtifact(file, relative) {
  return scanStableArtifact(file, relative, "archive", (snapshot) => scanArchives([snapshot]));
}

function scanPkgArtifact(root, file, relative) {
  return scanStableArtifact(file, relative, "pkg", (snapshot, outer) => {
    const expanded = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || process.env.TMPDIR || "/tmp", "agentpass-pkg-scan-"));
    try {
      try {
        execFileSync("pkgutil", ["--expand-full", snapshot, expanded], { stdio: ["ignore", "ignore", "pipe"], encoding: "utf8", maxBuffer: 1024 * 1024 });
      } catch (error) {
        const detail = error?.stderr?.toString?.("utf8")?.trim() || error?.message || "pkgutil failed";
        throw new CiPreflightError(`PKG expansion failed for ${relative}: ${detail}`);
      }
      const result = scanArchives([expanded]);
      return { path: relative, kind: "pkg", ...outer, scan: normalizeArchiveResult(result, expanded, relative) };
    } finally {
      fs.rmSync(expanded, { recursive: true, force: true });
    }
  });
}

/**
 * Bind every format scanner to bytes copied from one already-opened release
 * file descriptor. Passing the release pathname to a scanner after an
 * lstat/open/hash sequence would re-resolve attacker-controlled directory
 * entries and leave a pathname swap window. The scanner pathname below is a
 * private, single-file snapshot; the source fd and snapshot fd are both
 * checked before and after the scanner runs.
 */
function scanStableArtifact(file, relative, kind, scan) {
  let sourceFd;
  let snapshotFd;
  let snapshotDirectory;
  try {
    sourceFd = openRegularFile(file);
    const sourceStat = fs.fstatSync(sourceFd);
    const copied = copyRegularFileToSnapshot(sourceFd, sourceStat, file);
    const sourceAfterCopy = hashOpenRegularFile(sourceFd, file);
    if (!sameFileDigest(copied, sourceAfterCopy)) throw new CiPreflightError(`release artifact changed while being scanned: ${relative}`);

    snapshotDirectory = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || process.env.TMPDIR || "/tmp", "agentpass-release-scan-"));
    // Preserve the source suffix so the dedicated scanner selects the same
    // format (for example, tar versus a plain file) without reopening source.
    const snapshot = path.join(snapshotDirectory, path.basename(file));
    const snapshotWriteFd = openSnapshotForWrite(snapshot, relative);
    try {
      copyBytesToSnapshot(copied.bytes, sourceFd, snapshotWriteFd, file);
      fs.fsyncSync(snapshotWriteFd);
    } finally {
      fs.closeSync(snapshotWriteFd);
    }
    snapshotFd = openRegularFile(snapshot);
    const snapshotBefore = hashOpenRegularFile(snapshotFd, snapshot);
    if (!sameFileDigest(copied, snapshotBefore)) throw new CiPreflightError(`release artifact snapshot is inconsistent: ${relative}`);

    const result = scan(snapshot, copied);
    const sourceAfterScan = hashOpenRegularFile(sourceFd, file);
    const snapshotAfterScan = hashOpenRegularFile(snapshotFd, snapshot);
    if (!sameFileDigest(copied, sourceAfterScan) || !sameFileDigest(copied, snapshotAfterScan)) {
      throw new CiPreflightError(`release artifact changed while being scanned: ${relative}`);
    }
    return { path: relative, kind, ...copied, scan: normalizeArchiveResult(result, snapshot, relative) };
  } finally {
    if (snapshotFd !== undefined) fs.closeSync(snapshotFd);
    if (sourceFd !== undefined) fs.closeSync(sourceFd);
    if (snapshotDirectory !== undefined) fs.rmSync(snapshotDirectory, { recursive: true, force: true });
  }
}

function openRegularFile(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(fd);
    assertRegularFileStat(stat, file);
    return fd;
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (error instanceof CiPreflightError) throw error;
    throw new CiPreflightError(`release artifact could not be opened safely: ${file}`);
  }
}

function openSnapshotForWrite(file, relative) {
  try {
    return fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
  } catch {
    throw new CiPreflightError(`release artifact snapshot could not be created: ${relative}`);
  }
}

function assertRegularFileStat(stat, file) {
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_RELEASE_FILE_BYTES) {
    throw new CiPreflightError(`release artifact file is unsafe or too large: ${file}`);
  }
}

function copyRegularFileToSnapshot(sourceFd, sourceStat, file) {
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, sourceStat.size)));
  let offset = 0;
  while (offset < sourceStat.size) {
    const count = fs.readSync(sourceFd, buffer, 0, Math.min(buffer.length, sourceStat.size - offset), offset);
    if (count === 0) throw new CiPreflightError(`release artifact changed while being scanned: ${file}`);
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = fs.fstatSync(sourceFd);
  if (after.dev !== sourceStat.dev || after.ino !== sourceStat.ino || after.size !== sourceStat.size || after.nlink !== sourceStat.nlink) {
    throw new CiPreflightError(`release artifact changed while being scanned: ${file}`);
  }
  return { bytes: sourceStat.size, sha256: hash.digest("hex") };
}

function copyBytesToSnapshot(bytes, sourceFd, snapshotFd, file) {
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, bytes)));
  let offset = 0;
  while (offset < bytes) {
    const count = fs.readSync(sourceFd, buffer, 0, Math.min(buffer.length, bytes - offset), offset);
    if (count === 0) throw new CiPreflightError(`release artifact changed while being scanned: ${file}`);
    let written = 0;
    while (written < count) written += fs.writeSync(snapshotFd, buffer, written, count - written, offset + written);
    offset += count;
  }
}

function hashOpenRegularFile(fd, file) {
  const before = fs.fstatSync(fd);
  assertRegularFileStat(before, file);
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, before.size)));
  let offset = 0;
  while (offset < before.size) {
    const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, before.size - offset), offset);
    if (count === 0) throw new CiPreflightError(`release artifact changed while being scanned: ${file}`);
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = fs.fstatSync(fd);
  if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.nlink !== before.nlink) {
    throw new CiPreflightError(`release artifact changed while being scanned: ${file}`);
  }
  return { bytes: before.size, sha256: hash.digest("hex") };
}

function sameFileDigest(left, right) {
  return left.bytes === right.bytes && left.sha256 === right.sha256;
}

function normalizeArchiveResult(result, source, prefix) {
  return {
    version: result.version,
    clean: result.clean,
    total_bytes: result.total_bytes,
    files: result.files.map((item) => {
      const directoryMarker = `${path.resolve(source)}${path.sep}`;
      const archiveMarker = `${path.resolve(source)}::`;
      const member = item.path === path.resolve(source)
        ? prefix
        : item.path.startsWith(directoryMarker)
        ? item.path.slice(directoryMarker.length).split(path.sep).join("/")
        : item.path.startsWith(archiveMarker)
          ? item.path.slice(archiveMarker.length)
          : item.path;
      return { path: member, bytes: item.bytes, sha256: item.sha256 };
    }).sort((left, right) => left.path.localeCompare(right.path))
  };
}

export function assertSourceBinding({ releaseHeadSha, qualificationHeadSha, ciHeadSha, manifestSourceCommit, manifestSourceTree, independentTreeSha }) {
  const values = [releaseHeadSha, qualificationHeadSha, ciHeadSha, manifestSourceCommit, manifestSourceTree, independentTreeSha];
  if (values.some((value) => typeof value !== "string" || !SHA.test(value))) throw new CiPreflightError("release source binding contains an invalid SHA or tree");
  if (new Set([releaseHeadSha, qualificationHeadSha, ciHeadSha, manifestSourceCommit]).size !== 1) throw new CiPreflightError("release, qualification, CI, and manifest commits do not match");
  if (manifestSourceTree !== independentTreeSha) throw new CiPreflightError("manifest source tree does not match independent GitHub tree lookup");
  return Object.freeze({ source_commit: releaseHeadSha, source_tree: manifestSourceTree });
}

/**
 * A release candidate may carry KMS evidence only when the complete provider
 * qualification passed for the exact source commit.  `not_run` is useful
 * operational evidence but is never a promotion result.
 */
export function assertCloudSignerKmsQualified(input, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedRunId, expectedJobId } = {}) {
  assertExpectedQualificationBinding({ expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedRunId, expectedJobId }, { label: "KMS", deploymentDigest: true });
  let result;
  try { result = verifyCloudSignerKmsQualificationEvidence(input, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedRunId, expectedJobId }); }
  catch { throw new CiPreflightError("cloud signer KMS qualification evidence is invalid"); }
  assertQualificationBinding(result, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedRunId, expectedJobId }, "cloud signer KMS");
  return Object.freeze(result);
}

export function assertPlatformAuthQualified(input, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigests, expectedRunId, expectedJobId } = {}) {
  assertExpectedQualificationBinding({ expectedSourceCommit, expectedSourceTree, expectedDeploymentDigests, expectedRunId, expectedJobId }, { label: "Platform Auth", deploymentDigests: true });
  let result;
  try { result = verifyPlatformAuthQualificationEvidence(input, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigests, expectedRunId, expectedJobId }); }
  catch { throw new CiPreflightError("Platform auth qualification evidence is invalid"); }
  assertQualificationBinding(result, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigests, expectedRunId, expectedJobId }, "Platform auth");
  return Object.freeze(result);
}

export function assertQualificationBinding(result, { expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedDeploymentDigests, expectedRunId, expectedJobId } = {}, label = "qualification") {
  if (result.status !== "passed" || result.qualified !== true || result.source_commit !== expectedSourceCommit
    || (expectedSourceTree !== undefined && result.source_tree !== expectedSourceTree)
    || (expectedDeploymentDigest !== undefined && result.deployment_digest !== expectedDeploymentDigest)
    || (expectedDeploymentDigests !== undefined && (!result.deployment_digests
      || Object.keys(expectedDeploymentDigests).some((name) => result.deployment_digests[name] !== expectedDeploymentDigests[name])))
    || (expectedRunId !== undefined && result.run_id !== String(expectedRunId))
    || (expectedJobId !== undefined && result.job_id !== String(expectedJobId))) {
    throw new CiPreflightError(`${label} qualification is not a passed result for the expected protected binding`);
  }
  return result;
}

/**
 * Verify the release-facing external qualification aggregate.
 *
 * JSON Schema validation is necessary but not sufficient here: JSON Schema
 * cannot express equality between `expected` and `observed`, nor can it bind
 * every child execution to an independently retrieved run/job/artifact.  The
 * release workflow must call this function with those authoritative values;
 * omitting an expected binding is an error rather than a permissive mode.
 */
export function assertExternalQualificationEvidence(input, {
  expectedRepository,
  expectedSourceCommit,
  expectedSourceTree,
  expectedReleaseArtifactSha256,
  expectedCiRunId,
  expectedCiRunAttempt,
  expectedGateArtifacts = {},
  expectedGateJobIds = {}
} = {}) {
  requireExternalBindingExpectation({
    expectedRepository,
    expectedSourceCommit,
    expectedSourceTree,
    expectedReleaseArtifactSha256,
    expectedCiRunId,
    expectedCiRunAttempt
  });
  const expectedArtifacts = normalizeExpectedGateMap(expectedGateArtifacts, "artifact");
  const expectedJobs = normalizeExpectedGateMap(expectedGateJobIds, "job");
  if (!plainObject(input)) throw new CiPreflightError("external qualification evidence must be an object");
  assertExactKeys(input, ["schema_version", "kind", "status", "qualified", "reason", "release", "gates"], "external qualification evidence");
  if (input.schema_version !== 1 || input.kind !== "agentpass-external-qualification") throw new CiPreflightError("external qualification evidence kind/version is invalid");
  if (!EXTERNAL_STATUS.has(input.status)) throw new CiPreflightError("external qualification evidence status is invalid");
  if (typeof input.qualified !== "boolean" || (input.status === "passed" ? input.qualified !== true : input.qualified !== false)) throw new CiPreflightError("external qualification qualified flag is inconsistent");
  if ((input.reason !== null && (typeof input.reason !== "string" || !EXTERNAL_REASON.has(input.reason)))
    || (input.status === "passed" && input.reason !== null)
    || (input.status !== "passed" && (typeof input.reason !== "string" || input.reason.length === 0))) {
    throw new CiPreflightError("external qualification reason is inconsistent");
  }

  const release = input.release;
  if (!plainObject(release)) throw new CiPreflightError("external qualification release binding is invalid");
  assertExactKeys(release, ["repository", "source_commit", "source_tree", "artifact_sha256", "ci_run_id", "ci_run_attempt"], "external qualification release binding");
  if (release.repository !== expectedRepository
    || release.source_commit !== expectedSourceCommit
    || release.source_tree !== expectedSourceTree
    || release.artifact_sha256 !== expectedReleaseArtifactSha256
    || release.ci_run_id !== expectedCiRunId
    || release.ci_run_attempt !== expectedCiRunAttempt) {
    throw new CiPreflightError("external qualification release binding is mismatched");
  }

  if (!plainObject(input.gates)) throw new CiPreflightError("external qualification gates are invalid");
  const gateNames = Object.keys(EXTERNAL_QUALIFICATION_GATES);
  if (new Set(Object.keys(input.gates)).size !== gateNames.length
    || gateNames.some((name) => !Object.prototype.hasOwnProperty.call(input.gates, name))) {
    throw new CiPreflightError("external qualification gate inventory is not exact");
  }

  const normalizedGates = {};
  const executionArtifacts = new Set();
  const statuses = [];
  for (const [name, contract] of Object.entries(EXTERNAL_QUALIFICATION_GATES)) {
    const gate = input.gates[name];
    assertExternalGate(name, gate, contract, release, {
      expectedArtifactSha256: expectedArtifacts[name],
      expectedJobId: expectedJobs[name],
      executionArtifacts
    });
    normalizedGates[name] = gate;
    statuses.push(gate.status);
  }
  const derivedStatus = statuses.includes("failed") ? "failed" : statuses.includes("not_run") ? "not_run" : "passed";
  if (input.status !== derivedStatus) throw new CiPreflightError("external qualification aggregate status is not derived from gate statuses");
  return Object.freeze({ ...input, release: Object.freeze({ ...release }), gates: Object.freeze(normalizedGates) });
}

function assertExternalGate(name, gate, contract, release, { expectedArtifactSha256, expectedJobId, executionArtifacts } = {}) {
  if (!plainObject(gate)) throw new CiPreflightError(`external qualification gate ${name} is invalid`);
  assertExactKeys(gate, ["status", "qualified", "reason", "execution", "required_checks", "checks"], `external qualification gate ${name}`);
  if (!EXTERNAL_STATUS.has(gate.status) || gate.qualified !== (gate.status === "passed")) throw new CiPreflightError(`external qualification gate ${name} status/qualified mismatch`);
  if (!Array.isArray(gate.required_checks)
    || gate.required_checks.length !== contract.required_checks.length
    || gate.required_checks.some((value, index) => value !== contract.required_checks[index])) {
    throw new CiPreflightError(`external qualification gate ${name} required check inventory is invalid`);
  }
  if (gate.status === "not_run") {
    if (gate.reason === null || typeof gate.reason !== "string" || gate.execution !== null || !Array.isArray(gate.checks) || gate.checks.length !== 0) {
      throw new CiPreflightError(`external qualification gate ${name} not_run evidence is not fail-closed`);
    }
    return;
  }
  if (gate.reason !== null && (typeof gate.reason !== "string" || gate.reason.length === 0)) throw new CiPreflightError(`external qualification gate ${name} reason is invalid`);
  if (gate.status === "passed" && gate.reason !== null) throw new CiPreflightError(`external qualification gate ${name} passed result has a failure reason`);
  if (gate.status === "failed" && gate.reason === null) throw new CiPreflightError(`external qualification gate ${name} failed result has no reason`);
  if (expectedArtifactSha256 === undefined || expectedJobId === undefined) throw new CiPreflightError(`external qualification gate ${name} is missing independent artifact/job binding`);
  assertExternalExecution(name, gate.execution, contract, release, { expectedArtifactSha256, expectedJobId, executionArtifacts });
  if (!Array.isArray(gate.checks) || gate.checks.length < contract.required_checks.length) throw new CiPreflightError(`external qualification gate ${name} checks are incomplete`);
  const seenChecks = new Set();
  let failedCheck = false;
  for (const check of gate.checks) {
    assertExternalCheck(name, check);
    if (seenChecks.has(check.check_id)) throw new CiPreflightError(`external qualification gate ${name} has duplicate checks`);
    seenChecks.add(check.check_id);
    failedCheck ||= check.status === "failed";
  }
  if (contract.required_checks.some((checkId) => !seenChecks.has(checkId))) throw new CiPreflightError(`external qualification gate ${name} is missing a required check`);
  if (gate.status === "passed" && failedCheck) throw new CiPreflightError(`external qualification gate ${name} claims passed with a failed check`);
  if (gate.status === "failed" && !failedCheck) throw new CiPreflightError(`external qualification gate ${name} claims failed without a failed check`);
}

function assertExternalExecution(name, execution, contract, release, { expectedArtifactSha256, expectedJobId, executionArtifacts } = {}) {
  if (!plainObject(execution)) throw new CiPreflightError(`external qualification gate ${name} execution is missing`);
  assertExactKeys(execution, ["kind", "real_execution", "runner_id", "run_id", "job_id", "run_attempt", "source_commit", "source_tree", "artifact_sha256", "started_at", "completed_at", "environment"], `external qualification gate ${name} execution`);
  if (execution.kind !== "external_runner" || execution.real_execution !== true
    || typeof execution.runner_id !== "string" || !EXTERNAL_IDENTIFIER.test(execution.runner_id) || LOCAL_EVIDENCE_MARKER.test(execution.runner_id)
    || execution.run_id !== release.ci_run_id || execution.job_id !== expectedJobId || execution.run_attempt !== release.ci_run_attempt
    || execution.source_commit !== release.source_commit || execution.source_tree !== release.source_tree
    || execution.artifact_sha256 !== expectedArtifactSha256 || !/^[0-9a-f]{64}$/u.test(execution.artifact_sha256)) {
    throw new CiPreflightError(`external qualification gate ${name} execution binding is invalid`);
  }
  if (executionArtifacts.has(execution.artifact_sha256)) throw new CiPreflightError("external qualification child artifact digest is reused across gates");
  executionArtifacts.add(execution.artifact_sha256);
  if (!EXTERNAL_TIMESTAMP.test(execution.started_at) || !EXTERNAL_TIMESTAMP.test(execution.completed_at)
    || Date.parse(execution.completed_at) < Date.parse(execution.started_at)) throw new CiPreflightError(`external qualification gate ${name} execution timestamps are invalid`);
  const environment = execution.environment;
  if (!plainObject(environment)) throw new CiPreflightError(`external qualification gate ${name} environment is invalid`);
  assertExactKeys(environment, ["kind", "identity"], `external qualification gate ${name} environment`);
  if (environment.kind !== contract.environment_kind || typeof environment.identity !== "string"
    || !EXTERNAL_ENVIRONMENT_IDENTITY.test(environment.identity) || LOCAL_EVIDENCE_MARKER.test(environment.identity)) {
    throw new CiPreflightError(`external qualification gate ${name} is not bound to a real required environment`);
  }
}

function assertExternalCheck(name, check) {
  if (!plainObject(check)) throw new CiPreflightError(`external qualification gate ${name} check is invalid`);
  assertExactKeys(check, ["check_id", "status", "expected", "observed", "evidence_sha256"], `external qualification gate ${name} check`);
  if (typeof check.check_id !== "string" || !/^[a-z][a-z0-9_]{2,63}$/u.test(check.check_id) || !["passed", "failed"].includes(check.status)) throw new CiPreflightError(`external qualification gate ${name} check identity is invalid`);
  const expected = assertExternalTypedValue(check.expected, `${name}.${check.check_id}.expected`);
  const observed = assertExternalTypedValue(check.observed, `${name}.${check.check_id}.observed`);
  if (expected.type !== observed.type || check.status !== (canonicalJson(expected) === canonicalJson(observed) ? "passed" : "failed")) throw new CiPreflightError(`external qualification gate ${name} check result does not match expected value`);
  if (check.status === "passed" && (!isPositiveExternalCheckValue(expected) || !isPositiveExternalCheckValue(observed))) {
    throw new CiPreflightError(`external qualification gate ${name} passed check is not a positive observation`);
  }
  if (typeof check.evidence_sha256 !== "string" || !/^[0-9a-f]{64}$/u.test(check.evidence_sha256)) throw new CiPreflightError(`external qualification gate ${name} check evidence digest is invalid`);
}

function isPositiveExternalCheckValue(value) {
  if (value.type === "boolean") return value.value === true;
  if (value.type === "integer") return value.value >= 0;
  if (value.type === "string") {
    return value.value.length > 0
      && !/^(?:0|false|failed|incomplete|missing|n(?:\W|_)*a|no|not(?:\W|_)*available|not(?:\W|_)*run|pending|partial|skipped|simulated|unknown|unavailable)$/iu.test(value.value.trim());
  }
  return false;
}

function assertExternalTypedValue(value, label) {
  if (!plainObject(value)) throw new CiPreflightError(`${label} is not typed`);
  assertExactKeys(value, ["type", "value"], label);
  if (value.type === "boolean" && typeof value.value === "boolean") return Object.freeze({ type: value.type, value: value.value });
  if (value.type === "integer" && Number.isSafeInteger(value.value)) return Object.freeze({ type: value.type, value: value.value });
  if (value.type === "string" && typeof value.value === "string" && value.value.length <= 256) return Object.freeze({ type: value.type, value: value.value });
  throw new CiPreflightError(`${label} has an invalid typed value`);
}

function requireExternalBindingExpectation({ expectedRepository, expectedSourceCommit, expectedSourceTree, expectedReleaseArtifactSha256, expectedCiRunId, expectedCiRunAttempt }) {
  if (typeof expectedRepository !== "string" || !/^[^/\s]+\/[^/\s]+$/u.test(expectedRepository)
    || typeof expectedSourceCommit !== "string" || !SHA.test(expectedSourceCommit)
    || typeof expectedSourceTree !== "string" || !SHA.test(expectedSourceTree)
    || typeof expectedReleaseArtifactSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(expectedReleaseArtifactSha256)
    || !GITHUB_ID.test(String(expectedCiRunId ?? "")) || !GITHUB_ID.test(String(expectedCiRunAttempt ?? ""))) {
    throw new CiPreflightError("external qualification authoritative binding expectations are incomplete or invalid");
  }
}

function normalizeExpectedGateMap(value, label) {
  if (!plainObject(value)) throw new CiPreflightError(`external qualification expected ${label} map is invalid`);
  const names = new Set(Object.keys(EXTERNAL_QUALIFICATION_GATES));
  if (Object.keys(value).some((name) => !names.has(name))) throw new CiPreflightError(`external qualification expected ${label} map has an unknown gate`);
  const normalized = {};
  for (const [name, item] of Object.entries(value)) {
    if (typeof item !== "string" || (label === "artifact" ? !/^[0-9a-f]{64}$/u.test(item) : !GITHUB_ID.test(item))) throw new CiPreflightError(`external qualification expected ${label} binding for ${name} is invalid`);
    normalized[name] = item;
  }
  return normalized;
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) throw new CiPreflightError(`${label} has unknown or missing fields`);
}

function assertExpectedQualificationBinding({ expectedSourceCommit, expectedSourceTree, expectedDeploymentDigest, expectedDeploymentDigests, expectedRunId, expectedJobId }, { label, deploymentDigest = false, deploymentDigests = false }) {
  if (typeof expectedSourceCommit !== "string" || !SHA.test(expectedSourceCommit)) throw new CiPreflightError(`expected ${label} qualification source SHA is invalid`);
  if (typeof expectedSourceTree !== "string" || !SHA.test(expectedSourceTree)) throw new CiPreflightError(`expected ${label} qualification source tree is invalid`);
  if (!GITHUB_ID.test(String(expectedRunId ?? "")) || !GITHUB_ID.test(String(expectedJobId ?? ""))) throw new CiPreflightError(`expected ${label} qualification run/job binding is invalid`);
  if (deploymentDigest && (typeof expectedDeploymentDigest !== "string" || !/^[0-9a-f]{64}$/u.test(expectedDeploymentDigest))) throw new CiPreflightError("expected KMS qualification deployment digest is invalid");
  if (deploymentDigests && (!plainObject(expectedDeploymentDigests)
    || Object.keys(expectedDeploymentDigests).length !== 2
    || !["primary", "secondary"].every((name) => typeof expectedDeploymentDigests[name] === "string" && /^[0-9a-f]{64}$/u.test(expectedDeploymentDigests[name])))) {
    throw new CiPreflightError("expected Platform Auth deployment digests are invalid");
  }
}

export function scanProtectedArtifacts(paths, { maximumBytes = 64 * 1024 * 1024 } = {}) {
  if (!Array.isArray(paths) || paths.length < 1) throw new CiPreflightError("protected artifact paths are required");
  const seenInodes = new Map();
  const files = [];
  for (const input of paths) walk(path.resolve(input), seenInodes, files, maximumBytes);
  return Object.freeze({ version: 1, clean: true, files: Object.freeze(files.sort((left, right) => left.path.localeCompare(right.path))) });
}

function walk(target, seenInodes, files, maximumBytes) {
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new CiPreflightError(`protected artifact contains an unsupported file: ${target}`);
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(target)) walk(path.join(target, entry), seenInodes, files, maximumBytes);
    return;
  }
  if (OPAQUE_ARCHIVE.test(target)) throw new CiPreflightError(`protected artifact archive requires an independent scanner: ${target}`);
  if (stat.size > maximumBytes) throw new CiPreflightError(`protected artifact file exceeds scan limit: ${target}`);
  const inode = `${stat.dev}:${stat.ino}`;
  if (seenInodes.has(inode)) throw new CiPreflightError(`protected artifact contains a hardlink: ${target}`);
  seenInodes.set(inode, target);
  const bytes = fs.readFileSync(target);
  const text = bytes.toString("utf8");
  if (SECRET_MARKERS.some((marker) => marker.test(text))) throw new CiPreflightError(`protected artifact contains secret material: ${target}`);
  files.push(Object.freeze({ path: target, bytes: stat.size, sha256: crypto.createHash("sha256").update(bytes).digest("hex") }));
}

function canonicalLane(value) {
  if (EXACT_CI_LANES.includes(value)) return value;
  const matches = EXACT_CI_LANES.filter((lane) => value.startsWith(`${lane} (`) && value.endsWith(")"));
  if (matches.length === 1) return matches[0];
  return value;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), "utf8"));
}

function usage() {
  return [
    "usage:",
    "  ci-preflight.mjs github <run.json> <jobs.json> <expected-sha> [repository] [expected-run-id]",
    "  ci-preflight.mjs github-evidence <run.json> <jobs.json> <artifacts.json> <repository> <workflow-name> <workflow-path> <event> <run-id> <expected-sha> [--job=<name>] [--artifact=<name>]",
    "  ci-preflight.mjs github-commit <commit.json> <repository> <expected-sha>",
    "  ci-preflight.mjs terminal-results <results.json> <expected-sha> <run-id>",
    "  ci-preflight.mjs browser-e2e <result.json> <output.json> <expected-sha> <expected-tree> <run-id> <run-attempt> <job-id> <expected-tests>",
    "  ci-preflight.mjs source-binding <binding.json>",
    "  ci-preflight.mjs kms-qualification <evidence.json> <expected-sha> <expected-tree> <expected-deployment-digest> <expected-run-id> <expected-job-id>",
    "  ci-preflight.mjs platform-auth-qualification <evidence.json> <expected-sha> <expected-tree> <expected-primary-deployment-digest> <expected-secondary-deployment-digest> <expected-run-id> <expected-job-id>",
    "  ci-preflight.mjs external-qualification <evidence.json> <binding.json>",
    "  ci-preflight.mjs secret-scan <path> [path ...]",
    "  ci-preflight.mjs artifact-scan <root> <output> [--exclude=<relative-path>]"
  ].join("\n");
}

export async function runCli(argv = process.argv.slice(2)) {
  const [command, ...args] = argv;
  if (!command) throw new CiPreflightError(usage());
  if (command === "github") {
    if (args.length < 3 || args.length > 5) throw new CiPreflightError(usage());
    const run = readJson(args[0]);
    const jobsEnvelope = readJson(args[1]);
    if (!plainObject(jobsEnvelope) || !Array.isArray(jobsEnvelope.jobs) || !Number.isSafeInteger(jobsEnvelope.total_count)) throw new CiPreflightError("GitHub jobs response must include an exact total_count");
    return assertGithubCiRun(run, jobsEnvelope.jobs, { expectedSha: args[2], repository: args[3], expectedRunId: args[4], jobsTotalCount: jobsEnvelope.total_count });
  }
  if (command === "github-evidence") {
    if (args.length < 9 || args.slice(9).some((value) => !value.startsWith("--job=") && !value.startsWith("--artifact="))) throw new CiPreflightError(usage());
    const run = readJson(args[0]);
    const jobsEnvelope = readJson(args[1]);
    const artifactsEnvelope = readJson(args[2]);
    if (!plainObject(jobsEnvelope) || !Number.isSafeInteger(jobsEnvelope.total_count)) throw new CiPreflightError("GitHub jobs response must include an exact total_count");
    if (!plainObject(artifactsEnvelope) || !Number.isSafeInteger(artifactsEnvelope.total_count)) throw new CiPreflightError("GitHub artifacts response must include an exact total_count");
    const jobNames = args.slice(9).filter((value) => value.startsWith("--job=")).map((value) => value.slice("--job=".length));
    const artifactNames = args.slice(9).filter((value) => value.startsWith("--artifact=")).map((value) => value.slice("--artifact=".length));
    return assertGithubWorkflowEvidence(run, jobsEnvelope, artifactsEnvelope, {
      repository: args[3], workflowName: args[4], workflowPath: args[5], expectedEvent: args[6], expectedRunId: args[7], expectedSha: args[8],
      expectedJobNames: jobNames, expectedArtifactNames: artifactNames
    });
  }
  if (command === "github-commit") {
    if (args.length !== 3) throw new CiPreflightError(usage());
    return assertGithubCommit(readJson(args[0]), { repository: args[1], expectedSha: args[2] });
  }
  if (command === "terminal-results") {
    if (args.length !== 3) throw new CiPreflightError(usage());
    return { terminal_results: assertTerminalResults(readJson(args[0]), { expectedSha: args[1], expectedRunId: args[2] }) };
  }
  if (command === "browser-e2e") {
    if (args.length !== 8) throw new CiPreflightError(usage());
    const evidence = assertBrowserE2eEvidence(readJson(args[0]), {
      expectedSourceCommit: args[2],
      expectedSourceTree: args[3],
      expectedRunId: args[4],
      expectedRunAttempt: args[5],
      expectedJobId: args[6],
      expectedTests: Number(args[7])
    });
    fs.writeFileSync(path.resolve(args[1]), canonicalJson(evidence), { flag: "wx", mode: 0o600 });
    return evidence;
  }
  if (command === "source-binding") {
    if (args.length !== 1) throw new CiPreflightError(usage());
    return assertSourceBinding(readJson(args[0]));
  }
  if (command === "kms-qualification") {
    if (args.length !== 6) throw new CiPreflightError(usage());
    return assertCloudSignerKmsQualified(readCanonicalJson(args[0]), {
      expectedSourceCommit: args[1], expectedSourceTree: args[2], expectedDeploymentDigest: args[3], expectedRunId: args[4], expectedJobId: args[5]
    });
  }
  if (command === "platform-auth-qualification") {
    if (args.length !== 7) throw new CiPreflightError(usage());
    return assertPlatformAuthQualified(readCanonicalJson(args[0]), {
      expectedSourceCommit: args[1], expectedSourceTree: args[2],
      expectedDeploymentDigests: { primary: args[3], secondary: args[4] }, expectedRunId: args[5], expectedJobId: args[6]
    });
  }
  if (command === "external-qualification") {
    if (args.length !== 2) throw new CiPreflightError(usage());
    const binding = readJson(args[1]);
    if (!plainObject(binding)) throw new CiPreflightError("external qualification binding must be an object");
    assertExactKeys(binding, [
      "repository", "source_commit", "source_tree", "release_artifact_sha256", "ci_run_id", "ci_run_attempt", "gate_artifacts", "gate_job_ids"
    ], "external qualification binding");
    return assertExternalQualificationEvidence(readCanonicalJson(args[0]), {
      expectedRepository: binding.repository,
      expectedSourceCommit: binding.source_commit,
      expectedSourceTree: binding.source_tree,
      expectedReleaseArtifactSha256: binding.release_artifact_sha256,
      expectedCiRunId: binding.ci_run_id,
      expectedCiRunAttempt: binding.ci_run_attempt,
      expectedGateArtifacts: binding.gate_artifacts,
      expectedGateJobIds: binding.gate_job_ids
    });
  }
  if (command === "secret-scan") {
    if (args.length < 1) throw new CiPreflightError(usage());
    return scanProtectedArtifacts(args);
  }
  if (command === "artifact-scan") {
    if (args.length < 2 || args.some((value, index) => index >= 2 && !value.startsWith("--exclude="))) throw new CiPreflightError(usage());
    const root = args[0];
    const output = args[1];
    const exclude = args.slice(2).map((value) => value.slice("--exclude=".length));
    const evidence = scanReleaseArtifacts(root, { exclude });
    fs.writeFileSync(path.resolve(output), canonicalJson(evidence), { flag: "wx", mode: 0o644 });
    return evidence;
  }
  throw new CiPreflightError(`unknown ci preflight command: ${command}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  runCli().then((result) => {
    process.stdout.write(`${canonicalJson(result)}\n`);
  }).catch((error) => {
    process.stderr.write(`ci preflight failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
