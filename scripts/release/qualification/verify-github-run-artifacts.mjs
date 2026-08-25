#!/usr/bin/env node
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,18}$/u;
const ARTIFACT_ID = /^[1-9][0-9]{0,18}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const API_ORIGIN = "https://api.github.com";

export const QUALIFICATION_WORKFLOWS = Object.freeze({
  cloud: Object.freeze({
    name: "Cloud production qualification",
    path: ".github/workflows/cloud-production-qualification.yml",
    jobs: Object.freeze(["qualify"]),
    artifactName: (sourceSha) => `cloud-production-qualification-${sourceSha}`,
    outputName: "cloud-production-qualification"
  }),
  macos: Object.freeze({
    name: "macOS hardware qualification evidence",
    path: ".github/workflows/macos-hardware-qualification.yml",
    jobs: Object.freeze(["arm64", "x86_64"]),
    artifactNames: (sourceSha) => Object.freeze([
      `macos-hardware-qualification-arm64-${sourceSha}`,
      `macos-hardware-qualification-x86_64-${sourceSha}`
    ]),
    outputNames: Object.freeze(["macos-hardware-qualification-arm64", "macos-hardware-qualification-x86_64"])
  })
});

function fail(message) {
  throw new Error(message);
}

function readJson(value, label) {
  try {
    return JSON.parse(value);
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

function requireString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} is invalid`);
  return value;
}

function requireRunId(value, label) {
  return requireString(String(value), RUN_ID, label);
}

function validateCollection(value, field, label) {
  if (value === null || typeof value !== "object" || !Array.isArray(value[field])) fail(`${label}.${field} is missing`);
  return value[field];
}

export function validateWorkflowRun(run, { repository, runId, sourceSha, workflow }) {
  if (run === null || typeof run !== "object" || Array.isArray(run)) fail("workflow run must be an object");
  requireRunId(runId, "workflow run ID");
  if (String(run.id) !== String(runId)) fail("workflow run ID does not match the requested run");
  if (run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) fail("workflow run repository identity is not canonical");
  if (run.name !== workflow.name || run.path !== workflow.path) fail("workflow run workflow identity is not exact");
  if (run.event !== "workflow_dispatch" || run.status !== "completed" || run.conclusion !== "success" || run.head_branch !== "main") fail("workflow run is not a successful protected dispatch");
  if (run.head_sha !== sourceSha) fail("workflow run source SHA does not match the release source SHA");
  return Object.freeze({ id: String(run.id), head_sha: run.head_sha, name: run.name, path: run.path });
}

export function validateSuccessfulJobs(jobsResponse, { runId, workflow }) {
  const jobs = validateCollection(jobsResponse, "jobs", "jobs response");
  if (jobsResponse.total_count !== undefined && jobsResponse.total_count !== jobs.length) fail("jobs response is incomplete or paginated");
  const results = [];
  for (const expectedName of workflow.jobs) {
    const matches = jobs.filter((job) => job?.name === expectedName);
    if (matches.length !== 1) fail(`required qualification job is missing or duplicated: ${expectedName}`);
    const [job] = matches;
    if (job === null || typeof job !== "object" || Array.isArray(job)) fail("qualification job must be an object");
    if (String(job.run_id) !== String(runId) || !ARTIFACT_ID.test(String(job.id)) || job.status !== "completed" || job.conclusion !== "success") fail(`qualification job is not successful: ${expectedName}`);
    results.push(Object.freeze({ id: String(job.id), name: job.name }));
  }
  return Object.freeze(results);
}

function expectedArchiveUrl(repository, artifactId) {
  return `${API_ORIGIN}/repos/${repository}/actions/artifacts/${artifactId}/zip`;
}

export function verifyDownloadedArtifactDigest(bytes, expectedDigest) {
  requireString(expectedDigest, DIGEST, "qualification artifact digest");
  const actualDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (actualDigest !== expectedDigest) fail("downloaded qualification artifact digest mismatch");
  return actualDigest;
}

export function validateArtifact(artifactsResponse, { repository, runId, name, outputName }) {
  const artifacts = validateCollection(artifactsResponse, "artifacts", "artifacts response");
  if (artifactsResponse.total_count !== undefined && artifactsResponse.total_count !== artifacts.length) fail("artifacts response is incomplete or paginated");
  const matches = artifacts.filter((artifact) => artifact?.name === name);
  if (matches.length !== 1) fail(`required qualification artifact is missing or duplicated: ${name}`);
  const artifact = matches[0];
  if (artifact === null || typeof artifact !== "object" || Array.isArray(artifact)) fail("qualification artifact must be an object");
  const artifactId = requireString(String(artifact.id), ARTIFACT_ID, "qualification artifact ID");
  if (artifact.expired !== false || String(artifact.workflow_run?.id) !== String(runId)) fail(`qualification artifact is not live and bound to the selected run: ${name}`);
  requireString(artifact.digest, DIGEST, "qualification artifact digest");
  if (!Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes <= 0) fail(`qualification artifact size is invalid: ${name}`);
  if (artifact.archive_download_url !== expectedArchiveUrl(repository, artifactId)) fail(`qualification artifact download URL is not canonical: ${name}`);
  if (!SAFE_NAME.test(outputName) || outputName !== path.basename(outputName)) fail("qualification evidence output name is unsafe");
  return Object.freeze({
    id: artifactId,
    name: artifact.name,
    digest: artifact.digest,
    size_in_bytes: artifact.size_in_bytes,
    archive_download_url: artifact.archive_download_url,
    outputName
  });
}

export function validateQualificationMetadata({ repository, sourceSha, cloud, macos }) {
  requireString(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u, "repository");
  requireString(sourceSha, COMMIT_SHA, "source SHA");
  if (!cloud || !macos) fail("both Cloud and macOS qualification metadata are required");
  const cloudRunId = requireRunId(cloud.runId, "Cloud qualification run ID");
  const macosRunId = requireRunId(macos.runId, "macOS qualification run ID");
  if (new Set([cloudRunId, macosRunId]).size !== 2) fail("Cloud and macOS qualification runs must be distinct");
  const cloudWorkflow = QUALIFICATION_WORKFLOWS.cloud;
  const macosWorkflow = QUALIFICATION_WORKFLOWS.macos;
  const cloudRun = validateWorkflowRun(cloud.run, { repository, runId: cloudRunId, sourceSha, workflow: cloudWorkflow });
  const macosRun = validateWorkflowRun(macos.run, { repository, runId: macosRunId, sourceSha, workflow: macosWorkflow });
  const cloudJobs = validateSuccessfulJobs(cloud.jobs, { runId: cloudRunId, workflow: cloudWorkflow });
  const macosJobs = validateSuccessfulJobs(macos.jobs, { runId: macosRunId, workflow: macosWorkflow });
  const cloudArtifact = validateArtifact(cloud.artifacts, {
    repository,
    runId: cloudRunId,
    name: cloudWorkflow.artifactName(sourceSha),
    outputName: cloudWorkflow.outputName
  });
  const macosArtifacts = macosWorkflow.artifactNames(sourceSha).map((name, index) => validateArtifact(macos.artifacts, {
    repository,
    runId: macosRunId,
    name,
    outputName: macosWorkflow.outputNames[index]
  }));
  return Object.freeze({
    schema_version: 1,
    repository,
    source_sha: sourceSha,
    cloud: Object.freeze({ run: cloudRun, jobs: cloudJobs, artifact: cloudArtifact }),
    macos: Object.freeze({ run: macosRun, jobs: macosJobs, artifacts: Object.freeze(macosArtifacts) })
  });
}

function safeOutputDirectory(directory) {
  if (typeof directory !== "string" || directory.length === 0 || !path.isAbsolute(directory)) fail("retention directory must be absolute");
  return path.resolve(directory);
}

function runGhApi(url, outputPath) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("gh", [
      "api", "--method", "GET", "-H", "Accept: application/vnd.github+json", "--output", outputPath, url
    ], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", (error) => rejectPromise(error));
    child.once("close", (code) => code === 0 ? resolvePromise() : rejectPromise(new Error(`GitHub artifact download failed: ${stderr.trim() || `exit ${code}`}`)));
  });
}

async function retainArtifact({ artifact, run, jobs, root }) {
  const directory = path.join(root, artifact.outputName);
  if (existsSync(directory)) fail(`qualification evidence retention path already exists: ${artifact.outputName}`);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const archivePath = path.join(directory, "artifact.zip");
  await runGhApi(artifact.archive_download_url, archivePath);
  const bytes = await readFile(archivePath);
  try { verifyDownloadedArtifactDigest(bytes, artifact.digest); } catch (error) { throw new Error(`${error.message}: ${artifact.name}`); }
  await chmod(archivePath, 0o600);
  const metadataBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, "utf8");
  const workflowRunBytes = Buffer.from(`${JSON.stringify(run, null, 2)}\n`, "utf8");
  const workflowJobsBytes = Buffer.from(`${JSON.stringify(jobs, null, 2)}\n`, "utf8");
  await writeFile(path.join(directory, "artifact-metadata.json"), metadataBytes, { mode: 0o600, flag: "wx" });
  await writeFile(path.join(directory, "workflow-run.json"), workflowRunBytes, { mode: 0o600, flag: "wx" });
  await writeFile(path.join(directory, "workflow-jobs.json"), workflowJobsBytes, { mode: 0o600, flag: "wx" });
  return Object.freeze({
    name: artifact.name,
    digest: artifact.digest,
    run_id: String(run.id),
    source_sha: run.head_sha,
    archive: "artifact.zip",
    metadata_sha256: createHash("sha256").update(metadataBytes).digest("hex"),
    workflow_run_sha256: createHash("sha256").update(workflowRunBytes).digest("hex"),
    workflow_jobs_sha256: createHash("sha256").update(workflowJobsBytes).digest("hex")
  });
}

export async function retainQualificationEvidence({ metadata, raw, outputRoot }) {
  const root = safeOutputDirectory(outputRoot);
  if (existsSync(root)) fail("qualification evidence retention root already exists");
  await mkdir(root, { recursive: true, mode: 0o700 });
  const retained = {
    cloud: await retainArtifact({ artifact: metadata.cloud.artifact, run: raw.cloud.run, jobs: raw.cloud.jobs, root }),
    macos: []
  };
  for (let index = 0; index < metadata.macos.artifacts.length; index += 1) {
    retained.macos.push(await retainArtifact({ artifact: metadata.macos.artifacts[index], run: raw.macos.run, jobs: raw.macos.jobs, root }));
  }
  const report = {
    schema_version: 1,
    repository: metadata.repository,
    source_sha: metadata.source_sha,
    cloud: retained.cloud,
    macos: {
      run_id: metadata.macos.run.id,
      source_sha: metadata.source_sha,
      artifacts: retained.macos
    }
  };
  await writeFile(path.join(root, "qualification-verification.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return Object.freeze(report);
}

function parseArgs(args) {
  const values = {};
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key.startsWith("--") || index + 1 >= args.length || args[index + 1].startsWith("--")) fail("invalid arguments");
    values[key.slice(2)] = args[++index];
  }
  return values;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const required = [
    "repository", "source-sha", "cloud-run-id", "cloud-run-json", "cloud-jobs-json", "cloud-artifacts-json",
    "macos-run-id", "macos-run-json", "macos-jobs-json", "macos-artifacts-json", "retain-root"
  ];
  if (required.some((key) => !options[key]) || Object.keys(options).some((key) => !required.includes(key))) fail("invalid arguments");
  const raw = {
    cloud: {
      runId: options["cloud-run-id"],
      run: readJson(await readFile(options["cloud-run-json"], "utf8"), "Cloud run response"),
      jobs: readJson(await readFile(options["cloud-jobs-json"], "utf8"), "Cloud jobs response"),
      artifacts: readJson(await readFile(options["cloud-artifacts-json"], "utf8"), "Cloud artifacts response")
    },
    macos: {
      runId: options["macos-run-id"],
      run: readJson(await readFile(options["macos-run-json"], "utf8"), "macOS run response"),
      jobs: readJson(await readFile(options["macos-jobs-json"], "utf8"), "macOS jobs response"),
      artifacts: readJson(await readFile(options["macos-artifacts-json"], "utf8"), "macOS artifacts response")
    }
  };
  const metadata = validateQualificationMetadata({ repository: options.repository, sourceSha: options["source-sha"], cloud: raw.cloud, macos: raw.macos });
  const report = await retainQualificationEvidence({ metadata, raw, outputRoot: options["retain-root"] });
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`qualification-api: ${error.message}\n`);
    process.exitCode = 1;
  });
}
