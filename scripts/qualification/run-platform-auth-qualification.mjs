#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { runPlatformAuthQualification, verifyPlatformAuthQualificationEvidence } from "./platform-auth.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;

export class PlatformAuthQualificationRunnerError extends Error {
  constructor(message) { super(message); this.name = "PlatformAuthQualificationRunnerError"; }
}

function required(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new PlatformAuthQualificationRunnerError(`${name} is missing or invalid`);
  return value;
}

function adapterFile(env) {
  const absolute = path.resolve(required(env, "AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_MODULE", /^[^\0]+$/u));
  const expectedDigest = required(env, "AGENTPASS_PLATFORM_AUTH_PROVIDER_ADAPTER_SHA256", DIGEST);
  let fd;
  try {
    fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1) throw new PlatformAuthQualificationRunnerError("Platform Auth adapter must be a single-link regular file");
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.ino !== after.ino || before.dev !== after.dev) throw new PlatformAuthQualificationRunnerError("Platform Auth adapter changed while reading");
    if (crypto.createHash("sha256").update(bytes).digest("hex") !== expectedDigest) throw new PlatformAuthQualificationRunnerError("Platform Auth adapter digest is mismatched");
    return Object.freeze({ absolute, expectedDigest });
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

async function loadAdapter(env) {
  const file = adapterFile(env);
  const loaded = await import(pathToFileURL(file.absolute).href);
  const adapter = typeof loaded.createProviderAdapter === "function"
    ? await loaded.createProviderAdapter({ env: Object.freeze({ ...env }) })
    : (loaded.providerAdapter ?? loaded.default);
  if (!adapter || typeof adapter !== "object") throw new PlatformAuthQualificationRunnerError("Platform Auth adapter export is missing");
  adapterFile(env);
  return Object.freeze({ adapter, sha256: file.expectedDigest });
}

export async function runExternalPlatformAuthQualification({ env = process.env } = {}) {
  if (env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENABLED !== "true"
    || env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EXECUTION !== "external"
    || env.AGENTPASS_PLATFORM_AUTH_QUALIFICATION_REAL_EXECUTION !== "true") {
    throw new PlatformAuthQualificationRunnerError("external Platform Auth qualification mode is not enabled");
  }
  const runner = required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (LOCAL_MARKER.test(runner)) throw new PlatformAuthQualificationRunnerError("Platform Auth qualification runner is not external");
  const binding = {
    source_commit: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SOURCE_TREE", SHA),
    primary_deployment_digest: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST", DIGEST),
    secondary_deployment_digest: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST", DIGEST),
    ci_run_id: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_CI_RUN_ID", RUN_ID),
    ci_run_attempt: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_CI_RUN_ATTEMPT", RUN_ID),
    qualification_run_id: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ID", RUN_ID),
    qualification_run_attempt: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    qualification_job_id: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_JOB_ID", RUN_ID),
    environment_id: required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_ENVIRONMENT_ID", IDENTIFIER),
  };
  if (binding.ci_run_id === binding.qualification_run_id) throw new PlatformAuthQualificationRunnerError("canonical CI and qualification runs must be distinct");
  const output = path.resolve(required(env, "AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new PlatformAuthQualificationRunnerError("Platform Auth qualification evidence target already exists");
  const loadedAdapter = await loadAdapter(env);
  const report = await runPlatformAuthQualification({
    env: {
      ...env,
      AGENTPASS_PLATFORM_AUTH_QUALIFICATION_RUN_ID: binding.qualification_run_id,
      AGENTPASS_PLATFORM_AUTH_QUALIFICATION_JOB_ID: binding.qualification_job_id,
      AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EXECUTION: "external",
      AGENTPASS_PLATFORM_AUTH_QUALIFICATION_REAL_EXECUTION: "true"
    },
    sourceCommit: binding.source_commit,
    sourceTree: binding.source_tree,
    expectedDeploymentDigests: { primary: binding.primary_deployment_digest, secondary: binding.secondary_deployment_digest },
    runId: binding.qualification_run_id,
    jobId: binding.qualification_job_id,
    providerAdapter: loadedAdapter.adapter,
  });
  if (report.status !== "passed" || report.qualified !== true) throw new PlatformAuthQualificationRunnerError("Platform Auth qualification did not pass");
  const outputReport = {
    ...report,
    ci_run_id: binding.ci_run_id,
    ci_run_attempt: binding.ci_run_attempt,
    qualification_run_id: binding.qualification_run_id,
    qualification_run_attempt: binding.qualification_run_attempt,
    qualification_job_id: binding.qualification_job_id,
    execution: {
      kind: "external_runner",
      real_execution: true,
      runner_id: runner,
      run_id: binding.qualification_run_id,
      job_id: binding.qualification_job_id,
      run_attempt: binding.qualification_run_attempt,
      source_commit: binding.source_commit,
      source_tree: binding.source_tree,
      ci_run_id: binding.ci_run_id,
      ci_run_attempt: binding.ci_run_attempt,
      qualification_run_id: binding.qualification_run_id,
      qualification_run_attempt: binding.qualification_run_attempt,
      qualification_job_id: binding.qualification_job_id,
      started_at: report.started_at,
      completed_at: report.completed_at,
      environment: { kind: "platform_auth", identity: binding.environment_id }
    }
  };
  verifyPlatformAuthQualificationEvidence(canonicalJson(outputReport), {
    expectedSourceCommit: binding.source_commit,
    expectedSourceTree: binding.source_tree,
    expectedDeploymentDigests: { primary: binding.primary_deployment_digest, secondary: binding.secondary_deployment_digest },
    expectedRunId: binding.qualification_run_id,
    expectedJobId: binding.qualification_job_id,
    expectedRunAttempt: binding.qualification_run_attempt,
    expectedCiRunId: binding.ci_run_id,
    expectedCiRunAttempt: binding.ci_run_attempt,
    requireExternalExecution: true
  });
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, `${canonicalJson(outputReport)}\n`, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return Object.freeze({ status: "passed", qualified: true, evidence_path: output, adapter_sha256: loadedAdapter.sha256, source_commit: binding.source_commit, ci_run_id: binding.ci_run_id, ci_run_attempt: binding.ci_run_attempt, qualification_run_id: binding.qualification_run_id, qualification_run_attempt: binding.qualification_run_attempt, qualification_job_id: binding.qualification_job_id });
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  runExternalPlatformAuthQualification().then((result) => process.stdout.write(`${canonicalJson(result)}\n`)).catch((error) => {
    process.stderr.write(`external Platform Auth qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
