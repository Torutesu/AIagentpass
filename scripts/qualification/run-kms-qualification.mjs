#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { runCloudSignerKmsQualification, verifyCloudSignerKmsQualificationEvidence } from "./cloud-signer-kms.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;

export class KmsQualificationRunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = "KmsQualificationRunnerError";
  }
}

function required(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new KmsQualificationRunnerError(`${name} is missing or invalid`);
  return value;
}

function binding(env) {
  const runner = required(env, "AGENTPASS_KMS_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (LOCAL_MARKER.test(runner)) throw new KmsQualificationRunnerError("KMS qualification runner is not external");
  return Object.freeze({
    source_commit: required(env, "AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE", SHA),
    deployment_digest: required(env, "AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST", DIGEST),
    artifact_sha256: required(env, "AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
    run_id: required(env, "AGENTPASS_KMS_QUALIFICATION_RUN_ID", RUN_ID),
    job_id: required(env, "AGENTPASS_KMS_QUALIFICATION_JOB_ID", RUN_ID),
    runner_id: runner,
  });
}

function adapterFile(env) {
  const modulePath = required(env, "AGENTPASS_KMS_PROVIDER_ADAPTER_MODULE", /^[^\0]+$/u);
  const expectedDigest = required(env, "AGENTPASS_KMS_PROVIDER_ADAPTER_SHA256", DIGEST);
  const absolute = path.resolve(modulePath);
  let fd;
  try {
    fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1) throw new KmsQualificationRunnerError("KMS provider adapter must be a single-link regular file");
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.ino !== after.ino || before.dev !== after.dev) throw new KmsQualificationRunnerError("KMS provider adapter changed while reading");
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    if (digest !== expectedDigest) throw new KmsQualificationRunnerError("KMS provider adapter digest is mismatched");
    return Object.freeze({ absolute, expectedDigest });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

async function loadAdapter(env) {
  const file = adapterFile(env);
  const loaded = await import(pathToFileURL(file.absolute).href);
  const adapter = typeof loaded.createProviderAdapter === "function"
    ? await loaded.createProviderAdapter({ env: Object.freeze({ ...env }) })
    : (loaded.providerAdapter ?? loaded.default);
  if (!adapter || typeof adapter !== "object") throw new KmsQualificationRunnerError("KMS provider adapter export is missing");
  const after = adapterFile(env);
  if (after.expectedDigest !== file.expectedDigest) throw new KmsQualificationRunnerError("KMS provider adapter binding changed");
  return Object.freeze({ adapter, sha256: file.expectedDigest });
}

export async function runExternalKmsQualification({ env = process.env } = {}) {
  if (env.AGENTPASS_KMS_QUALIFICATION_ENABLED !== "true" || env.AGENTPASS_KMS_QUALIFICATION_EXECUTION !== "external" || env.AGENTPASS_KMS_QUALIFICATION_REAL_EXECUTION !== "true") {
    throw new KmsQualificationRunnerError("external KMS qualification mode is not enabled");
  }
  const expected = binding(env);
  const output = path.resolve(required(env, "AGENTPASS_KMS_QUALIFICATION_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new KmsQualificationRunnerError("KMS qualification evidence target already exists");
  const loadedAdapter = await loadAdapter(env);
  const reportEnv = {
    ...env,
    AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT: expected.source_commit,
    AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE: expected.source_tree,
    AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST: expected.deployment_digest,
    AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256: expected.artifact_sha256,
    AGENTPASS_KMS_QUALIFICATION_RUN_ID: expected.run_id,
    AGENTPASS_KMS_QUALIFICATION_JOB_ID: expected.job_id,
    AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: expected.runner_id,
  };
  const report = await runCloudSignerKmsQualification({ env: reportEnv, providerAdapter: loadedAdapter.adapter });
  const text = canonicalJson(report);
  if (report.status !== "passed" || report.qualified !== true) throw new KmsQualificationRunnerError("KMS qualification did not pass");
  verifyCloudSignerKmsQualificationEvidence(text, expected);
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, text, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return Object.freeze({ status: "passed", qualified: true, evidence_path: output, adapter_sha256: loadedAdapter.sha256, source_commit: expected.source_commit, run_id: expected.run_id, job_id: expected.job_id, artifact_sha256: expected.artifact_sha256 });
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  runExternalKmsQualification().then((result) => process.stdout.write(`${canonicalJson(result)}\n`)).catch((error) => {
    process.stderr.write(`external KMS qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
