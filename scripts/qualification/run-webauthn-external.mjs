#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { validateWebAuthnEvidence } from "./run-webauthn-e2e.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;
const EVIDENCE_KIND = "agentpass-webauthn-agent-unattended-e2e";
const REQUIRED_CHECKS = Object.freeze([
  "authenticator_origin_rp",
  "durable_one_time_consumption",
  "replay_rejection",
  "stale_context_rejection",
  "outage_fail_closed"
]);

export class WebAuthnExternalQualificationError extends Error {
  constructor(message) { super(message); this.name = "WebAuthnExternalQualificationError"; }
}

function required(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new WebAuthnExternalQualificationError(`${name} is missing or invalid`);
  return value;
}

function adapterFile(env) {
  const absolute = path.resolve(required(env, "AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_MODULE", /^[^\0]+$/u));
  const expectedDigest = required(env, "AGENTPASS_WEBAUTHN_PROVIDER_ADAPTER_SHA256", DIGEST);
  let fd;
  try {
    fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1) throw new WebAuthnExternalQualificationError("WebAuthn adapter must be a single-link regular file");
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.ino !== after.ino || before.dev !== after.dev) throw new WebAuthnExternalQualificationError("WebAuthn adapter changed while reading");
    if (crypto.createHash("sha256").update(bytes).digest("hex") !== expectedDigest) throw new WebAuthnExternalQualificationError("WebAuthn adapter digest is mismatched");
    return Object.freeze({ absolute, expectedDigest });
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

async function loadAdapter(env) {
  const file = adapterFile(env);
  const loaded = await import(pathToFileURL(file.absolute).href);
  const adapter = typeof loaded.createWebAuthnQualificationAdapter === "function"
    ? await loaded.createWebAuthnQualificationAdapter({ env: Object.freeze({ ...env }) })
    : (loaded.webAuthnQualificationAdapter ?? loaded.default);
  if (!adapter || typeof adapter !== "object" || typeof adapter.qualify !== "function") throw new WebAuthnExternalQualificationError("WebAuthn adapter must export qualify()");
  adapterFile(env);
  return Object.freeze({ adapter, sha256: file.expectedDigest });
}

function binding(env) {
  const runnerId = required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (LOCAL_MARKER.test(runnerId)) throw new WebAuthnExternalQualificationError("WebAuthn runner is not external");
  const value = {
    source_commit: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_SOURCE_TREE", SHA),
    deployment_digest: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_DEPLOYMENT_DIGEST", DIGEST),
    artifact_sha256: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
    origin: required(env, "AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN", /^https:\/\/[^\s/]+(?:\/[^\s]*)?$/u),
    rp_id: required(env, "AGENTPASS_WEBAUTHN_EXPECTED_RP_ID", /^[a-z0-9](?:[a-z0-9.-]{0,127})[a-z0-9]$/u),
    ci_run_id: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_CI_RUN_ID", RUN_ID),
    ci_run_attempt: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_CI_RUN_ATTEMPT", RUN_ID),
    qualification_run_id: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_RUN_ID", RUN_ID),
    qualification_run_attempt: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    qualification_job_id: required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_JOB_ID", RUN_ID),
    runner_id: runnerId
  };
  if (value.ci_run_id === value.qualification_run_id) throw new WebAuthnExternalQualificationError("canonical CI and qualification runs must be distinct");
  return Object.freeze(value);
}

function validateAdapterEvidence(evidence, expected) {
  const validationEnv = {
    AGENTPASS_QUALIFICATION_RUNNER_ID: expected.runner_id,
    AGENTPASS_QUALIFICATION_RUN_ID: expected.qualification_run_id,
    AGENTPASS_QUALIFICATION_JOB_ID: expected.qualification_job_id,
    AGENTPASS_QUALIFICATION_RUN_ATTEMPT: expected.qualification_run_attempt,
    GITHUB_SHA: expected.source_commit,
    AGENTPASS_SOURCE_TREE: expected.source_tree,
    AGENTPASS_QUALIFICATION_ARTIFACT_SHA256: expected.artifact_sha256,
    AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN: expected.origin,
    AGENTPASS_WEBAUTHN_EXPECTED_RP_ID: expected.rp_id
  };
  const normalized = validateWebAuthnEvidence(evidence, validationEnv);
  if (normalized.execution.environment.identity !== expected.deployment_digest) throw new WebAuthnExternalQualificationError("WebAuthn evidence deployment identity is mismatched");
  return normalized;
}

export async function runExternalWebAuthnQualification({ env = process.env } = {}) {
  if (env.AGENTPASS_WEBAUTHN_QUALIFICATION_ENABLED !== "true"
    || env.AGENTPASS_WEBAUTHN_QUALIFICATION_EXECUTION !== "external"
    || env.AGENTPASS_WEBAUTHN_QUALIFICATION_REAL_EXECUTION !== "true") {
    throw new WebAuthnExternalQualificationError("external WebAuthn qualification mode is not enabled");
  }
  const expected = binding(env);
  const output = path.resolve(required(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new WebAuthnExternalQualificationError("WebAuthn evidence target already exists");
  const loaded = await loadAdapter(env);
  const evidence = await loaded.adapter.qualify(Object.freeze({
    source_commit: expected.source_commit,
    source_tree: expected.source_tree,
    deployment_digest: expected.deployment_digest,
    artifact_sha256: expected.artifact_sha256,
    run_id: expected.qualification_run_id,
    run_attempt: expected.qualification_run_attempt,
    job_id: expected.qualification_job_id
  }));
  const normalized = validateAdapterEvidence(evidence, expected);
  const outputEvidence = {
    ...normalized,
    execution: {
      ...normalized.execution,
      ci_run_id: expected.ci_run_id,
      ci_run_attempt: expected.ci_run_attempt,
      qualification_run_id: expected.qualification_run_id,
      qualification_run_attempt: expected.qualification_run_attempt,
      qualification_job_id: expected.qualification_job_id
    }
  };
  const text = canonicalJson(outputEvidence);
  if (normalized.kind !== EVIDENCE_KIND || normalized.required_checks.join("|") !== REQUIRED_CHECKS.join("|") || normalized.status !== "passed" || normalized.qualified !== true) throw new WebAuthnExternalQualificationError("WebAuthn adapter did not produce a complete passing result");
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, `${text}\n`, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return Object.freeze({ status: "passed", qualified: true, evidence_path: output, adapter_sha256: loaded.sha256, source_commit: expected.source_commit, ci_run_id: expected.ci_run_id, ci_run_attempt: expected.ci_run_attempt, qualification_run_id: expected.qualification_run_id, qualification_run_attempt: expected.qualification_run_attempt, qualification_job_id: expected.qualification_job_id, deployment_digest: expected.deployment_digest });
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  runExternalWebAuthnQualification().then((result) => process.stdout.write(`${canonicalJson(result)}\n`)).catch((error) => {
    process.stderr.write(`external WebAuthn qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
