#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { identityAttestationNonce, runCloudSignerKmsQualification, verifyCloudSignerKmsQualificationEvidence } from "./cloud-signer-kms.mjs";
import {
  identityBindingDigest,
  normalizeKmsProviderIdentityAttestorTrustInputs,
  verifyKmsProviderIdentityAttestation
} from "./kms-provider-identity-attestation.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;
const ATTESTOR_KEYS_ENV = "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTOR_PUBLIC_KEYS";
const IDENTITY_ATTESTATION_TRUST_ENV = "AGENTPASS_KMS_QUALIFICATION_IDENTITY_ATTESTATION_TRUST";

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
  const value = {
    source_commit: required(env, "AGENTPASS_KMS_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_KMS_QUALIFICATION_SOURCE_TREE", SHA),
    deployment_digest: required(env, "AGENTPASS_KMS_QUALIFICATION_DEPLOYMENT_DIGEST", DIGEST),
    artifact_sha256: required(env, "AGENTPASS_KMS_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
    ci_run_id: required(env, "AGENTPASS_KMS_QUALIFICATION_CI_RUN_ID", RUN_ID),
    ci_run_attempt: required(env, "AGENTPASS_KMS_QUALIFICATION_CI_RUN_ATTEMPT", RUN_ID),
    qualification_run_id: required(env, "AGENTPASS_KMS_QUALIFICATION_RUN_ID", RUN_ID),
    qualification_run_attempt: required(env, "AGENTPASS_KMS_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    qualification_job_id: required(env, "AGENTPASS_KMS_QUALIFICATION_JOB_ID", RUN_ID),
    runner_id: runner,
  };
  if (value.ci_run_id === value.qualification_run_id) throw new KmsQualificationRunnerError("canonical CI and qualification runs must be distinct");
  return Object.freeze(value);
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

export function verifyProviderIdentityAttestations(report, expectedBindings, env) {
  let trusted;
  try {
    trusted = normalizeKmsProviderIdentityAttestorTrustInputs({
      identityAttestationTrust: env[IDENTITY_ATTESTATION_TRUST_ENV],
      attestorPublicKeys: env[ATTESTOR_KEYS_ENV],
      expectedProviders: new Set(Object.values(expectedBindings).map((item) => item.provider))
    });
  } catch {
    throw new KmsQualificationRunnerError("KMS provider identity attestor keys are missing or invalid");
  }
  if (trusted === null) throw new KmsQualificationRunnerError("KMS provider identity attestor keys are missing or invalid");
  const byProvider = new Map();
  for (const identity of report.provider_identities) {
    if (byProvider.has(identity.provider) || !identity.attestation) throw new KmsQualificationRunnerError("KMS provider identity attestation is missing");
    const key = trusted[identity.provider];
    if (!key) throw new KmsQualificationRunnerError("KMS provider identity attestor key is missing");
    const resources = report.purpose_bindings.filter((item) => item.provider === identity.provider).map((item) => item.provider_resource_id).sort();
    const digest = identityBindingDigest({
      source_commit: report.source_commit, source_tree: report.source_tree, deployment_digest: report.deployment_digest,
      artifact_sha256: report.artifact_sha256, run_id: report.run_id, job_id: report.job_id,
      provider: identity.provider, account_or_project: identity.account_or_project, identity: identity.identity,
      identity_fingerprint: identity.identity_fingerprint, region: identity.region, resource_ids: resources
    });
    if (identity.attestation.provider !== identity.provider
      || identity.attestation.account_or_project !== identity.account_or_project
      || identity.attestation.identity !== identity.identity
      || identity.attestation.identity_fingerprint !== identity.identity_fingerprint
      || identity.attestation.region !== identity.region
      || JSON.stringify([...identity.attestation.resource_ids].sort()) !== JSON.stringify(resources)
      || identity.observed_at !== identity.attestation.challenge?.issued_at) {
      throw new KmsQualificationRunnerError("KMS provider identity attestation target is mismatched");
    }
    const qualificationBinding = {
      source_commit: report.source_commit,
      source_tree: report.source_tree,
      deployment_digest: report.deployment_digest,
      artifact_sha256: report.artifact_sha256,
      run_id: report.run_id,
      job_id: report.job_id
    };
    const verified = verifyKmsProviderIdentityAttestation(identity.attestation, {
      trustedPublicKey: Buffer.from(key.public_key_der_base64url, "base64url"),
      expectedNonce: identityAttestationNonce(identity.provider, qualificationBinding),
      expectedBindingDigest: digest,
      // The identity proof is collected and verified at qualification start.
      // Do not re-evaluate its five-minute TTL after the long KMS matrix has
      // completed; the signature and binding remain independently checked.
      now: Date.parse(report.started_at)
    });
    if (key.key_id !== verified.attestor_key_id || key.public_key_fingerprint !== verified.attestor_public_key_fingerprint) throw new KmsQualificationRunnerError("KMS provider identity attestor trust binding is mismatched");
    byProvider.set(identity.provider, verified);
  }
  const expectedProviders = new Set(Object.values(expectedBindings).map((item) => item.provider));
  if (byProvider.size !== expectedProviders.size || [...expectedProviders].some((provider) => !byProvider.has(provider))) throw new KmsQualificationRunnerError("KMS provider identity attestation set is incomplete");
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
    AGENTPASS_KMS_QUALIFICATION_RUN_ID: expected.qualification_run_id,
    AGENTPASS_KMS_QUALIFICATION_RUN_ATTEMPT: expected.qualification_run_attempt,
    AGENTPASS_KMS_QUALIFICATION_JOB_ID: expected.qualification_job_id,
    AGENTPASS_KMS_QUALIFICATION_RUNNER_ID: expected.runner_id,
  };
  const report = await runCloudSignerKmsQualification({ env: reportEnv, providerAdapter: loadedAdapter.adapter });
  if (report.status !== "passed" || report.qualified !== true) throw new KmsQualificationRunnerError("KMS qualification did not pass");
  verifyProviderIdentityAttestations(report, expectedProviderBindingsFromReport(report), env);
  verifyCloudSignerKmsQualificationEvidence(canonicalJson(report), { ...expected, expectedRunId: expected.qualification_run_id, expectedJobId: expected.qualification_job_id });
  const outputReport = {
    ...report,
    ci_run_id: expected.ci_run_id,
    ci_run_attempt: expected.ci_run_attempt,
    qualification_run_id: expected.qualification_run_id,
    qualification_run_attempt: expected.qualification_run_attempt,
    qualification_job_id: expected.qualification_job_id
  };
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, `${canonicalJson(outputReport)}\n`, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return Object.freeze({ status: "passed", qualified: true, evidence_path: output, adapter_sha256: loadedAdapter.sha256, source_commit: expected.source_commit, ci_run_id: expected.ci_run_id, ci_run_attempt: expected.ci_run_attempt, qualification_run_id: expected.qualification_run_id, qualification_run_attempt: expected.qualification_run_attempt, qualification_job_id: expected.qualification_job_id, artifact_sha256: expected.artifact_sha256 });
}

function expectedProviderBindingsFromReport(report) {
  return Object.fromEntries(report.purpose_bindings.map((item) => [item.name, item]));
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  runExternalKmsQualification().then((result) => process.stdout.write(`${canonicalJson(result)}\n`)).catch((error) => {
    process.stderr.write(`external KMS qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
