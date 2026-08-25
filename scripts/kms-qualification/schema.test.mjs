import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

import {
  KMS_QUALIFICATION_PURPOSES,
  KMS_QUALIFICATION_SIGNATURE_DOMAIN,
  KmsQualificationEvidenceError,
  buildKmsQualificationReport,
  canonicalJson,
  parseKmsQualificationReport,
  resolveKmsQualificationSourceCommit,
  serializeKmsQualificationReport,
  scanForForbiddenEvidence,
  signatureInputBytes,
  verifyKmsQualificationReport,
  writeKmsQualificationReport
} from "./schema.mjs";

const root = path.resolve(import.meta.dirname, "../..");
const now = "2026-08-17T12:00:00.000Z";
const imageDigest = `sha256:${"1".repeat(64)}`;
const configDigest = `sha256:${"2".repeat(64)}`;
const evidenceDigest = `sha256:${"3".repeat(64)}`;
const requestDigest = `sha256:${"4".repeat(64)}`;
const signatureDigest = `sha256:${"5".repeat(64)}`;
const qualificationEvidenceKey = crypto.generateKeyPairSync("ed25519");
const qualificationEvidencePublicKeyDer = qualificationEvidenceKey.publicKey.export({ type: "spki", format: "der" });
const qualificationEvidenceKeyId = "qualification-evidence-2026-08";
const uuids = [
  "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004",
  "00000000-0000-4000-8000-000000000005", "00000000-0000-4000-8000-000000000006",
  "00000000-0000-4000-8000-000000000007", "00000000-0000-4000-8000-000000000008"
];

function digest(seed) {
  return `sha256:${crypto.createHash("sha256").update(seed).digest("hex")}`;
}

function baseInput({ provider = "aws", mode = "mock", production = false } = {}) {
  const sourceCommit = resolveKmsQualificationSourceCommit(root);
  const credentialSource = mode === "mock" ? "test_fixture" : `${provider}_workload_identity`;
  const bindings = KMS_QUALIFICATION_PURPOSES.map(({ name, purpose }, index) => {
    const registry = Object.values(requireRegistry()).find((entry) => entry.name === name);
    const resource = provider === "aws"
      ? `arn:aws:kms:ap-northeast-1:123456789012:key/${uuids[index]}`
      : `projects/agentpass-demo/locations/asia-northeast1/keyRings/agentpass/cryptoKeys/${name}/cryptoKeyVersions/7`;
    return {
      name,
      purpose,
      provider,
      registry_version: registry.registry_version,
      protocol_version: registry.protocol_version,
      signing_version: registry.signing_version,
      algorithm: "ed25519",
      key_id: `${name}-2026-08`,
      key_resource: resource,
      key_version: "7",
      public_key_fingerprint: index.toString(16).padStart(64, "0"),
      lifecycle_epoch: 2,
      protection: {
        level: "HSM",
        non_exportable: true,
        key_usage: "sign_verify",
        evidence_source: mode === "mock" ? "test_fixture" : `${provider}.kms_api`,
        evidence_digest: digest(`protection:${purpose}`),
        observed_at: now
      },
      sign_verify: {
        status: "passed",
        verified: true,
        request_digest: digest(`request:${purpose}`),
        signature_digest: digest(`signature:${purpose}`),
        evidence_digest: digest(`sign-verify:${purpose}`),
        observed_at: now
      }
    };
  });
  const iamMatrix = [];
  for (const requester of KMS_QUALIFICATION_PURPOSES) for (const target of KMS_QUALIFICATION_PURPOSES) {
    const expected = requester.purpose === target.purpose ? "allow" : "deny";
    iamMatrix.push({
      requester_purpose: requester.purpose,
      target_purpose: target.purpose,
      action: "sign",
      expected,
      observed: expected,
      status: "passed",
      request_digest: digest(`iam-request:${requester.purpose}:${target.purpose}`),
      evidence_digest: digest(`iam-evidence:${requester.purpose}:${target.purpose}`),
      observed_at: now
    });
  }
  const scenarioExpectation = {
    rotation: "new_version_only",
    disable: "disabled_rejected",
    outage: "fail_closed",
    throttle: "bounded_retry",
    response_loss: "reconcile_without_resign"
  };
  const scenarios = [];
  for (const { purpose } of KMS_QUALIFICATION_PURPOSES) for (const [scenario, expected] of Object.entries(scenarioExpectation)) scenarios.push({
    purpose,
    scenario,
    status: "passed",
    expected,
    observed: expected,
    previous_key_version: scenario === "rotation" ? "6" : null,
    current_key_version: scenario === "rotation" ? "7" : null,
    provider_invocations: scenario === "response_loss" ? 1 : 2,
    client_retries: scenario === "throttle" ? 2 : 0,
    replay_safe: true,
    evidence_digest: digest(`scenario:${purpose}:${scenario}`),
    observed_at: now
  });
  return {
    provider,
    production,
    evidence_origin: mode,
    source: { source_commit: sourceCommit, image_digest: imageDigest, config_digest: configDigest },
    execution: {
      run_id: "kms-qualification-2026-08",
      mode,
      credential_source: credentialSource,
      zero_skip: true,
      skip_count: 0,
      instance_count: 2,
      started_at: now,
      completed_at: now
    },
    purpose_bindings: bindings,
    iam_matrix: iamMatrix,
    scenario_results: scenarios,
    postgres_binding: {
      status: "passed",
      instance_count: 2,
      instances: [
        { id: "instance-a", source_commit: sourceCommit, image_digest: imageDigest, config_digest: configDigest, observed_at: now },
        { id: "instance-b", source_commit: sourceCommit, image_digest: imageDigest, config_digest: configDigest, observed_at: now }
      ],
      image_digest: imageDigest,
      migration_head: "0076_agent_session_signing_capability_expiry_audit",
      operation_table: "managed_signer_provider_operations",
      binding_scope: "purpose_key_version_request_digest",
      contention_requests: 100,
      committed_result_count: 8,
      response_loss_reconciled: true,
      evidence_digest: evidenceDigest,
      observed_at: now
    }
  };
}

function requireRegistry() {
  // Keep the fixture independent of the registry's object insertion order while
  // still deriving protocol/signing versions from the production registry.
  return requireRegistry.cache ??= Object.values(globalThis.__agentpassKmsRegistry ?? {});
}

// ESM imports are intentionally kept at module scope in production code. The
// test imports the registry through a synchronous module cache initialized here.
const registryModule = await import("../../apps/cloud-api/src/signer-purpose-registry.mjs");
globalThis.__agentpassKmsRegistry = registryModule.SIGNER_PURPOSE_REGISTRY;

async function signedReport(input) {
  const unsigned = buildKmsQualificationReport(input);
  const signature = crypto.sign(null, signatureInputBytes(unsigned), qualificationEvidenceKey.privateKey).toString("base64url");
  const signed = buildKmsQualificationReport({
    ...input,
    signature: {
      status: "signed",
      algorithm: "ed25519",
      domain: KMS_QUALIFICATION_SIGNATURE_DOMAIN,
      key_id: qualificationEvidenceKeyId,
      public_key_der_base64url: qualificationEvidencePublicKeyDer.toString("base64url"),
      public_key_fingerprint: crypto.createHash("sha256").update(qualificationEvidencePublicKeyDer).digest("hex"),
      signature_base64url: signature
    }
  });
  return signed;
}

function assertCode(code, operation) {
  assert.throws(operation, (error) => error instanceof KmsQualificationEvidenceError && error.code === code);
}

function reboundReport(report, mutate) {
  const tampered = structuredClone(report);
  mutate(tampered);
  const { signature: _signature, report_digest: _reportDigest, ...core } = tampered;
  void _signature;
  void _reportDigest;
  tampered.report_digest = digest(canonicalJson(core));
  return tampered;
}

function reorderJsonKeys(value) {
  if (Array.isArray(value)) return value.map(reorderJsonKeys);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).reverse().map((key) => [key, reorderJsonKeys(value[key])]));
  }
  return value;
}

test("builds canonical mock evidence with exactly eight purposes and fixed matrices", () => {
  const report = buildKmsQualificationReport(baseInput());
  assert.equal(report.production, false);
  assert.equal(report.execution.skip_count, 0);
  assert.equal(report.purpose_bindings.length, 8);
  assert.equal(report.iam_matrix.length, 64);
  assert.equal(report.scenario_results.length, 40);
  assert.equal(report.overall.status, "passed");
  const bytes = serializeKmsQualificationReport(report);
  assert.equal(bytes.toString("utf8"), `${canonicalJson(report)}\n`);
  assert.deepEqual(parseKmsQualificationReport(bytes), report);
});

test("accepts a signed protected-external report and independently verifies its source binding", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  assert.equal(report.signature.status, "signed");
  assert.equal(verifyKmsQualificationReport(report, {
    repositoryRoot: root,
    trustedPublicKeyDer: qualificationEvidencePublicKeyDer,
    trustedKeyId: qualificationEvidenceKeyId
  }).provider, "aws");
  const parsed = parseKmsQualificationReport(serializeKmsQualificationReport(report));
  assert.equal(parsed.report_digest, report.report_digest);
});

test("JSON Schema is strict and accepts the normalized report", async () => {
  const schema = JSON.parse(await fs.readFile(
    path.join(root, "contracts/schemas/kms-qualification-evidence-v1.schema.json"),
    "utf8"
  ));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  assert.equal(validate(report), true, JSON.stringify(validate.errors));
  const unknown = structuredClone(report);
  unknown.execution.unreviewed = true;
  assert.equal(validate(unknown), false);
});

test("rejects unknown fields, incomplete purposes, and shared key identity", () => {
  const unknown = baseInput();
  unknown.postgres_binding.diagnostic = "must never enter evidence";
  assertCode("sensitive_field", () => buildKmsQualificationReport(unknown));

  const incomplete = baseInput();
  incomplete.purpose_bindings.pop();
  assertCode("invalid_array", () => buildKmsQualificationReport(incomplete));

  const shared = baseInput();
  shared.purpose_bindings[1].key_resource = shared.purpose_bindings[0].key_resource;
  assertCode("shared_key_resource", () => buildKmsQualificationReport(shared));
});

test("rejects common API/session credential fields and JWT-shaped values", () => {
  assertCode("sensitive_field", () => scanForForbiddenEvidence({ api_key: "redacted-but-never-accepted" }));
  assertCode("sensitive_field", () => scanForForbiddenEvidence({ session_token: "redacted-but-never-accepted" }));
  assertCode("sensitive_value", () => scanForForbiddenEvidence("eyJaaaaaaaa.eyJbbbbbbbb.eyJcccccccc"));
});

test("rejects provider/resource/version substitutions and non-HSM evidence", () => {
  const wrongProvider = baseInput();
  wrongProvider.provider = "azure";
  assertCode("invalid_provider", () => buildKmsQualificationReport(wrongProvider));

  const alias = baseInput();
  alias.purpose_bindings[0].key_resource = "arn:aws:kms:ap-northeast-1:123456789012:alias/not-a-key";
  assertCode("invalid_value", () => buildKmsQualificationReport(alias));

  const gcpMismatch = baseInput({ provider: "gcp" });
  gcpMismatch.purpose_bindings[0].key_resource = gcpMismatch.purpose_bindings[0].key_resource.replace("cryptoKeyVersions/7", "cryptoKeyVersions/8");
  assertCode("key_version_mismatch", () => buildKmsQualificationReport(gcpMismatch));

  const noHsm = baseInput();
  noHsm.purpose_bindings[0].protection.non_exportable = false;
  assertCode("protection_not_proven", () => buildKmsQualificationReport(noHsm));
});

test("rejects incomplete IAM, lifecycle, and two-instance PostgreSQL evidence", () => {
  const iam = baseInput();
  iam.iam_matrix[1].observed = "allow";
  assertCode("iam_matrix_failed", () => buildKmsQualificationReport(iam));

  const responseLoss = baseInput();
  responseLoss.scenario_results.find((entry) => entry.scenario === "response_loss").replay_safe = false;
  assertCode("response_loss_not_proven", () => buildKmsQualificationReport(responseLoss));

  const postgres = baseInput();
  postgres.postgres_binding.instances[1].config_digest = digest("different-config");
  assertCode("postgres_binding_mismatch", () => buildKmsQualificationReport(postgres));
});

test("mock evidence cannot be upgraded to production and production requires zero skip", () => {
  const mock = baseInput();
  const upgraded = { ...mock, production: true };
  assertCode("production_gate_failed", () => buildKmsQualificationReport(upgraded));
  const skipped = baseInput({ mode: "protected_external", production: false });
  skipped.execution.skip_count = 1;
  skipped.execution.zero_skip = false;
  skipped.production = true;
  const skippedReport = buildKmsQualificationReport(skipped);
  assertCode("production_gate_failed", () => verifyKmsQualificationReport(skippedReport, { repositoryRoot: root }));
  const report = buildKmsQualificationReport(baseInput());
  assertCode("not_production", () => verifyKmsQualificationReport(report, { repositoryRoot: root }));
});

test("rejects noncanonical bytes, digest tampering, signature tampering, and source mismatch", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  const bytes = serializeKmsQualificationReport(report);
  assertCode("noncanonical_json", () => parseKmsQualificationReport(Buffer.from(bytes.toString("utf8").replace("{", "{\n"))));
  const tampered = structuredClone(report);
  tampered.source.config_digest = digest("tampered");
  assertCode("postgres_binding_mismatch", () => parseKmsQualificationReport(Buffer.from(`${canonicalJson(tampered)}\n`)));
  const badSignature = structuredClone(report);
  badSignature.signature.signature_base64url = Buffer.alloc(64, 9).toString("base64url");
  const parsedBadSignature = parseKmsQualificationReport(Buffer.from(`${canonicalJson(badSignature)}\n`));
  assertCode("invalid_signature", () => verifyKmsQualificationReport(parsedBadSignature, {
    repositoryRoot: root,
    trustedPublicKeyDer: qualificationEvidencePublicKeyDer,
    trustedKeyId: qualificationEvidenceKeyId
  }));
  const wrongSource = structuredClone(report);
  wrongSource.source.source_commit = "0".repeat(40);
  for (const instance of wrongSource.postgres_binding.instances) instance.source_commit = wrongSource.source.source_commit;
  const { signature: _wrongSourceSignature, report_digest: _wrongSourceDigest, ...wrongSourceCore } = wrongSource;
  void _wrongSourceSignature;
  void _wrongSourceDigest;
  wrongSource.report_digest = digest(canonicalJson(wrongSourceCore));
  assertCode("source_commit_mismatch", () => verifyKmsQualificationReport(wrongSource, { repositoryRoot: root, requireProduction: false }));
});

test("production verification rejects a self-asserted or differently pinned signing key", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  assertCode("trusted_key_required", () => verifyKmsQualificationReport(report, { repositoryRoot: root }));
  const attackerPublicKeyDer = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" });
  assertCode("untrusted_signature_key", () => verifyKmsQualificationReport(report, {
    repositoryRoot: root,
    trustedPublicKeyDer: attackerPublicKeyDer,
    trustedKeyId: qualificationEvidenceKeyId
  }));
  assertCode("untrusted_signature_key", () => verifyKmsQualificationReport(report, {
    repositoryRoot: root,
    trustedPublicKeyDer: qualificationEvidencePublicKeyDer,
    trustedKeyId: "attacker-key"
  }));
});

test("direct verifier canonicalizes the candidate report before validating it", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  const reordered = reorderJsonKeys(report);
  const result = verifyKmsQualificationReport(reordered, {
    repositoryRoot: root,
    trustedPublicKeyDer: qualificationEvidencePublicKeyDer,
    trustedKeyId: qualificationEvidenceKeyId
  });
  assert.equal(result.report_digest, report.report_digest);
  assertCode("unknown_field", () => verifyKmsQualificationReport(
    reboundReport(report, (value) => { value.purpose_bindings[0].untrusted_projection = true; }),
    { repositoryRoot: root, requireProduction: false }
  ));
});

test("direct verifier binds every purpose and every source/tree identity", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  assert.deepEqual(
    report.purpose_bindings.map((entry) => entry.purpose),
    KMS_QUALIFICATION_PURPOSES.map((entry) => entry.purpose)
  );
  const missingPurpose = reboundReport(report, (value) => { value.purpose_bindings.pop(); });
  assertCode("invalid_array", () => verifyKmsQualificationReport(missingPurpose, { repositoryRoot: root, requireProduction: false }));

  const candidateMismatch = reboundReport(report, (value) => {
    value.source.image_digest = digest("different-candidate-image");
  });
  assertCode("postgres_binding_mismatch", () => verifyKmsQualificationReport(candidateMismatch, { repositoryRoot: root, requireProduction: false }));

  const treeMismatch = reboundReport(report, (value) => {
    value.source.source_commit = "0".repeat(40);
    for (const instance of value.postgres_binding.instances) instance.source_commit = value.source.source_commit;
  });
  assertCode("source_commit_mismatch", () => verifyKmsQualificationReport(treeMismatch, { repositoryRoot: root, requireProduction: false }));
});

test("direct verifier requires all IAM denials", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  const denial = reboundReport(report, (value) => {
    const entry = value.iam_matrix.find((candidate) => candidate.expected === "deny");
    entry.observed = "allow";
  });
  assertCode("iam_matrix_failed", () => verifyKmsQualificationReport(denial, { repositoryRoot: root, requireProduction: false }));
});

test("direct verifier enforces rotation, disable, and response-loss behavior", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  const cases = [
    ["rotation_not_proven", (value) => { value.scenario_results.find((entry) => entry.scenario === "rotation").current_key_version = "6"; }],
    ["scenario_failed", (value) => { value.scenario_results.find((entry) => entry.scenario === "disable").observed = "fail_closed"; }],
    ["response_loss_not_proven", (value) => { value.scenario_results.find((entry) => entry.scenario === "response_loss").replay_safe = false; }]
  ];
  for (const [code, mutate] of cases) {
    assertCode(code, () => verifyKmsQualificationReport(reboundReport(report, mutate), { repositoryRoot: root, requireProduction: false }));
  }
});

test("direct verifier rejects non-exportability tampering", async () => {
  const report = await signedReport(baseInput({ mode: "protected_external", production: true }));
  const tampered = reboundReport(report, (value) => {
    value.purpose_bindings.find((entry) => entry.purpose === KMS_QUALIFICATION_PURPOSES[0].purpose).protection.non_exportable = false;
  });
  assertCode("protection_not_proven", () => verifyKmsQualificationReport(tampered, { repositoryRoot: root, requireProduction: false }));
});

test("verifier CLI emits only stable codes and never diagnostics", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-kms-qualification-"));
  const reportPath = path.join(directory, "mock.json");
  const trustedKeyPath = path.join(directory, "qualification-public-key.der");
  await fs.writeFile(reportPath, serializeKmsQualificationReport(buildKmsQualificationReport(baseInput())), { mode: 0o600 });
  await fs.writeFile(trustedKeyPath, qualificationEvidencePublicKeyDer, { mode: 0o644 });
  const result = spawnSync(process.execPath, [path.join(import.meta.dirname, "verify.mjs"), reportPath, trustedKeyPath, qualificationEvidenceKeyId], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "kms-qualification-verify: not_production\n");
  assert.doesNotMatch(result.stderr, /fixture|diagnostic|credential|PRIVATE KEY/iu);
  const invalid = spawnSync(process.execPath, [path.join(import.meta.dirname, "verify.mjs"), reportPath, "extra"], { cwd: root, encoding: "utf8" });
  assert.equal(invalid.status, 2);
  assert.equal(invalid.stderr, "kms-qualification-verify: invalid_arguments\n");
});

test("report publication is atomic and refuses to replace existing evidence", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-kms-publication-"));
  const output = path.join(directory, "qualification.json");
  const report = buildKmsQualificationReport(baseInput());
  await writeKmsQualificationReport(output, report);
  const original = await fs.readFile(output);
  await assert.rejects(
    writeKmsQualificationReport(output, report),
    (error) => error instanceof KmsQualificationEvidenceError && error.code === "write_failed"
  );
  assert.deepEqual(await fs.readFile(output), original);
  assert.equal((await fs.stat(output)).mode & 0o777, 0o600);
});
