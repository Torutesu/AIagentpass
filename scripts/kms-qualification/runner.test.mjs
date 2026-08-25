import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  KMS_QUALIFICATION_RUNNER_PROBE_DOMAIN,
  KMS_QUALIFICATION_RUNNER_VERSION,
  KmsQualificationRunnerError,
  runKmsQualification,
  validateKmsQualificationRunnerResult
} from "./runner.mjs";
import { KMS_QUALIFICATION_PURPOSES } from "./schema.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../../apps/cloud-api/src/signer-purpose-registry.mjs";

const NOW = "2026-08-17T12:00:00.000Z";
const FINGERPRINTS = new Map(KMS_QUALIFICATION_PURPOSES.map(({ name }, index) => [name, `${String(index + 1).repeat(64)}`.slice(0, 64)]));

function awsResource(index) {
  return `arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

function safeDigest(seed) {
  return `sha256:${crypto.createHash("sha256").update(seed).digest("hex")}`;
}

function fixtureOperations({ onDescribe, onSign, onIam } = {}) {
  return {
    async describePurpose(purpose) {
      onDescribe?.(purpose);
      const index = KMS_QUALIFICATION_PURPOSES.findIndex(({ name }) => name === purpose.name) + 1;
      return {
        key_id: `purpose-${purpose.name}`,
        key_resource: awsResource(index),
        key_version: "1",
        lifecycle_epoch: 1,
        public_key_fingerprint: FINGERPRINTS.get(purpose.name),
        protection: {
          level: "HSM",
          non_exportable: true,
          key_usage: "sign_verify",
          evidence_source: "aws.workload.identity",
          evidence_digest: safeDigest(`protection:${purpose.name}`),
          observed_at: NOW
        }
      };
    },
    async signAndVerify(input) {
      onSign?.(input);
      return {
        status: "passed",
        verified: true,
        signature_digest: safeDigest(`signature:${input.purpose}`),
        evidence_digest: safeDigest(`sign:${input.purpose}`),
        observed_at: NOW
      };
    },
    async checkIam(input) {
      onIam?.(input);
      return {
        observed: input.expected,
        status: "passed",
        evidence_digest: safeDigest(`iam:${input.requester.purpose}:${input.target.purpose}`),
        observed_at: NOW
      };
    }
  };
}

test("runs exactly eight purpose probes and 64 IAM probes with deterministic redacted output", async () => {
  const described = [];
  const signed = [];
  const iam = [];
  const result = await runKmsQualification({
    provider: "aws",
    operations: fixtureOperations({
      onDescribe: (value) => described.push(value.name),
      onSign: (value) => signed.push(value),
      onIam: (value) => iam.push(value)
    })
  });

  assert.equal(result.runner_version, KMS_QUALIFICATION_RUNNER_VERSION);
  assert.equal(result.provider, "aws");
  assert.equal(result.evidence_origin, "protected_external");
  assert.equal(result.purpose_bindings.length, 8);
  assert.equal(result.iam_matrix.length, 64);
  assert.deepEqual(described, KMS_QUALIFICATION_PURPOSES.map(({ name }) => name));
  assert.deepEqual(signed.map(({ name }) => name), KMS_QUALIFICATION_PURPOSES.map(({ name }) => name));
  assert.equal(iam.length, 64);
  assert.equal(new Set(result.iam_matrix.map(({ requester_purpose, target_purpose }) => `${requester_purpose}\0${target_purpose}`)).size, 64);
  assert.equal(result.purpose_bindings.every(({ sign_verify }) => sign_verify.status === "passed" && sign_verify.verified), true);
  assert.equal(result.iam_matrix.every(({ status, observed, expected }) => status === "passed" && observed === expected), true);
  assert.equal(Object.hasOwn(result.purpose_bindings[0].sign_verify, "signature"), false);
  assert.equal(Object.hasOwn(result.purpose_bindings[0].sign_verify, "raw_response"), false);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.purpose_bindings[0]), true);
  assert.equal(Object.isFrozen(result.iam_matrix[0]), true);
  validateKmsQualificationRunnerResult(result, { provider: "aws", mode: "protected_external" });
});

test("passes only canonical non-secret context to injected operations", async () => {
  const seen = [];
  await runKmsQualification({
    provider: "aws",
    operations: fixtureOperations({
      onDescribe: (value) => {
        seen.push(value);
        assert.deepEqual(Object.keys(value).sort(), ["algorithm", "name", "protocol_version", "purpose", "registry_version", "signing_version"]);
        assert.equal(value.domain, undefined);
      },
      onSign: (value) => {
        assert.equal(Buffer.isBuffer(value.request_bytes), true);
        assert.equal(value.request_digest.startsWith("sha256:"), true);
        assert.equal(value.request_bytes.toString("utf8").includes(KMS_QUALIFICATION_RUNNER_PROBE_DOMAIN), true);
        assert.equal(Object.hasOwn(value, "private_key"), false);
      }
    })
  });
  assert.equal(seen.length, 8);
});

test("rejects raw provider-shaped output, forbidden fields, and secret values", async () => {
  const bad = fixtureOperations({
    onDescribe: undefined
  });
  bad.describePurpose = async () => ({
    key_id: "purpose-capability",
    key_resource: awsResource(1),
    key_version: "1",
    lifecycle_epoch: 1,
    public_key_fingerprint: FINGERPRINTS.get("capability"),
    raw_response: { KeyId: "arn:aws:kms:us-east-1:123456789012:key/secret" },
    protection: {
      level: "HSM",
      non_exportable: true,
      key_usage: "sign_verify",
      evidence_source: "aws.workload.identity",
      evidence_digest: safeDigest("x"),
      observed_at: NOW
    }
  });
  await assert.rejects(runKmsQualification({ provider: "aws", operations: bad }), { code: "operation_failed" });

  const secret = fixtureOperations();
  secret.describePurpose = async () => ({
    key_id: "purpose-capability",
    key_resource: awsResource(1),
    key_version: "1",
    lifecycle_epoch: 1,
    public_key_fingerprint: FINGERPRINTS.get("capability"),
    protection: {
      level: "HSM",
      non_exportable: true,
      key_usage: "sign_verify",
      evidence_source: "aws.workload.identity",
      evidence_digest: safeDigest("x"),
      observed_at: NOW,
      diagnostic: "-----BEGIN PRIVATE KEY-----"
    }
  });
  await assert.rejects(runKmsQualification({ provider: "aws", operations: secret }), { code: "operation_failed" });
});

test("does not retry or duplicate a failed operation and reports only stable failure metadata", async () => {
  let signCalls = 0;
  const operations = fixtureOperations();
  operations.signAndVerify = async () => {
    signCalls += 1;
    throw new Error("provider credential leaked");
  };
  await assert.rejects(runKmsQualification({ provider: "aws", operations, maxConcurrency: 2 }), (error) => {
    assert.equal(error instanceof KmsQualificationRunnerError, true);
    assert.equal(error.code, "operation_failed");
    assert.equal(typeof error.message, "string");
    assert.equal(Object.hasOwn(error, "message_detail"), false);
    return true;
  });
  assert.equal(signCalls, 8);
});

test("bounds concurrency and timeout without exposing callback errors", async () => {
  let active = 0;
  let peak = 0;
  const operations = fixtureOperations();
  operations.signAndVerify = async () => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    return { status: "passed", verified: true, signature_digest: safeDigest("s"), evidence_digest: safeDigest("e"), observed_at: NOW };
  };
  const result = await runKmsQualification({ provider: "aws", operations, maxConcurrency: 2, timeoutMs: 100 });
  assert.equal(result.purpose_bindings.length, 8);
  assert.equal(peak <= 2, true);

  const timeout = fixtureOperations();
  timeout.describePurpose = async () => new Promise(() => {});
  await assert.rejects(runKmsQualification({ provider: "aws", operations: timeout, timeoutMs: 5 }), { code: "operation_timeout" });
});

test("supports GCP resource/version binding and preserves failed redacted outcomes", async () => {
  const result = await runKmsQualification({
    provider: "gcp",
    operations: {
      async describePurpose(purpose) {
        const index = KMS_QUALIFICATION_PURPOSES.findIndex(({ name }) => name === purpose.name) + 1;
        return {
          key_id: `gcp-${purpose.name}`,
          key_resource: `projects/agentpass1/locations/global/keyRings/signing/cryptoKeys/${purpose.name}/cryptoKeyVersions/${index}`,
          key_version: String(index),
          lifecycle_epoch: 2,
          public_key_fingerprint: FINGERPRINTS.get(purpose.name),
          protection: { level: "HSM", non_exportable: true, key_usage: "sign_verify", evidence_source: "gcp.workload.identity", evidence_digest: safeDigest(`p:${purpose.name}`), observed_at: NOW }
        };
      },
      async signAndVerify(input) {
        return { status: input.name === "audit_anchor" ? "failed" : "passed", verified: input.name !== "audit_anchor", signature_digest: safeDigest(`sig:${input.name}`), evidence_digest: safeDigest(`e:${input.name}`), observed_at: NOW };
      },
      async checkIam(input) {
        const expected = input.requester.purpose === input.target.purpose ? "allow" : "deny";
        return { observed: expected, status: "passed", evidence_digest: safeDigest(`iam:${expected}`), observed_at: NOW };
      }
    }
  });
  assert.equal(result.provider, "gcp");
  assert.equal(result.purpose_bindings.find(({ name }) => name === "audit_anchor").sign_verify.status, "failed");
  assert.doesNotThrow(() => validateKmsQualificationRunnerResult(result, { provider: "gcp" }));
});

test("rejects tampering or a non-exact matrix at the handoff boundary", async () => {
  const result = await runKmsQualification({ provider: "aws", operations: fixtureOperations() });
  const tampered = structuredClone(result);
  tampered.iam_matrix.pop();
  assert.throws(() => validateKmsQualificationRunnerResult(tampered), { code: "iam_count" });
  const unknown = structuredClone(result);
  unknown.purpose_bindings[0].sign_verify.raw = "x";
  assert.throws(() => validateKmsQualificationRunnerResult(unknown), { code: "unsafe_evidence" });
  const requestTampered = structuredClone(result);
  requestTampered.purpose_bindings[0].sign_verify.request_digest = safeDigest("different-request");
  assert.throws(() => validateKmsQualificationRunnerResult(requestTampered), { code: "sign_request_binding" });
  const iamRequestTampered = structuredClone(result);
  iamRequestTampered.iam_matrix[0].request_digest = safeDigest("different-iam-request");
  assert.throws(() => validateKmsQualificationRunnerResult(iamRequestTampered), { code: "iam_request_binding" });
});

test("keeps registry versions bound to the frozen signer registry", () => {
  for (const purpose of KMS_QUALIFICATION_PURPOSES) {
    const registry = SIGNER_PURPOSE_REGISTRY[purpose.name];
    assert.equal(registry.purpose, purpose.purpose);
    assert.equal(registry.registry_version, 1);
  }
});
