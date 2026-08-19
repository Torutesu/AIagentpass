import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { PRODUCTION_EVIDENCE_MANIFEST_KIND, PRODUCTION_EVIDENCE_NOT_PROVEN, ProductionEvidenceError, verifyProductionEvidenceManifest } from "./verify-production-evidence.mjs";

const SCRIPT = path.resolve("scripts/release/verify-production-evidence.mjs");
const SOURCE = "a".repeat(40);
const ARTIFACT = "b".repeat(64);
const CANDIDATE = `release-pkg-sha256-v1-${ARTIFACT}`;

function descriptor(name) { return { name, bytes: 1, sha256: "c".repeat(64) }; }
function signedManifest() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const manifest = {
    schema_version: 1,
    kind: PRODUCTION_EVIDENCE_MANIFEST_KIND,
    candidate: {
      artifact_name: "AgentPass-0.18.0-macos-universal.pkg",
      artifact_sha256: ARTIFACT,
      candidate_id: CANDIDATE,
      source_commit: SOURCE,
      version: "0.18.0"
    },
    gates: {
      kms: { report: descriptor("kms.json"), trusted_key_id: "kms-key-2026", trusted_public_key: descriptor("kms-key.der") },
      postgres: { qualification: descriptor("postgres.json") },
      release: { attestation: descriptor("release-attestation.json"), offline_evidence: descriptor("release-evidence.json") }
    }
  };
  const signature = crypto.sign(null, Buffer.from(`${canonicalJson(manifest)}\n`), privateKey).toString("base64url");
  const der = publicKey.export({ type: "spki", format: "der" });
  manifest.signature = {
    algorithm: "ed25519",
    key_id: "bundle-key-2026",
    public_key_fingerprint: `SHA256:${crypto.createHash("sha256").update(der).digest("base64url")}`,
    signature_base64url: signature
  };
  return { manifest, der, privateKey };
}

test("the production bundle has a stable not_proven result when external evidence is absent", () => {
  assert.deepEqual(PRODUCTION_EVIDENCE_NOT_PROVEN, {
    status: "not_proven",
    reason: "production_evidence_unavailable",
    required: ["signed_candidate_manifest", "protected_kms", "protected_postgres", "protected_release"]
  });
  const result = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.deepEqual(JSON.parse(result.stdout), PRODUCTION_EVIDENCE_NOT_PROVEN);
  assert.equal(result.stderr, "");
});

test("the published manifest schema is closed", () => {
  const schema = JSON.parse(fs.readFileSync(new URL("./production-evidence-manifest.schema.json", import.meta.url), "utf8"));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const { manifest } = signedManifest();
  assert.equal(validate(manifest), true, JSON.stringify(validate.errors));
  const unknown = structuredClone(manifest);
  unknown.gates.release.unexpected = true;
  assert.equal(validate(unknown), false);
});

test("a signed envelope still remains not_proven when KMS evidence is missing", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-production-evidence-"));
  const { manifest, der } = signedManifest();
  assert.throws(
    () => verifyProductionEvidenceManifest({ manifest, root, repositoryRoot: path.resolve("."), trustedPublicKeyDer: der, trustedKeyId: "bundle-key-2026" }),
    (error) => error instanceof ProductionEvidenceError && error.code === "kms_report_unavailable"
  );
});

test("unknown manifest fields cannot be upgraded into a production pass", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-production-evidence-"));
  const { manifest, der } = signedManifest();
  manifest.status = "closed";
  assert.throws(
    () => verifyProductionEvidenceManifest({ manifest, root, repositoryRoot: path.resolve("."), trustedPublicKeyDer: der, trustedKeyId: "bundle-key-2026" }),
    (error) => error instanceof ProductionEvidenceError && error.code === "invalid_manifest"
  );
});

test("path traversal in a protected release descriptor is rejected", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-production-evidence-"));
  const { manifest, der, privateKey } = signedManifest();
  manifest.gates.kms.report.name = "../kms.json";
  const { signature: _signature, ...unsigned } = manifest;
  manifest.signature.signature_base64url = crypto.sign(null, Buffer.from(`${canonicalJson(unsigned)}\n`), privateKey).toString("base64url");
  assert.throws(
    () => verifyProductionEvidenceManifest({ manifest, root, repositoryRoot: path.resolve("."), trustedPublicKeyDer: der, trustedKeyId: "bundle-key-2026" }),
    (error) => error instanceof ProductionEvidenceError && error.code === "invalid_kms_report"
  );
});
