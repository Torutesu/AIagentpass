import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { canonicalReportBytes, publicKeyFingerprint, signHardwareQualification } from "../scripts/release/sign-hardware-qualification.mjs";

function reportFor(fingerprint) {
  return {
    schema_version: 2,
    source_commit: "a".repeat(40),
    dependency_lock_sha256: "b".repeat(64),
    release_manifest_sha256: "c".repeat(64),
    artifact_name: "AgentPass-0.18.0-macos-universal.pkg",
    artifact_sha256: "d".repeat(64),
    architecture: "arm64",
    hardware_class: "apple_silicon",
    model_identifier: "Mac15,7",
    macos_version: "26.0.1",
    macos_build: "25A100",
    secure_enclave: true,
    team_id: "ABCDE12345",
    nested_code_identities: [{ path: "AgentPass.app", bundle_id: "dev.agentpass", team_id: "ABCDE12345", code_directory_hash: "e".repeat(40) }],
    notarization: { status: "not_verified", submission_ids: [], evidence: [] },
    cloud_image_digest: `sha256:${"f".repeat(64)}`,
    database_migration_manifest_sha256: "1".repeat(64),
    signer_key_versions: [{ name: "capability", version: "cap-2026-08" }],
    browser_versions: [{ name: "chromium", version: "151.0.7922.34" }],
    started_at: "2026-08-13T00:00:00.000Z",
    completed_at: "2026-08-13T00:00:01.000Z",
    operator: "operator@example.com",
    operator_key_fingerprint: fingerprint,
    qualified: true,
    tests: [{ name: "secure-enclave", status: "passed", evidence: [] }],
    gates: [{ name: "release", status: "passed", evidence: [] }]
  };
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-hardware-sign-"));
  const pair = crypto.generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "operator-private.pem");
  const publicPath = path.join(directory, "operator-public.pem");
  fs.writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  const fingerprint = publicKeyFingerprint(pair.publicKey);
  const reportPath = path.join(directory, "qualification.json");
  fs.writeFileSync(reportPath, canonicalReportBytes(reportFor(fingerprint)), { mode: 0o644 });
  return { directory, pair, privatePath, publicPath, fingerprint, reportPath };
}

function cleanup(directory) {
  fs.rmSync(directory, { recursive: true, force: true });
}

function inputs(value, signaturePath = path.join(value.directory, "qualification.sig")) {
  return { reportPath: value.reportPath, privateKeyPath: value.privatePath, signaturePath, publicKeyPath: value.publicPath, expectedFingerprint: value.fingerprint };
}

test("signs only canonical v2 report bytes and emits a detached one-line Ed25519 signature", () => {
  const value = fixture();
  try {
    const result = signHardwareQualification(inputs(value));
    const signaturePath = path.join(value.directory, "qualification.sig");
    const signatureText = fs.readFileSync(signaturePath, "utf8");
    assert.equal(result.signature_bytes, 64);
    assert.match(signatureText, /^(?:[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{87}=)\n$/u);
    assert.equal(crypto.verify(null, fs.readFileSync(value.reportPath), value.pair.publicKey, Buffer.from(signatureText.trim(), "base64")), true);
    assert.equal(fs.statSync(signaturePath).mode & 0o777, 0o600);
  } finally { cleanup(value.directory); }
});

test("rejects report substitution and externally mismatched operator identity", () => {
  const value = fixture();
  try {
    const other = crypto.generateKeyPairSync("ed25519");
    const substituted = reportFor(publicKeyFingerprint(other.publicKey));
    fs.writeFileSync(value.reportPath, canonicalReportBytes(substituted));
    assert.throws(() => signHardwareQualification(inputs(value)), /operator fingerprint does not match the report/);
    fs.writeFileSync(value.reportPath, canonicalReportBytes(reportFor(value.fingerprint)));
    const otherPublicPath = path.join(value.directory, "other-public.pem");
    fs.writeFileSync(otherPublicPath, other.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
    assert.throws(() => signHardwareQualification({ ...inputs(value), publicKeyPath: otherPublicPath, expectedFingerprint: publicKeyFingerprint(other.publicKey) }), /public key.*does not match|fingerprint.*does not match/u);
  } finally { cleanup(value.directory); }
});

test("rejects noncanonical report bytes", () => {
  const value = fixture();
  try {
    const parsed = JSON.parse(fs.readFileSync(value.reportPath));
    fs.writeFileSync(value.reportPath, JSON.stringify(parsed));
    assert.throws(() => signHardwareQualification(inputs(value)), /not canonical JSON/);
  } finally { cleanup(value.directory); }
});

test("rejects non-Ed25519 private keys", () => {
  const value = fixture();
  try {
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    fs.writeFileSync(value.privatePath, rsa.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    assert.throws(() => signHardwareQualification(inputs(value)), /must be Ed25519/);
  } finally { cleanup(value.directory); }
});

test("rejects unsafe private-key mode and symlink", () => {
  const value = fixture();
  try {
    fs.chmodSync(value.privatePath, 0o640);
    assert.throws(() => signHardwareQualification(inputs(value)), /mode 0600/);
    fs.chmodSync(value.privatePath, 0o600);
    const link = path.join(value.directory, "private-link.pem");
    fs.symlinkSync(value.privatePath, link);
    assert.throws(() => signHardwareQualification({ ...inputs(value), privateKeyPath: link }), /cannot open operator private key|single-link/);
  } finally { cleanup(value.directory); }
});

test("requires public-key verification and refuses signature overwrite", () => {
  const value = fixture();
  try {
    assert.throws(() => signHardwareQualification({ reportPath: value.reportPath, privateKeyPath: value.privatePath, signaturePath: path.join(value.directory, "missing-public.sig") }), /public key and expected fingerprint/);
    const signaturePath = path.join(value.directory, "qualification.sig");
    signHardwareQualification(inputs(value, signaturePath));
    const before = fs.readFileSync(signaturePath);
    assert.throws(() => signHardwareQualification(inputs(value, signaturePath)), /cannot write signature output/);
    assert.deepEqual(fs.readFileSync(signaturePath), before);
  } finally { cleanup(value.directory); }
});
