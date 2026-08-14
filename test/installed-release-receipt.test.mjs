import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { deriveReleaseCandidateId } from "../lib/release-candidate-identity.mjs";
import {
  INSTALLED_RELEASE_RECEIPT_CODES,
  createInstalledReleaseReceipt,
  installedReleaseReceiptPath,
  readInstalledReleaseReceipt,
  verifyInstalledReleaseReceipt,
  writeInstalledReleaseReceipt
} from "../lib/installed-release-receipt.mjs";

const owner = process.getuid?.();
const artifactSha256 = "a".repeat(64);
const signerFingerprint = `SHA256:${"d".repeat(43)}`;

function receipt(overrides = {}) {
  const manifest = {
    schema_version: 4,
    candidate_id: deriveReleaseCandidateId(artifactSha256),
    source: { commit: "c".repeat(40) }
  };
  return createInstalledReleaseReceipt({
    manifest,
    manifestBytes: Buffer.from(JSON.stringify(manifest), "utf8"),
    artifactSha256,
    teamId: "ABCDE12345",
    releaseSignerFingerprint: signerFingerprint,
    ...overrides
  });
}

function stateRoot() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-installed-receipt-")));
  fs.chmodSync(root, 0o755);
  return root;
}

test("constructs the exact public receipt and rejects candidate substitution", () => {
  const value = receipt();
  assert.deepEqual(Object.keys(value).sort(), ["artifact_sha256", "candidate_id", "kind", "manifest_sha256", "release_signer_fingerprint", "source_commit", "team_id", "version"]);
  assert.equal(value.version, 1);
  assert.equal(value.kind, "agentpass.installed-release-receipt");
  assert.throws(() => receipt({ artifactSha256: "b".repeat(64) }), { code: INSTALLED_RELEASE_RECEIPT_CODES.INVALID });
});

test("writes, reads, and upgrades a root-owned canonical receipt atomically", () => {
  const root = stateRoot();
  try {
    const first = receipt();
    const second = receipt({
      manifest: { schema_version: 4, candidate_id: first.candidate_id, source: { commit: "e".repeat(40) } },
      manifestBytes: Buffer.from("second manifest\n", "utf8")
    });
    const firstWrite = writeInstalledReleaseReceipt(first, { root, owner });
    assert.equal(firstWrite.path, installedReleaseReceiptPath(root));
    assert.deepEqual(readInstalledReleaseReceipt({ root, owner }), first);
    assert.equal(fs.lstatSync(firstWrite.path).nlink, 1);
    assert.equal(fs.lstatSync(firstWrite.path).uid, owner);
    assert.equal(fs.lstatSync(firstWrite.path).mode & 0o777, 0o644);
    assert.deepEqual(verifyInstalledReleaseReceipt({ root, owner }), first);

    writeInstalledReleaseReceipt(second, { root, owner });
    assert.deepEqual(readInstalledReleaseReceipt({ root, owner }), second);
    assert.equal(fs.readdirSync(root).filter((name) => name.endsWith(".tmp")).length, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("ignores and removes only a safe interrupted temporary receipt", () => {
  const root = stateRoot();
  try {
    const temporary = path.join(root, `.installed-release-receipt.${process.pid}.${"a".repeat(48)}.tmp`);
    fs.writeFileSync(temporary, "interrupted\n", { mode: 0o600 });
    const value = receipt();
    writeInstalledReleaseReceipt(value, { root, owner });
    assert.equal(fs.existsSync(temporary), false);
    assert.deepEqual(readInstalledReleaseReceipt({ root, owner }), value);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("fails closed on symlinked or unsafe final receipts", () => {
  const root = stateRoot();
  try {
    const target = installedReleaseReceiptPath(root);
    const outside = path.join(path.dirname(root), "outside-receipt");
    fs.writeFileSync(outside, "outside\n", { mode: 0o600 });
    fs.symlinkSync(outside, target);
    assert.throws(() => readInstalledReleaseReceipt({ root, owner }), (error) => error.code === INSTALLED_RELEASE_RECEIPT_CODES.INVALID);
    assert.throws(() => writeInstalledReleaseReceipt(receipt(), { root, owner }), (error) => error.code === INSTALLED_RELEASE_RECEIPT_CODES.DESTINATION_UNSAFE);
    fs.unlinkSync(target);
    fs.writeFileSync(target, "unsafe\n", { mode: 0o644 });
    assert.throws(() => readInstalledReleaseReceipt({ root, owner }), (error) => error.code === INSTALLED_RELEASE_RECEIPT_CODES.INVALID);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    try { fs.unlinkSync(path.join(path.dirname(root), "outside-receipt")); } catch {}
  }
});

test("preserves the prior receipt when the atomic rename fails", () => {
  const root = stateRoot();
  try {
    const first = receipt();
    const second = receipt({ manifest: { schema_version: 4, candidate_id: first.candidate_id, source: { commit: "e".repeat(40) } }, manifestBytes: Buffer.from("second\n") });
    writeInstalledReleaseReceipt(first, { root, owner });
    const failingFs = { ...fs, renameSync() { throw new Error("simulated rename failure"); } };
    assert.throws(() => writeInstalledReleaseReceipt(second, { root, owner, fs: failingFs }), { code: INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED });
    assert.deepEqual(readInstalledReleaseReceipt({ root, owner }), first);
    assert.equal(fs.readdirSync(root).filter((name) => name.endsWith(".tmp")).length, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("rejects malformed receipt values before touching protected state", () => {
  const root = stateRoot();
  try {
    const value = receipt();
    assert.throws(() => writeInstalledReleaseReceipt({ ...value, extra: true }, { root, owner }), { code: INSTALLED_RELEASE_RECEIPT_CODES.INVALID });
    assert.equal(fs.readdirSync(root).length, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
