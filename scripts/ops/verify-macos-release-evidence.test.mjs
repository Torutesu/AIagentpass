import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../../", import.meta.url).pathname;
const script = new URL("./verify-macos-release-evidence.mjs", import.meta.url).pathname;
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const write = (path, value) => fs.writeFileSync(path, canonical(value), { flag: "wx", mode: 0o600 });
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

function fixture() {
  const base = fs.mkdtempSync(join(os.tmpdir(), "agentpass-macos-wrapper-"));
  const artifactRoot = join(base, "artifact"); const evidenceRoot = join(base, "evidence");
  fs.mkdirSync(artifactRoot); fs.mkdirSync(evidenceRoot);
  const artifactPath = join(artifactRoot, "AgentPass-1.0.0.pkg"); fs.writeFileSync(artifactPath, "package\n");
  const inventoryPath = join(evidenceRoot, "inventory.json");
  execFileSync(process.execPath, [join(root, "native/macos/scripts/generate-artifact-inventory.mjs"), artifactRoot, artifactPath, inventoryPath]);
  const inventoryBytes = fs.readFileSync(inventoryPath); const inventory = JSON.parse(inventoryBytes); const artifact = inventory.artifact;
  const notary = { status: "Accepted", id: "01234567-89ab-cdef-0123-456789abcdef", artifact_sha256: artifact.sha256 };
  write(join(evidenceRoot, "notary.json"), notary); write(join(evidenceRoot, "staple.json"), { status: "validated", artifact_sha256: artifact.sha256 }); write(join(evidenceRoot, "gatekeeper.json"), { assessment: "accepted", artifact_sha256: artifact.sha256 });
  const verification = { schema_version: 1, kind: "agentpass.macos-distribution-verification-v1", status: "verified", artifact_sha256: artifact.sha256, signature_verified: true, notarization_verified: true, staple_verified: true, gatekeeper_verified: true };
  write(join(evidenceRoot, "verification.json"), verification); const verificationBytes = fs.readFileSync(join(evidenceRoot, "verification.json"));
  const evidenceValue = { schema_version: 1, kind: "agentpass.macos-distribution-evidence", artifact, inventory: { name: "inventory.json", bytes: inventoryBytes.length, sha256: digest(inventoryBytes) }, signature: { format: "Developer ID Installer", identity: "Developer ID Installer: Release (TEAM123456)", team_id: "TEAM123456", verified: true }, notarization: { status: "Accepted", submission_id: notary.id, artifact_sha256: artifact.sha256, evidence_file: "notary.json" }, staple: { status: "validated", artifact_sha256: artifact.sha256, evidence_file: "staple.json" }, gatekeeper: { assessment: "accepted", artifact_sha256: artifact.sha256, evidence_file: "gatekeeper.json" }, verification: { name: "verification.json", bytes: verificationBytes.length, sha256: digest(verificationBytes) } };
  const evidencePath = join(evidenceRoot, "evidence.json"); write(evidencePath, evidenceValue);
  return { artifactRoot, evidenceRoot, inventoryPath, evidencePath };
}

test("delegates only an inventory-bound evidence set", () => {
  const value = fixture();
  const output = execFileSync(process.execPath, [script, value.evidencePath, value.inventoryPath, value.artifactRoot, value.evidenceRoot, join(value.evidenceRoot, "verification.json")], { encoding: "utf8" });
  assert.match(output, /"status":"verified"/u);
});

test("binds Developer ID evidence to the expected Team ID when supplied", () => {
  const value = fixture();
  const args = [script, value.evidencePath, value.inventoryPath, value.artifactRoot, value.evidenceRoot, join(value.evidenceRoot, "verification.json"), "TEAM123456"];
  assert.match(execFileSync(process.execPath, args, { encoding: "utf8" }), /"status":"verified"/u);
  assert.throws(() => execFileSync(process.execPath, [...args.slice(0, -1), "OTHER12345"], { encoding: "utf8", stdio: "pipe" }), /Team ID/u);
});

test("reports unknown rather than accepting claim-only evidence", async () => {
  await new Promise((resolve, reject) => {
    execFile(process.execPath, [script], (error) => error?.code === 2 ? resolve() : reject(error ?? new Error("expected unknown")));
  });
});

test("performs a fail-closed path preflight before delegating the distribution verifier", () => {
  const value = fixture();
  assert.throws(() => execFileSync(process.execPath, [script, value.evidencePath.slice(1), value.inventoryPath, value.artifactRoot, value.evidenceRoot, join(value.evidenceRoot, "verification.json")], { encoding: "utf8", stdio: "pipe" }), /preflight refused|normalized absolute path/u);

  const symlink = join(value.evidenceRoot, "evidence-link.json");
  fs.symlinkSync(value.evidencePath, symlink);
  assert.throws(() => execFileSync(process.execPath, [script, symlink, value.inventoryPath, value.artifactRoot, value.evidenceRoot, join(value.evidenceRoot, "verification.json")], { encoding: "utf8", stdio: "pipe" }), /preflight refused|regular single-link file/u);
});
