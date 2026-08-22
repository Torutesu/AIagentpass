import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { NATIVE_XPC_CONTRACT_RELATIVE_PATH, validateNativeXpcContract } from "./native-xpc-contract-gate.mjs";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const git = (directory, ...args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8" }).trim();

const createFixture = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-xpc-release-gate-"));
  const contract = JSON.parse(fs.readFileSync(path.join(root, NATIVE_XPC_CONTRACT_RELATIVE_PATH), "utf8"));
  fs.mkdirSync(path.join(directory, "native/macos/Qualification"), { recursive: true });
  for (const sourceRef of contract.source_refs) {
    const target = path.join(directory, sourceRef);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, sourceRef), target);
  }
  const contractPath = path.join(directory, NATIVE_XPC_CONTRACT_RELATIVE_PATH);
  fs.writeFileSync(contractPath, fs.readFileSync(path.join(root, NATIVE_XPC_CONTRACT_RELATIVE_PATH)));
  git(directory, "init", "-q");
  git(directory, "config", "user.email", "release-gate@example.invalid");
  git(directory, "config", "user.name", "AgentPass release gate");
  git(directory, "add", ".");
  git(directory, "commit", "-qm", "native XPC release contract");
  const identity = () => ({ commit: git(directory, "rev-parse", "HEAD"), tree: git(directory, "rev-parse", "HEAD^{tree}") });
  return { directory, contractPath, identity };
};

test("authoritative macOS release verifier invokes the native XPC contract gate", () => {
  const verifier = fs.readFileSync(path.join(root, "scripts/release/verify-macos-release.sh"), "utf8");
  assert.match(verifier, /native-xpc-contract-gate\.mjs/u);
  assert.match(verifier, /SOURCE_COMMIT=.*m\.source\?\.commit/u);
  assert.match(verifier, /SOURCE_TREE=.*m\.source\?\.tree/u);
  assert.match(verifier, /native-xpc-contract-gate\.mjs.*\$ROOT_DIR.*\$SOURCE_COMMIT.*\$SOURCE_TREE/u);
});

test("passes only when the canonical contract is present, source-tree bound, and fingerprint bound", () => {
  const fixture = createFixture();
  const identity = fixture.identity();
  const result = validateNativeXpcContract({ repoRoot: fixture.directory, expectedSourceCommit: identity.commit, expectedSourceTree: identity.tree });
  assert.equal(result.status, "passed");
  assert.equal(result.contract_path, NATIVE_XPC_CONTRACT_RELATIVE_PATH);
  assert.equal(result.source_commit, identity.commit);
  assert.equal(result.source_tree, identity.tree);
  assert.match(result.contract_sha256, /^[0-9a-f]{64}$/u);
});

test("fails closed when the contract is missing or non-canonical", () => {
  const missing = createFixture();
  const missingIdentity = missing.identity();
  fs.unlinkSync(missing.contractPath);
  assert.throws(() => validateNativeXpcContract({ repoRoot: missing.directory, expectedSourceCommit: missingIdentity.commit, expectedSourceTree: missingIdentity.tree }), /native XPC contract/u);

  const nonCanonical = createFixture();
  const nonCanonicalIdentity = nonCanonical.identity();
  const value = JSON.parse(fs.readFileSync(nonCanonical.contractPath, "utf8"));
  fs.writeFileSync(nonCanonical.contractPath, `${JSON.stringify(value, null, 2)}\n`);
  assert.throws(() => validateNativeXpcContract({ repoRoot: nonCanonical.directory, expectedSourceCommit: nonCanonicalIdentity.commit, expectedSourceTree: nonCanonicalIdentity.tree }), /not canonical JSON/u);
});

test("fails closed when source tree or Swift fingerprint binding drifts", () => {
  const sourceMismatch = createFixture();
  const sourceIdentity = sourceMismatch.identity();
  assert.throws(() => validateNativeXpcContract({ repoRoot: sourceMismatch.directory, expectedSourceCommit: sourceIdentity.commit, expectedSourceTree: "f".repeat(40) }), /source tree/u);

  const fingerprintMismatch = createFixture();
  const swiftPath = path.join(fingerprintMismatch.directory, "native/macos/Sources/AgentPassNativeCore/NativeXPCContract.swift");
  const changed = fs.readFileSync(swiftPath, "utf8").replace(/frozenFingerprint = "SHA256:[0-9a-f]{64}"/u, `frozenFingerprint = "SHA256:${"a".repeat(64)}"`);
  assert.notEqual(changed, fs.readFileSync(swiftPath, "utf8"));
  fs.writeFileSync(swiftPath, changed);
  git(fingerprintMismatch.directory, "add", ".");
  git(fingerprintMismatch.directory, "commit", "-qm", "change native XPC fingerprint");
  const fingerprintIdentity = fingerprintMismatch.identity();
  assert.throws(() => validateNativeXpcContract({ repoRoot: fingerprintMismatch.directory, expectedSourceCommit: fingerprintIdentity.commit, expectedSourceTree: fingerprintIdentity.tree }), /fingerprint is not bound/u);
});
