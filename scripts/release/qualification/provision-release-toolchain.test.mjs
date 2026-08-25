import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createReleaseToolchainManifest, RELEASE_TOOLCHAIN_FILES } from "./create-release-toolchain-manifest.mjs";
import { provisionReleaseToolchain } from "./provision-release-toolchain.mjs";

const sourceMap = {
  "verify-installed-toolchain.mjs": "native/macos/Qualification/verify-installed-toolchain.mjs",
  "verify-hardware-qualification-set.mjs": "scripts/release/verify-hardware-qualification-set.mjs",
  "validate-hardware-qualification.mjs": "scripts/release/validate-hardware-qualification.mjs",
  "generate-hardware-qualification-template.mjs": "scripts/release/generate-hardware-qualification-template.mjs",
  "run-p0c-qualification.mjs": "scripts/release/run-p0c-qualification.mjs",
  "sign-hardware-qualification.mjs": "scripts/release/sign-hardware-qualification.mjs",
  "p0c/verify-runner-attestation.mjs": "scripts/release/p0c/verify-runner-attestation.mjs",
  "n3e/controller-identity-contract.mjs": "scripts/release/n3e/controller-identity-contract.mjs",
  "n3e/qualification-suite-evidence.mjs": "scripts/release/n3e/qualification-suite-evidence.mjs",
  "lib/release-candidate-identity.mjs": "lib/release-candidate-identity.mjs"
};

function fixture() {
  const root = process.cwd();
  const key = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, key.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-toolchain-dest-")); fs.chmodSync(parent, 0o700);
  return { root, keyPath, parent, destination: path.join(parent, "qualification-tool") };
}

test("provisions a signed release toolchain atomically with the closed inventory", () => {
  const value = fixture();
  const result = provisionReleaseToolchain({ sourceRoot: value.root, destination: value.destination, signingKey: value.keyPath, production: false });
  assert.equal(result.destination, value.destination);
  assert.deepEqual(result.files, [...RELEASE_TOOLCHAIN_FILES]);
  const manifest = createReleaseToolchainManifest(value.destination);
  assert.deepEqual(manifest.files.map((item) => item.path), [...RELEASE_TOOLCHAIN_FILES]);
  const manifestBytes = fs.readFileSync(path.join(value.destination, "manifest.json"));
  const signature = Buffer.from(fs.readFileSync(path.join(value.destination, "manifest.sig"), "utf8").trim(), "base64");
  const publicKey = crypto.createPublicKey({ key: fs.readFileSync(path.join(value.destination, "manifest.pub")), format: "der", type: "spki" });
  assert.equal(crypto.verify(null, manifestBytes, publicKey, signature), true);
  assert.equal(fs.statSync(value.destination).mode & 0o022, 0);
});

test("refuses to replace an existing protected toolchain", () => {
  const value = fixture(); fs.mkdirSync(value.destination);
  assert.throws(() => provisionReleaseToolchain({ sourceRoot: value.root, destination: value.destination, signingKey: value.keyPath, production: false }), /already exists/u);
});
