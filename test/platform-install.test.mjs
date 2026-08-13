import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { executeProductionInstall, prepareProductionInstall, removeStagedProductionInstall, stageProductionInstall, verifyProductionInstall } from "../lib/platform-install.mjs";

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-install-"));
  const manifest = path.join(directory, "release.json");
  const signature = path.join(directory, "release.sig");
  const publicKey = path.join(directory, "release.pem");
  const pkg = path.join(directory, "AgentPass-0.18.0-macos-universal.pkg");
  fs.writeFileSync(manifest, JSON.stringify({ artifacts: [{ role: "product", media_type: "application/vnd.apple.installer+xml", name: path.basename(pkg) }] }));
  fs.writeFileSync(signature, "signature");
  fs.writeFileSync(publicKey, "public key");
  fs.writeFileSync(pkg, "package");
  const verifier = path.join(directory, "verify.sh");
  fs.writeFileSync(verifier, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  return { directory, manifest, signature, publicKey, pkg, verifier };
}

test("production install plan requires pinned identities and a verified package", () => {
  const value = fixture();
  try {
    const inputs = prepareProductionInstall({
      manifest: value.manifest,
      signature: value.signature,
      publicKey: value.publicKey,
      fingerprint: "SHA256:abcdefghijklmnopqrstuvwx",
      teamId: "ABCDE12345"
    }, { platform: "darwin" });
    const plan = verifyProductionInstall(inputs, value.verifier);
    assert.equal(plan.package, value.pkg);
    assert.equal(plan.verified, true);
    assert.equal(plan.preservesProtectedState, true);
    assert.throws(() => executeProductionInstall(plan, { uid: 501 }), /requires root/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("production install rejects other platforms, unsafe files, and artifact paths", () => {
  const value = fixture();
  try {
    const options = { manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: "SHA256:abcdefghijklmnopqrstuvwx", teamId: "ABCDE12345" };
    assert.throws(() => prepareProductionInstall(options, { platform: "linux" }), /only on macOS/);
    assert.throws(() => prepareProductionInstall({ ...options, teamId: "bad" }, { platform: "darwin" }), /Team ID/);
    const link = path.join(value.directory, "manifest-link.json");
    fs.symlinkSync(value.manifest, link);
    assert.throws(() => prepareProductionInstall({ ...options, manifest: link }, { platform: "darwin" }), /single-link regular file/);

    fs.writeFileSync(value.manifest, JSON.stringify({ artifacts: [{ role: "product", media_type: "application/vnd.apple.installer+xml", name: "../AgentPass-0.18.0-macos-universal.pkg" }] }));
    const inputs = prepareProductionInstall(options, { platform: "darwin" });
    assert.throws(() => verifyProductionInstall(inputs, value.verifier), /must not contain a path/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("production install refuses failed verification and unverified execution", () => {
  const value = fixture();
  try {
    fs.writeFileSync(value.verifier, "#!/bin/sh\necho rejected >&2\nexit 1\n", { mode: 0o700 });
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: "SHA256:abcdefghijklmnopqrstuvwx", teamId: "ABCDE12345" }, { platform: "darwin" });
    assert.throws(() => verifyProductionInstall(inputs, value.verifier), /rejected/);
    assert.throws(() => executeProductionInstall({ verified: false }, { uid: 0 }), /unverified/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("release staging snapshots inputs and only removes its private directory", () => {
  const value = fixture();
  const stager = path.resolve("scripts/release/stage-release.mjs");
  try {
    const checksum = path.join(value.directory, "SHA256SUMS");
    const evidence = path.join(value.directory, "notarization.json");
    const controller = path.join(value.directory, "AgentPassQualificationController-0.18.0-macos-universal.tar");
    const controllerIdentity = path.join(value.directory, "qualification-controller-identity.json");
    const controllerEvidence = path.join(value.directory, "qualification-controller-notarization.json");
    fs.writeFileSync(checksum, "checksums");
    fs.writeFileSync(evidence, "evidence");
    fs.writeFileSync(controller, "controller archive");
    fs.writeFileSync(controllerIdentity, "controller identity");
    fs.writeFileSync(controllerEvidence, "controller notarization evidence");
    fs.writeFileSync(value.manifest, JSON.stringify({
      schema_version: 3,
      artifacts: [
        { role: "product", media_type: "application/vnd.apple.installer+xml", name: path.basename(value.pkg) },
        { role: "external_qualification_controller", media_type: "application/x-tar", name: path.basename(controller) }
      ],
      evidence: { checksums: { name: path.basename(checksum) }, notarization: { evidence: [{ name: path.basename(evidence) }] } },
      external_qualification_controller: {
        identity_document: { name: path.basename(controllerIdentity) },
        notarization: { evidence: [{ name: path.basename(controllerEvidence) }] }
      }
    }));
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: "SHA256:abcdefghijklmnopqrstuvwx", teamId: "ABCDE12345" }, { platform: "darwin" });
    const staged = stageProductionInstall(inputs, stager);
    assert.notEqual(staged.manifest, value.manifest);
    assert.equal(fs.readFileSync(staged.manifest, "utf8"), fs.readFileSync(value.manifest, "utf8"));
    assert.equal(fs.statSync(staged.stagingDirectory).mode & 0o777, 0o500);
    removeStagedProductionInstall(staged.stagingDirectory);
    assert.equal(fs.existsSync(staged.stagingDirectory), false);
    assert.throws(() => removeStagedProductionInstall(value.directory), /unknown release staging/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});
