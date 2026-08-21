import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import crypto from "node:crypto";
import { deriveReleaseCandidateId } from "../lib/release-candidate-identity.mjs";
import { assertInstallVersionAllowed, executeProductionInstall, prepareProductionInstall, removeStagedProductionInstall, stageProductionInstall, verifyProductionInstall } from "../lib/platform-install.mjs";
import { readInstalledReleaseReceipt } from "../lib/installed-release-receipt.mjs";

const owner = process.getuid?.();
const signerFingerprint = `SHA256:${"d".repeat(43)}`;

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-install-"));
  const manifest = path.join(directory, "release.json");
  const signature = path.join(directory, "release.sig");
  const publicKey = path.join(directory, "release.pem");
  const pkg = path.join(directory, "AgentPass-0.18.0-macos-universal.pkg");
  fs.writeFileSync(pkg, "package");
  const artifactSha256 = crypto.createHash("sha256").update(fs.readFileSync(pkg)).digest("hex");
  fs.writeFileSync(manifest, JSON.stringify({
    schema_version: 4,
    version: "0.18.0",
    candidate_id: deriveReleaseCandidateId(artifactSha256),
    source: { commit: "c".repeat(40) },
    artifacts: [{ role: "product", media_type: "application/vnd.apple.installer+xml", name: path.basename(pkg), sha256: artifactSha256 }],
    evidence: { notarization: { evidence: [] }, checksums: { name: "SHA256SUMS" } },
    external_qualification_controller: { identity_document: { name: "controller-identity.json" }, notarization: { evidence: [] } }
  }));
  fs.writeFileSync(signature, "signature");
  fs.writeFileSync(publicKey, "public key");
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
      fingerprint: signerFingerprint,
      teamId: "ABCDE12345"
    }, { platform: "darwin" });
    const plan = verifyProductionInstall(inputs, value.verifier);
    assert.equal(plan.package, value.pkg);
    assert.equal(plan.verified, true);
    assert.deepEqual(Object.keys(plan.releaseReceipt).sort(), ["artifact_sha256", "candidate_id", "kind", "manifest_sha256", "release_signer_fingerprint", "release_version", "source_commit", "team_id", "version"]);
    assert.equal(plan.preservesProtectedState, true);
    assert.throws(() => executeProductionInstall(plan, { uid: 501 }), /requires root/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("production install rejects other platforms, unsafe files, and artifact paths", () => {
  const value = fixture();
  try {
    const options = { manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: signerFingerprint, teamId: "ABCDE12345" };
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
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: signerFingerprint, teamId: "ABCDE12345" }, { platform: "darwin" });
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
    const artifactSha256 = crypto.createHash("sha256").update(fs.readFileSync(value.pkg)).digest("hex");
    fs.writeFileSync(value.manifest, JSON.stringify({
      schema_version: 4,
      version: "0.18.0",
      candidate_id: deriveReleaseCandidateId(artifactSha256),
      source: { commit: "c".repeat(40) },
      artifacts: [
        { role: "product", media_type: "application/vnd.apple.installer+xml", name: path.basename(value.pkg), sha256: artifactSha256 },
        { role: "external_qualification_controller", media_type: "application/x-tar", name: path.basename(controller) }
      ],
      evidence: { checksums: { name: path.basename(checksum) }, notarization: { evidence: [{ name: path.basename(evidence) }] } },
      external_qualification_controller: {
        identity_document: { name: path.basename(controllerIdentity) },
        notarization: { evidence: [{ name: path.basename(controllerEvidence) }] }
      }
    }));
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: signerFingerprint, teamId: "ABCDE12345" }, { platform: "darwin" });
    const staged = stageProductionInstall(inputs, stager);
    assert.notEqual(staged.manifest, value.manifest);
    assert.equal(fs.readFileSync(staged.manifest, "utf8"), fs.readFileSync(value.manifest, "utf8"));
    assert.equal(fs.statSync(staged.stagingDirectory).mode & 0o777, 0o500);
    removeStagedProductionInstall(staged.stagingDirectory);
    assert.equal(fs.existsSync(staged.stagingDirectory), false);
    assert.throws(() => removeStagedProductionInstall(value.directory), /unknown release staging/);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("execution verifies the installed app before atomically persisting the public receipt", () => {
  const value = fixture();
  const stateRoot = path.join(value.directory, "protected-state");
  const application = path.join(value.directory, "AgentPass.app");
  const installer = path.join(value.directory, "installer.sh");
  fs.mkdirSync(stateRoot, { mode: 0o755 });
  fs.mkdirSync(application, { mode: 0o700 });
  fs.writeFileSync(installer, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const expected = {
    application,
    manager: path.join(application, "Contents/MacOS/agentpass-native-manager"),
    client: path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client"),
    service: path.join(application, "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service")
  };
  try {
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: signerFingerprint, teamId: "ABCDE12345" }, { platform: "darwin" });
    const verified = verifyProductionInstall(inputs, value.verifier);
    const plan = { ...verified, application, protectedState: stateRoot };
    let inspected = false;
    const result = executeProductionInstall(plan, {
      uid: 0,
      receiptOwner: owner,
      protectedStateRoot: stateRoot,
      installer,
      inspectApplication: (target, options) => {
        inspected = true;
        assert.equal(target, application);
        assert.deepEqual(options, { expectedOwner: owner, expectedTeamId: "ABCDE12345" });
        return { ...expected, identity: { teamId: "ABCDE12345" }, serviceStatus: "enabled" };
      }
    });
    assert.equal(inspected, true);
    assert.equal(result.installed, true);
    assert.deepEqual(readInstalledReleaseReceipt({ root: stateRoot, owner }), verified.releaseReceipt);
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("execution leaves the previous receipt untouched when app verification fails", () => {
  const value = fixture();
  const stateRoot = path.join(value.directory, "protected-state");
  const application = path.join(value.directory, "AgentPass.app");
  const installer = path.join(value.directory, "installer.sh");
  fs.mkdirSync(stateRoot, { mode: 0o755 });
  fs.mkdirSync(application, { mode: 0o700 });
  fs.writeFileSync(installer, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  try {
    const inputs = prepareProductionInstall({ manifest: value.manifest, signature: value.signature, publicKey: value.publicKey, fingerprint: signerFingerprint, teamId: "ABCDE12345" }, { platform: "darwin" });
    const verified = verifyProductionInstall(inputs, value.verifier);
    const plan = { ...verified, application, protectedState: stateRoot };
    assert.throws(() => executeProductionInstall(plan, {
      uid: 0,
      receiptOwner: owner,
      protectedStateRoot: stateRoot,
      installer,
      inspectApplication: () => { throw new Error("verification failed"); }
    }), /verification failed/);
    assert.throws(() => readInstalledReleaseReceipt({ root: stateRoot, owner }), (error) => error.code === "INSTALLED_RECEIPT_MISSING");
  } finally { fs.rmSync(value.directory, { recursive: true, force: true }); }
});

test("install policy allows first install and an exact same-release repair", () => {
  const candidate = { release_version: "1.2.3", candidate_id: "candidate", artifact_sha256: "a".repeat(64), manifest_sha256: "b".repeat(64) };
  assert.deepEqual(assertInstallVersionAllowed(candidate, null), { decision: "first_install" });
  assert.deepEqual(assertInstallVersionAllowed(candidate, { ...candidate }), { decision: "same_release" });
});

test("install policy refuses older releases and same-version artifact substitution", () => {
  const installed = { release_version: "1.2.3", candidate_id: "candidate-new", artifact_sha256: "a".repeat(64), manifest_sha256: "b".repeat(64) };
  assert.throws(
    () => assertInstallVersionAllowed({ ...installed, release_version: "1.2.2" }, installed),
    (error) => error.code === "RELEASE_DOWNGRADE_REFUSED"
  );
  assert.throws(
    () => assertInstallVersionAllowed({ ...installed, artifact_sha256: "c".repeat(64) }, installed),
    (error) => error.code === "RELEASE_SAME_VERSION_MISMATCH"
  );
  assert.deepEqual(assertInstallVersionAllowed({ ...installed, release_version: "1.2.4" }, installed), { decision: "upgrade" });
});
