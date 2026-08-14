import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseControlBundleJson } from "./control-bundle-v2.mjs";
import { inspectNativeApplication } from "./platform-setup.mjs";
import {
  createInstalledReleaseReceipt,
  INSTALLED_RELEASE_RECEIPT_ROOT,
  writeInstalledReleaseReceipt
} from "./installed-release-receipt.mjs";

const TEAM_ID = /^[A-Z0-9]{10}$/;
const RELEASE_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{20,128}$/;

function secureRegularFile(file, label) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error(`${label} path must be absolute`);
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`${label} must be a single-link regular file`);
  return path.resolve(file);
}

function productArtifactFromManifest(manifestPath) {
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); } catch { throw new Error("Release manifest is not valid JSON"); }
  const products = manifest?.artifacts?.filter((artifact) =>
    artifact?.role === "product"
    && artifact?.media_type === "application/vnd.apple.installer+xml"
    && typeof artifact?.name === "string"
    && artifact.name.endsWith("-macos-universal.pkg")
  ) ?? [];
  if (products.length !== 1) throw new Error("Release manifest must identify exactly one macOS universal installer");
  const artifact = products[0];
  if (path.basename(artifact.name) !== artifact.name) throw new Error("Installer artifact name must not contain a path");
  return { artifact, packagePath: secureRegularFile(path.join(path.dirname(manifestPath), artifact.name), "Installer package") };
}

function digestFile(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function verifiedManifestBinding(manifestPath, teamId, releaseSignerFingerprint) {
  const manifestBytes = fs.readFileSync(manifestPath);
  let manifest;
  try { manifest = parseControlBundleJson(manifestBytes, { maxBytes: 16 * 1024 * 1024, maxDepth: 32 }); }
  catch { throw new Error("Verified release manifest is not valid canonical JSON"); }
  const { artifact, packagePath } = productArtifactFromManifest(manifestPath);
  const artifactSha256 = digestFile(packagePath);
  if (artifact.sha256 !== artifactSha256) throw new Error("Installer package digest does not match the signed release manifest");
  const receipt = createInstalledReleaseReceipt({ manifest, manifestBytes, artifactSha256, teamId, releaseSignerFingerprint });
  return { packagePath, receipt };
}

export function prepareProductionInstall(options, { platform = process.platform } = {}) {
  if (platform !== "darwin") throw new Error("Production AgentPass installation is supported only on macOS");
  if (!TEAM_ID.test(options.teamId ?? "")) throw new Error("Expected Apple Team ID must contain 10 uppercase letters or digits");
  if (!RELEASE_FINGERPRINT.test(options.fingerprint ?? "")) throw new Error("Release key fingerprint must use the pinned SHA256 form");
  return {
    manifest: secureRegularFile(options.manifest, "Release manifest"),
    signature: secureRegularFile(options.signature, "Release manifest signature"),
    publicKey: secureRegularFile(options.publicKey, "Release public key"),
    fingerprint: options.fingerprint,
    teamId: options.teamId
  };
}

export function stageProductionInstall(inputs, stagerPath) {
  const stager = secureRegularFile(stagerPath, "release stager");
  const stagingDirectory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-install-stage-")));
  fs.chmodSync(stagingDirectory, 0o700);
  const result = spawnSync(process.execPath, [stager, stagingDirectory, inputs.manifest, inputs.signature, inputs.publicKey], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  if (result.status !== 0) {
    fs.rmSync(stagingDirectory, { recursive: true, force: true });
    throw new Error(result.stderr.trim() || result.stdout.trim() || "Release staging failed");
  }
  let staged;
  try { staged = JSON.parse(result.stdout); } catch {
    fs.rmSync(stagingDirectory, { recursive: true, force: true });
    throw new Error("Release stager returned invalid output");
  }
  return {
    ...inputs,
    manifest: secureRegularFile(staged.manifest, "Staged release manifest"),
    signature: secureRegularFile(staged.signature, "Staged release signature"),
    publicKey: secureRegularFile(staged.public_key, "Staged release public key"),
    stagingDirectory
  };
}

export function removeStagedProductionInstall(stagingDirectory) {
  const temporaryRoot = fs.realpathSync(os.tmpdir());
  const resolved = path.resolve(stagingDirectory ?? "");
  if (path.dirname(resolved) !== temporaryRoot || !path.basename(resolved).startsWith("agentpass-install-stage-")) {
    throw new Error("Refusing to remove an unknown release staging directory");
  }
  const stat = fs.lstatSync(resolved);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || (uid !== undefined && stat.uid !== uid)) {
    throw new Error("Refusing to remove an unsafe release staging directory");
  }
  fs.chmodSync(resolved, 0o700);
  fs.rmSync(resolved, { recursive: true, force: true });
}

export function verifyProductionInstall(inputs, verifierPath) {
  const verifier = secureRegularFile(verifierPath, "macOS release verifier");
  const result = spawnSync(verifier, [inputs.manifest, inputs.signature, inputs.publicKey, inputs.fingerprint, inputs.teamId], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "macOS release verification failed");
  const { packagePath, receipt } = verifiedManifestBinding(inputs.manifest, inputs.teamId, inputs.fingerprint);
  return {
    version: 1,
    channel: "signed-notarized-pkg",
    verified: true,
    package: packagePath,
    stagingDirectory: inputs.stagingDirectory,
    application: "/Applications/AgentPass.app",
    protectedState: "/Library/Application Support/AgentPass",
    receiptRoot: INSTALLED_RELEASE_RECEIPT_ROOT,
    releaseReceipt: receipt,
    preservesProtectedState: true,
    requiresRoot: true,
    requiresExplicitServiceRegistration: true
  };
}

function expectedApplicationPaths(application) {
  return {
    application,
    manager: path.join(application, "Contents/MacOS/agentpass-native-manager"),
    client: path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client"),
    service: path.join(application, "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service")
  };
}

function assertApplicationInspection(plan, inspected) {
  const expected = expectedApplicationPaths(plan.application);
  if (!inspected || inspected.application !== expected.application || inspected.manager !== expected.manager || inspected.client !== expected.client || inspected.service !== expected.service || inspected.identity?.teamId !== plan.releaseReceipt.team_id) {
    throw new Error("Installed AgentPass application verification did not match the verified release");
  }
  return inspected;
}

export function executeProductionInstall(plan, {
  uid = process.getuid?.(),
  installer = "/usr/sbin/installer",
  inspectApplication = inspectNativeApplication,
  protectedStateRoot = plan?.receiptRoot,
  receiptOwner = 0
} = {}) {
  if (!plan?.verified || plan.channel !== "signed-notarized-pkg") throw new Error("Refusing to install an unverified AgentPass package");
  if (!plan.releaseReceipt) throw new Error("Refusing to install without a verified release receipt");
  if (uid !== 0) throw new Error("Installation requires root; rerun the verified command with sudo and --execute");
  const result = spawnSync(installer, ["-pkg", plan.package, "-target", "/"], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "macOS installer failed");
  const app = fs.lstatSync(plan.application);
  if (!app.isDirectory() || app.isSymbolicLink()) throw new Error("Installer completed without a valid /Applications/AgentPass.app");
  const applicationVerification = assertApplicationInspection(plan, inspectApplication(plan.application, {
    expectedOwner: receiptOwner,
    expectedTeamId: plan.releaseReceipt.team_id
  }));
  const receipt = writeInstalledReleaseReceipt(plan.releaseReceipt, {
    root: protectedStateRoot,
    owner: receiptOwner
  });
  return { ...plan, installed: true, installerOutput: result.stdout.trim(), applicationVerification, receiptPath: receipt.path };
}
