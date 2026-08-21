import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const buildScriptPath = path.join(root, "native/macos/scripts/build-app.sh");
const buildInstallerScriptPath = path.join(root, "native/macos/scripts/build-installer.sh");
const installerScriptPath = path.join(root, "native/macos/scripts/verify-installer-package.sh");
const notarizeInstallerScriptPath = path.join(root, "scripts/release/notarize-installer.sh");
const notarizeControllerScriptPath = path.join(root, "scripts/release/notarize-controller.sh");
const runbookPath = path.join(root, "docs/runbooks/MACOS_RELEASE_NOTARIZATION_RUNBOOK.md");
const buildScript = fs.readFileSync(buildScriptPath, "utf8");
const buildInstallerScript = fs.readFileSync(buildInstallerScriptPath, "utf8");
const installerScript = fs.readFileSync(installerScriptPath, "utf8");
const notarizeInstallerScript = fs.readFileSync(notarizeInstallerScriptPath, "utf8");
const notarizeControllerScript = fs.readFileSync(notarizeControllerScriptPath, "utf8");
const runbook = fs.readFileSync(runbookPath, "utf8");

const buildProducts = [
  "agentpass-onboarding",
  "agentpass-native-manager",
  "agentpass-native-service",
  "agentpass-native-client",
  "agentpass-native-agent-host",
  "agentpass-atomic-rename",
  "QUALIFICATION_CLIENT_BINARY"
];
const installerProducts = [...buildProducts.slice(0, -1), "agentpass-qualification-grant-client"];

test("universal build validates every native product before signing", () => {
  const validationBlock = buildScript.match(/if \[\[ "\$\{#ARCHITECTURES\[@\]\}" -eq 2 \]\]; then[\s\S]*?\nfi\n\ninstall -m 0644/u)?.[0];
  assert.ok(validationBlock, "build-app.sh must validate the --universal output");
  assert.match(validationBlock, /lipo -archs/);
  assert.match(validationBlock, /"arm64 x86_64"\|"x86_64 arm64"/u);
  for (const product of buildProducts) assert.match(validationBlock, new RegExp(product, "u"));
});

test("installer verification keeps the same cross-hardware native product set", () => {
  const validationBlock = installerScript.match(/CROSS_HARDWARE_BINARIES=\([\s\S]*?\n\)/u)?.[0];
  assert.ok(validationBlock);
  for (const product of installerProducts) assert.match(validationBlock, new RegExp(product, "u"));
  assert.match(installerScript, /exactly arm64 and x86_64 slices/u);
});

test("production signing is Developer ID-bound and timestamped at every app boundary", () => {
  assert.match(buildScript, /Developer ID Application:/u);
  assert.match(buildScript, /Authority=Developer ID Application/u);
  assert.match(buildScript, /TeamIdentifier=/u);
  assert.match(buildScript, /flags=.*runtime/u);
  assert.match(buildScript, /Timestamp=/u);
  assert.match(buildInstallerScript, /Developer ID Installer:/u);
  assert.match(installerScript, /Developer ID Installer/u);
  assert.match(installerScript, /Developer ID Application/u);
  assert.match(installerScript, /TeamIdentifier=/u);
});

test("notarization requires fresh evidence, Apple validation, digest binding, and no failed-artifact reuse", () => {
  for (const script of [notarizeInstallerScript, notarizeControllerScript]) {
    assert.match(script, /notarytool submit[\s\S]*--wait[\s\S]*--output-format json/u);
    assert.match(script, /status !== "Accepted"/u);
    assert.match(script, /stapler staple/u);
    assert.match(script, /stapler validate/u);
    assert.match(script, /spctl --assess/u);
    assert.match(script, /shasum -a 256/u);
    assert.match(script, /notarization-failed/u);
    assert.match(script, /notarization\.lock/u);
    assert.match(script, /must be rebuilt/u);
    assert.match(script, /mkdir "\$FAILURE_MARKER"/u);
    assert.doesNotMatch(script, /touch "\$FAILURE_MARKER"/u);
    assert.match(script, /! -e "\$output"/u);
    assert.match(script, /! -L "\$output"/u);
  }
  assert.match(notarizeInstallerScript, /PACKAGE_SHA256_BEFORE/u);
  assert.match(notarizeInstallerScript, /PACKAGE_SHA256_AFTER/u);
  assert.match(notarizeInstallerScript, /AGENTPASS_EXPECTED_ARTIFACT_SHA256/u);
});

test("installer notarization re-verifies the exact post-staple package", () => {
  const verifierCall = '"$SCRIPT_DIR/../../native/macos/scripts/verify-installer-package.sh" "$PACKAGE" "$TEAM_ID"';
  const staplerValidation = "/usr/sbin/spctl --assess --type install --verbose=4 \"$PACKAGE\"";
  const evidenceWrite = '/usr/bin/install -m 0600 "$TEMP_DIR/notarytool-result.json"';
  const verifierOffset = notarizeInstallerScript.indexOf(verifierCall);
  assert.ok(verifierOffset >= 0, "notarization must invoke the canonical installer verifier");
  assert.ok(notarizeInstallerScript.indexOf(staplerValidation) < verifierOffset, "post-staple package verification must follow Gatekeeper assessment");
  assert.ok(verifierOffset < notarizeInstallerScript.indexOf(evidenceWrite), "evidence must not be written before post-staple verification succeeds");
});

test("macOS distribution boundary documents the real-Developer-ID verification limit", () => {
  assert.match(runbook, /static contract|静的契約/iu);
  assert.match(runbook, /Developer ID/iu);
  assert.match(runbook, /not verified|not_proven|未検証/iu);
  assert.match(runbook, /Gatekeeper/iu);
  assert.match(runbook, /artifact_sha256/iu);
  assert.match(runbook, /notarization-failed/iu);
});

test("macOS distribution scripts are shell-syntax valid", () => {
  for (const script of [buildScriptPath, buildInstallerScriptPath, installerScriptPath, notarizeInstallerScriptPath, notarizeControllerScriptPath]) {
    const result = spawnSync("/bin/bash", ["-n", script], { encoding: "utf8" });
    assert.equal(result.status, 0, `${script}: ${result.stdout}\n${result.stderr}`);
  }
});
