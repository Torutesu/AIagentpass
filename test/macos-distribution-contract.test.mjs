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
const releaseVerifierScriptPath = path.join(root, "scripts/release/verify-macos-release.sh");
const releaseCandidateWorkflowPath = path.join(root, ".github/workflows/release-candidate.yml");
const runbookPath = path.join(root, "docs/runbooks/MACOS_RELEASE_NOTARIZATION_RUNBOOK.md");
const buildScript = fs.readFileSync(buildScriptPath, "utf8");
const buildInstallerScript = fs.readFileSync(buildInstallerScriptPath, "utf8");
const installerScript = fs.readFileSync(installerScriptPath, "utf8");
const notarizeInstallerScript = fs.readFileSync(notarizeInstallerScriptPath, "utf8");
const notarizeControllerScript = fs.readFileSync(notarizeControllerScriptPath, "utf8");
const releaseVerifierScript = fs.readFileSync(releaseVerifierScriptPath, "utf8");
const releaseCandidateWorkflow = fs.readFileSync(releaseCandidateWorkflowPath, "utf8");
const runbook = fs.readFileSync(runbookPath, "utf8");
const distributionEvidenceVerifier = fs.readFileSync(path.join(root, "native/macos/scripts/verify-distribution-evidence.mjs"), "utf8");
const distributionEvidenceWrapper = fs.readFileSync(path.join(root, "scripts/ops/verify-macos-release-evidence.mjs"), "utf8");
const workflowStep = (name) => {
  const start = releaseCandidateWorkflow.indexOf(`      - name: ${name}`);
  assert.ok(start >= 0, `missing release-candidate step: ${name}`);
  const rest = releaseCandidateWorkflow.slice(start + 1);
  const next = rest.search(/\n      - (?:name|id|uses):/u);
  return rest.slice(0, next < 0 ? rest.length : next + 1);
};

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
  assert.match(buildScript, /non-empty Developer ID Application identity bound to --team-id/u);
  assert.match(buildScript, /Authority=Developer ID Application/u);
  assert.match(buildScript, /TeamIdentifier=/u);
  assert.match(buildScript, /flags=.*runtime/u);
  assert.match(buildScript, /Timestamp=/u);
  assert.match(buildInstallerScript, /Developer ID Installer:/u);
  assert.match(buildInstallerScript, /non-empty Developer ID Installer identity bound to AGENTPASS_TEAM_ID/u);
  assert.match(installerScript, /Developer ID Installer/u);
  assert.match(installerScript, /Developer ID Application/u);
  assert.match(installerScript, /TeamIdentifier=/u);
  assert.match(installerScript, /complete Developer ID Application identity/u);
  assert.match(installerScript, /EXPECTED_IDENTITIES/u);
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

test("distribution evidence requires an independent post-staple verification artifact", () => {
  assert.match(distributionEvidenceVerifier, /VERIFICATION/u);
  assert.match(distributionEvidenceVerifier, /agentpass\.macos-distribution-verification-v1/u);
  assert.match(distributionEvidenceVerifier, /verification_sha256/u);
  assert.match(distributionEvidenceVerifier, /signature_verified/u);
  assert.match(distributionEvidenceVerifier, /notarization_verified/u);
  assert.match(distributionEvidenceVerifier, /staple_verified/u);
  assert.match(distributionEvidenceVerifier, /gatekeeper_verified/u);
  assert.match(distributionEvidenceWrapper, /verification/iu);
  assert.match(releaseVerifierScript, /AGENTPASS_DISTRIBUTION_EVIDENCE/);
  assert.match(releaseVerifierScript, /verify-macos-release-evidence\.mjs/);
  assert.match(releaseVerifierScript, /AGENTPASS_DISTRIBUTION_VERIFICATION.*TEAM_ID/su);
});

test("release candidate runs the independent distribution evidence chain before upload", () => {
  const inventory = releaseCandidateWorkflow.indexOf("Inventory exact post-staple installer artifact");
  const independent = releaseCandidateWorkflow.indexOf("Independently verify and canonicalize macOS distribution command evidence");
  const producer = releaseCandidateWorkflow.indexOf("Produce canonical independent macOS distribution evidence");
  const promotionGate = releaseCandidateWorkflow.indexOf("Enforce independent macOS promotion artifact gate");
  const strict = releaseCandidateWorkflow.indexOf("Strictly verify produced macOS distribution evidence");
  const upload = releaseCandidateWorkflow.indexOf("name: release-integrity-evidence");
  assert.ok(inventory >= 0 && independent > inventory && producer > independent && promotionGate > producer && strict > promotionGate && upload > strict, "distribution evidence stages must be ordered before upload");
  assert.match(releaseCandidateWorkflow, /xcrun stapler validate[\s\S]*spctl --assess --type install[\s\S]*pkgutil --check-signature[\s\S]*codesign --verify --strict/u);
  assert.match(releaseCandidateWorkflow, /native\/macos\/scripts\/generate-artifact-inventory\.mjs/u);
  assert.match(releaseCandidateWorkflow, /create-macos-distribution-evidence\.mjs/u);
  assert.match(releaseCandidateWorkflow, /macos-promotion-artifact-gate\.mjs/u);
  assert.match(releaseCandidateWorkflow, /create-macos-distribution-provenance\.mjs/u);
  assert.match(releaseCandidateWorkflow, /actions\/runs\/\$GITHUB_RUN_ID\/jobs\?per_page=100/u);
  assert.match(releaseCandidateWorkflow, /AGENTPASS_DISTRIBUTION_EVIDENCE:[\s\S]*verify-macos-release\.sh/u);
  assert.match(releaseCandidateWorkflow, /integrity-evidence\/macos-\*\.json/u);
});

test("independent macOS promotion checks cover both app and installer and stage every check", () => {
  const gate = workflowStep("Enforce independent macOS promotion artifact gate");
  assert.match(gate, /macos-promotion-artifact-gate\.mjs\s+\\[\s\S]*?"\$EXPECTED_TEAM_ID"\s+"\$APP"\s+"\$PACKAGE"/u);
  const staged = workflowStep("Stage exact macOS distribution evidence for promotion");
  for (const name of [
    "macos-artifact-inventory.json",
    "macos-notary.json",
    "macos-staple.json",
    "macos-gatekeeper.json",
    "macos-identity.json",
    "macos-verification.json",
    "macos-provenance.json",
    "macos-distribution-evidence.json",
    "macos-promotion-artifact-gate.json"
  ]) assert.match(staged, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), `missing staged independent evidence: ${name}`);
  workflowStep("Strictly verify produced macOS distribution evidence");
  const upload = releaseCandidateWorkflow.indexOf("name: release-integrity-evidence");
  const strictOffset = releaseCandidateWorkflow.indexOf("      - name: Strictly verify produced macOS distribution evidence");
  assert.ok(upload >= 0 && strictOffset >= 0 && strictOffset < upload, "independent evidence must be strictly verified before upload");
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
  for (const script of [buildScriptPath, buildInstallerScriptPath, installerScriptPath, notarizeInstallerScriptPath, notarizeControllerScriptPath, releaseVerifierScriptPath]) {
    const result = spawnSync("/bin/bash", ["-n", script], { encoding: "utf8" });
    assert.equal(result.status, 0, `${script}: ${result.stdout}\n${result.stderr}`);
  }
});
