import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = join(fileURLToPath(new URL("..", import.meta.url)));
const read = (relativePath) => fs.readFileSync(join(ROOT, relativePath), "utf8");
const p0c = (relativePath) => join(ROOT, "scripts", "release", "p0c", relativePath);

const REQUIRED_GATES = Object.freeze([
  "gatekeeper-notarization",
  "clean-install-launchd-xpc",
  "secure-enclave-enrollment",
  "cloud-possession-verification",
  "claude-code-unattended-sign",
  "cursor-code-unattended-sign",
  "audit-upload-observation",
  "policy-reduction-refresh-ack",
  "offline-expiry",
  "revoke-emergency-stop",
  "crash-restart-recovery",
  "sleep-wake-network-clock",
  "upgrade-preserves-state",
  "uninstall-reinstall-recovery",
  "current-user-purge",
  "negative-identity-and-entitlement-cases",
]);

const REQUIRED_TESTS = Object.freeze([
  "exact-pkg-install",
  "launchd-xpc-approval",
  "secure-enclave-key-creation",
  "secure-enclave-nonexportability",
  "cloud-possession-proof",
  "claude-code-unattended-sign",
  "cursor-code-unattended-sign",
  "unrelated-process-denied",
  "audit-console-observation",
  "policy-reduction-denied",
  "offline-expiry-denied",
  "revoke-denied",
  "emergency-stop-denied",
  "service-crash-recovery",
  "os-reboot-recovery",
  "sleep-wake-recovery",
  "network-clock-failure",
  "upgrade-preserves-state",
  "uninstall-reinstall-recovery",
  "current-user-purge",
]);

const DRIVER_TESTS = Object.freeze({
  "gatekeeper-notarization": ["exact-pkg-install"],
  "clean-install-launchd-xpc": ["launchd-xpc-approval"],
  "secure-enclave-enrollment": ["secure-enclave-key-creation", "secure-enclave-nonexportability"],
  "cloud-possession-verification": ["cloud-possession-proof"],
  "claude-code-unattended-sign": ["claude-code-unattended-sign"],
  "cursor-code-unattended-sign": ["cursor-code-unattended-sign"],
  "audit-upload-observation": ["audit-console-observation"],
  "policy-reduction-refresh-ack": ["policy-reduction-denied"],
  "offline-expiry": ["offline-expiry-denied"],
  "revoke-emergency-stop": ["revoke-denied", "emergency-stop-denied"],
  "crash-restart-recovery": ["service-crash-recovery", "os-reboot-recovery"],
  "sleep-wake-network-clock": ["sleep-wake-recovery", "network-clock-failure"],
  "upgrade-preserves-state": ["upgrade-preserves-state"],
  "uninstall-reinstall-recovery": ["uninstall-reinstall-recovery"],
  "current-user-purge": ["current-user-purge"],
  "negative-identity-and-entitlement-cases": ["unrelated-process-denied"],
});

const PHYSICAL_DRIVER_FILES = REQUIRED_GATES;
const PHYSICAL_SCENARIO_FILES = REQUIRED_GATES;
const EVIDENCE_VERIFIERS = Object.freeze([
  "scripts/release/run-p0c-qualification.mjs",
  "scripts/release/validate-hardware-qualification.mjs",
  "scripts/release/verify-hardware-qualification-set.mjs",
  "scripts/release/sign-hardware-qualification.mjs",
  "scripts/release/hardware-qualification.schema.json",
]);

const names = (directory, predicate = () => true) => fs.readdirSync(directory, { withFileTypes: true })
  .filter(predicate)
  .map((entry) => entry.name)
  .sort();

const quotedValues = (source, declaration) => {
  const match = source.match(new RegExp(`${declaration}\\s*=\\s*(?:Object\\.freeze\\(\\s*)?\\[([\\s\\S]*?)\\](?:\\s*\\))?`, "u"));
  assert.ok(match, `${declaration} must be declared as a closed array`);
  return [...match[1].matchAll(/['"]([^'"]+)['"]/gu)].map((item) => item[1]);
};

const driverDeclaration = (source) => ({
  gate: source.match(/gate:\s*['"]([^'"]+)['"]/u)?.[1],
  tests: [...(source.match(/tests:\s*\[([\s\S]*?)\]/u)?.[1] ?? "").matchAll(/['"]([^'"]+)['"]/gu)].map((item) => item[1]),
  scenario: source.match(/scenario:\s*['"]([^'"]+)['"]/u)?.[1],
});

const runCLI = (relativePath, args = [], env = {}) => spawnSync(process.execPath, [join(ROOT, relativePath), ...args], {
  cwd: ROOT,
  env: { ...process.env, ...env },
  encoding: "utf8",
  timeout: 10_000,
});

test("N3-E physical contract freezes the complete driver and test inventory", () => {
  const qualification = read("scripts/release/run-p0c-qualification.mjs");
  const verifier = read("scripts/release/validate-hardware-qualification.mjs");
  const aggregateVerifier = read("scripts/release/verify-hardware-qualification-set.mjs");
  assert.deepEqual(quotedValues(qualification, "REQUIRED_GATES"), REQUIRED_GATES);
  assert.deepEqual(quotedValues(qualification, "REQUIRED_TESTS"), REQUIRED_TESTS);
  assert.deepEqual(quotedValues(verifier, "requiredGates"), REQUIRED_GATES);
  assert.deepEqual(quotedValues(verifier, "requiredTests"), REQUIRED_TESTS);
  assert.match(aggregateVerifier, /const HARDWARE_CLASSES = Object\.freeze\(\['apple_silicon', 'intel_t2'\]\)/u);

  const driverDirectory = p0c("drivers");
  assert.deepEqual(names(driverDirectory, (entry) => entry.isFile() && !entry.name.endsWith(".test.mjs")), [...PHYSICAL_DRIVER_FILES].sort());
  for (const gate of REQUIRED_GATES) {
    const source = read(`scripts/release/p0c/drivers/${gate}`);
    assert.deepEqual(driverDeclaration(source), { gate, tests: DRIVER_TESTS[gate], scenario: gate });
    assert.match(source, /runGateDriver/u, `${gate} must use the fixed driver runtime`);
    assert.doesNotMatch(source, /(?:mock|fake|stub|simulat|fixture|automaticPresenceSimulation)/iu, `${gate} contains a simulation shortcut`);
  }
  assert.deepEqual(Object.values(DRIVER_TESTS).flat().sort(), [...REQUIRED_TESTS].sort());
});

test("N3-E physical contract freezes the scenario and evidence-verifier inventory", () => {
  const provisioner = read("scripts/release/p0c/provision-runner.mjs");
  const scenarioRuntime = read("scripts/release/p0c/lib/scenario-runtime.mjs");
  const driverRuntime = read("scripts/release/p0c/lib/driver-runtime.mjs");
  assert.deepEqual(quotedValues(provisioner, "REQUIRED_GATES").sort(), [...REQUIRED_GATES].sort());
  assert.match(provisioner, /exactEntries: REQUIRED_GATES/u);
  assert.match(provisioner, /scenarioFiles = REQUIRED_GATES\.map/u);
  assert.match(provisioner, /installed scenario directory/u);

  const scenarioDirectory = p0c("scenarios");
  const checkedInScenarioNames = names(scenarioDirectory, (entry) => entry.isFile() && !entry.name.endsWith(".test.mjs"));
  assert.ok(checkedInScenarioNames.length > 0, "at least one physical scenario implementation must be checked in");
  for (const scenario of checkedInScenarioNames) {
    const source = read(`scripts/release/p0c/scenarios/${scenario}`);
    assert.match(source, /executePhysicalScenario/u, `${scenario} must use the physical scenario runtime`);
    assert.doesNotMatch(source, /automaticPresenceSimulation|production\s*:\s*false/iu, `${scenario} contains a simulation shortcut`);
  }
  assert.match(scenarioRuntime, /if \(production && process\.platform !== 'darwin'\)/u);
  assert.match(scenarioRuntime, /release\.gate !== gate/u);
  assert.match(scenarioRuntime, /release\.tests\) !== JSON\.stringify\(tests\)/u);
  assert.match(driverRuntime, /if \(production && process\.platform !== 'darwin'\)/u);

  for (const verifier of EVIDENCE_VERIFIERS) {
    assert.ok(fs.statSync(join(ROOT, verifier)).isFile(), `${verifier} is part of the evidence verifier inventory`);
  }
  assert.match(read(EVIDENCE_VERIFIERS[2]), /argv\.length !== 16/u);
  assert.match(read(EVIDENCE_VERIFIERS[2]), /apple_silicon/u);
  assert.match(read(EVIDENCE_VERIFIERS[2]), /intel_t2/u);
});

test("N3-E physical evidence is candidate-bound and secret-free by construction", () => {
  const qualification = read("scripts/release/run-p0c-qualification.mjs");
  const driverRuntime = read("scripts/release/p0c/lib/driver-runtime.mjs");
  const scenarioRuntime = read("scripts/release/p0c/lib/scenario-runtime.mjs");
  const checkpoint = read("scripts/release/p0c/lib/candidate-checkpoint.mjs");
  const workflow = read(".github/workflows/p0c-hardware-qualification.yml");

  for (const binding of ["artifact_sha256", "source_commit", "team_id"]) {
    assert.match(qualification, new RegExp(binding, "u"));
  }
  for (const binding of ["artifactSha256", "sourceCommit", "teamId", "codeIdentities"]) assert.match(driverRuntime, new RegExp(binding, "u"));
  assert.match(driverRuntime, /code_identities_sha256/u);
  assert.match(scenarioRuntime, /AGENTPASS_P0C_ARTIFACT_SHA256/u);
  assert.match(scenarioRuntime, /AGENTPASS_P0C_SOURCE_COMMIT/u);
  assert.match(scenarioRuntime, /AGENTPASS_P0C_TEAM_ID/u);
  assert.match(checkpoint, /candidate checkpoint artifact binding mismatch/u);
  assert.match(checkpoint, /candidate checkpoint source binding mismatch/u);
  assert.match(checkpoint, /candidate checkpoint Team ID binding mismatch/u);
  assert.match(checkpoint, /export const withVerifiedCandidateCheckpoint/u);
  assert.match(workflow, /verify-release\.mjs/u);
  assert.match(workflow, /verify-macos-release\.sh/u);
  assert.match(workflow, /verify-hardware-qualification-set\.mjs/u);
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/u);

  const evidenceFunction = qualification.match(/const resultEvidence = \(kind, name, result, status\) =>([\s\S]*?);\nconst failedResult/u)?.[1] ?? "";
  assert.notEqual(evidenceFunction, "", "qualification must have a bounded evidence projection");
  assert.match(evidenceFunction, /stdout_bytes/u);
  assert.match(evidenceFunction, /stdout_sha256/u);
  assert.match(evidenceFunction, /stderr_bytes/u);
  assert.match(evidenceFunction, /stderr_sha256/u);
  assert.doesNotMatch(evidenceFunction, /stdout:\s*result\.stdout|stderr:\s*result\.stderr/iu);
  assert.doesNotMatch(evidenceFunction, /private[_-]?key|secret|credential|token|password/iu);
  assert.match(workflow, /operator-private\.pem/iu);
  assert.match(workflow, /Remove private operator key/u);
  assert.doesNotMatch(workflow.match(/actions\/upload-artifact[\s\S]*?Remove private operator key/u)?.[0] ?? "", /operator-private\.pem/iu);
});

test("N3-E physical entrypoints fail closed instead of accepting simulation or partial input", () => {
  const qualification = runCLI("scripts/release/run-p0c-qualification.mjs");
  assert.notEqual(qualification.status, 0);
  assert.match(`${qualification.stdout}${qualification.stderr}`, /invalid P0-C qualification arguments|usage/u);

  const aggregate = runCLI("scripts/release/verify-hardware-qualification-set.mjs");
  assert.notEqual(aggregate.status, 0);
  assert.match(`${aggregate.stdout}${aggregate.stderr}`, /Usage: verify-hardware-qualification-set\.mjs/u);

  const validator = runCLI("scripts/release/validate-hardware-qualification.mjs");
  assert.notEqual(validator.status, 0);
  assert.match(`${validator.stdout}${validator.stderr}`, /Usage: validate-hardware-qualification\.mjs/u);

  const source = read("scripts/release/run-p0c-qualification.mjs");
  assert.match(source, /if \(production && platform !== 'darwin'\)/u);
  assert.match(source, /production qualification cannot use injected runners or metadata/u);
  assert.match(source, /if \(result\.exitCode === 0/u);
  assert.match(source, /status: passed/u);
  assert.match(source, /status: 'skipped'/u);
  assert.match(source, /qualified: production && platform === 'darwin'/u);
});

test("N3-E qualification control stays closed and separate from Agent authority", () => {
  const xpc = read("native/macos/Sources/AgentPassNativeCore/AgentQualificationXPCProtocol.swift");
  const controller = read("native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationFaultController.swift");
  const requirement = read("native/macos/Sources/AgentPassNativeCore/NativeAgentQualificationCodeRequirement.swift");
  const agentProtocol = read("native/macos/Sources/AgentPassNativeCore/AgentXPCProtocol.swift");

  const phases = [
    "pre-cloud",
    "post-cloud-pre-local",
    "post-activation-pre-audit",
    "post-audit-pre-reply",
    "audit-fsync",
    "transport-reply",
  ];
  const scenarios = [
    "pre-cloud-kill",
    "post-cloud-pre-local-kill",
    "post-activation-pre-audit-kill",
    "post-audit-pre-reply-loss",
    "audit-fsync-failure",
    "transport-reply-loss",
  ];

  for (const phase of phases) {
    assert.match(xpc, new RegExp(`= "${phase}"`, "u"));
    assert.match(controller, new RegExp(`= "${phase}"`, "u"));
  }
  for (const scenario of scenarios) assert.match(controller, new RegExp(`= "${scenario}"`, "u"));
  assert.equal((xpc.match(/case \w+ = "/gu) ?? []).length >= phases.length, true);
  assert.match(xpc, /machServiceName = "dev\.agentpass\.n3e-qualification"/u);
  assert.match(requirement, /controllerBundleID = "dev\.agentpass\.qualification-controller"/u);
  assert.match(requirement, /controllerEntitlement = "dev\.agentpass\.qualification-control"/u);
  assert.match(requirement, /certificate leaf\[subject\.OU\]/u);
  assert.doesNotMatch(agentProtocol, /armFault|readStatus|disarmFault|n3e-qualification|qualification-control/u);
});
