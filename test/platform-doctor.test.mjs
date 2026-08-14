import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { saveConfig } from "../lib/config.mjs";
import { DOCTOR_SCHEMA_VERSION, runProductionDoctor } from "../lib/platform-doctor.mjs";
import { SETUP_STATES, createSetupJournal } from "../lib/setup-journal.mjs";

const FIXED_CLIENT = "/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client";
const FIXED_MANAGER = "/Applications/AgentPass.app/Contents/MacOS/agentpass-native-manager";

function publicKey() { return crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }); }

function installedReceipt(overrides = {}) {
  return {
    version: 1,
    kind: "agentpass.installed-release-receipt",
    candidate_id: "release-2026-08-15-01",
    manifest_sha256: "a".repeat(64),
    artifact_sha256: "b".repeat(64),
    source_commit: "c".repeat(40),
    team_id: "ABCDE12345",
    release_signer_fingerprint: `SHA256:${"d".repeat(43)}`,
    ...overrides
  };
}

function fixture(targetState = "complete") {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-doctor-")));
  const configDir = path.join(root, "config");
  const project = path.join(root, "project");
  const application = path.join(root, "AgentPass.app");
  fs.mkdirSync(project);
  fs.mkdirSync(application);
  const agentKey = publicKey();
  saveConfig({
    version: 4,
    agent: { name: "doctor-agent" },
    agents: [{
      id: "11111111-1111-4111-8111-111111111111",
      name: "doctor-agent",
      public_key: agentKey,
      scope: { operations: ["git.commit.sign"], repositories: [project], branches: { allow: ["feature/*"], deny: ["main"] }, remotes: { allow: [] } }
    }],
    default_agent_id: "11111111-1111-4111-8111-111111111111",
    operations: ["git.commit.sign"],
    repositories: [project],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: [] },
    audit_signing: { public_key: publicKey() },
    session: { required: true, ttl_seconds: 3600 },
    native_broker: { enabled: true, mach_service: "dev.agentpass.native-service", client: FIXED_CLIENT, manager: FIXED_MANAGER, team_id: "ABCDE12345" }
  }, configDir);
  const journal = createSetupJournal({ directory: configDir, clock: () => "2030-01-01T00:00:00.000Z" });
  const targetIndex = SETUP_STATES.indexOf(targetState);
  if (targetIndex < 0) throw new Error(`Unknown fixture state: ${targetState}`);
  for (const state of SETUP_STATES.slice(1, targetIndex + 1)) journal.transition(state);
  fs.writeFileSync(path.join(project, ".mcp.json"), `${JSON.stringify({ mcpServers: { agentpass: { command: process.execPath, args: ["/agentpass-mcp.mjs"], env: { AGENTPASS_PROJECT_DIR: project } } } })}\n`, { mode: 0o600 });
  return { root, configDir, project, application };
}

function successfulRun(command, args) {
  if (command.endsWith("codesign") && args[0] === "-dv") return { status: 0, stdout: "", stderr: "TeamIdentifier=ABCDE12345\n" };
  return { status: 0, stdout: command.endsWith("pkgutil") ? "package-id: dev.agentpass.installer\n" : "ok\n", stderr: "" };
}

test("production doctor returns stable healthy checks without leaking local paths", async () => {
  const value = fixture();
  try {
    const report = await runProductionDoctor({ configDir: value.configDir, application: value.application, expectedAppOwner: process.getuid(), expectedTeamId: "ABCDE12345", client: "claude-code", projectDir: value.project }, {
      platform: "darwin",
      architecture: "arm64",
      nodeVersion: "22.14.0",
      now: () => new Date("2026-08-12T00:00:00.000Z"),
      run: successfulRun,
      inspectApplication: () => ({ serviceStatus: "enabled", requiresApproval: false }),
      nativeStatus: async () => ({ ok: true }),
      readInstalledReleaseReceipt: () => installedReceipt()
    });
    assert.equal(report.schema_version, DOCTOR_SCHEMA_VERSION);
    assert.equal(report.state, "healthy");
    assert.equal(report.ok, true);
    assert.equal(report.mode, "production-native");
    assert.equal(report.checks.every((item) => item.id && item.state === "healthy"), true);
    assert.equal(report.checks.find((item) => item.id === "release.installed_receipt").state, "healthy");
    assert.equal(report.checks.find((item) => item.id === "release.receipt_team_id").state, "healthy");
    assert.equal(JSON.stringify(report).includes(value.root), false);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("doctor fails closed when the public release receipt is unavailable or unsafe", async () => {
  const value = fixture();
  try {
    const report = await runProductionDoctor({ configDir: value.configDir, application: value.application, expectedAppOwner: process.getuid(), expectedTeamId: "ABCDE12345", client: "claude-code", projectDir: value.project }, {
      platform: "darwin",
      architecture: "arm64",
      nodeVersion: "22.14.0",
      run: successfulRun,
      inspectApplication: () => ({ serviceStatus: "enabled", requiresApproval: false }),
      nativeStatus: async () => ({ ok: true }),
      readInstalledReleaseReceipt: () => {
        const error = new Error(`receipt unavailable at ${value.root}/private/receipt.json`);
        error.code = "INSTALLED_RECEIPT_INVALID";
        throw error;
      }
    });
    assert.equal(report.checks.find((item) => item.id === "release.installed_receipt").state, "blocked");
    assert.equal(report.checks.find((item) => item.id === "release.receipt_team_id").state, "blocked");
    assert.equal(JSON.stringify(report).includes(value.root), false);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("doctor rejects a public receipt whose Team ID differs from the inspected signed app", async () => {
  const value = fixture();
  try {
    const report = await runProductionDoctor({ configDir: value.configDir, application: value.application, expectedAppOwner: process.getuid(), expectedTeamId: "ABCDE12345", client: "claude-code", projectDir: value.project }, {
      platform: "darwin",
      nodeVersion: "22.14.0",
      run: successfulRun,
      inspectApplication: () => ({ serviceStatus: "enabled", requiresApproval: false }),
      nativeStatus: async () => ({ ok: true }),
      readInstalledReleaseReceipt: () => installedReceipt({ team_id: "ZZZZZZZZZZ" })
    });
    assert.equal(report.checks.find((item) => item.id === "release.installed_receipt").state, "healthy");
    const teamCheck = report.checks.find((item) => item.id === "release.receipt_team_id");
    assert.equal(teamCheck.state, "blocked");
    assert.match(teamCheck.remediation, /verified production PKG/);
    assert.equal(JSON.stringify(report).includes("ZZZZZZZZZZ"), false);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("doctor gives browser-assisted remediation at service_keys_activated", async () => {
  const value = fixture("service_keys_activated");
  try {
    const report = await runProductionDoctor({ configDir: value.configDir, application: value.application, expectedAppOwner: process.getuid(), expectedTeamId: "ABCDE12345", client: "claude-code", projectDir: value.project }, {
      platform: "darwin",
      nodeVersion: "22.14.0",
      run: successfulRun,
      inspectApplication: () => ({ serviceStatus: "enabled", requiresApproval: false }),
      nativeStatus: async () => ({ ok: true }),
      readInstalledReleaseReceipt: () => installedReceipt()
    });
    const onboarding = report.checks.find((item) => item.id === "setup.onboarding");
    assert.equal(onboarding.state, "action_required");
    assert.equal(onboarding.remediation, "Run `agentpass setup continue --execute --browser --console-url HTTPS_CONSOLE --enrollment-url HTTPS_API/v1` to finish device enrollment.");
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("doctor reports actionable setup state and stable blocked failures", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-doctor-empty-"));
  try {
    const report = await runProductionDoctor({ configDir: root, client: "claude-code", projectDir: root }, {
      platform: "linux",
      architecture: "x64",
      nodeVersion: "18.0.0",
      now: () => new Date("2026-08-12T00:00:00.000Z"),
      run: () => ({ status: 1, stdout: "", stderr: "missing" })
    });
    assert.equal(report.state, "blocked");
    assert.equal(report.ok, false);
    assert.equal(report.checks.find((item) => item.id === "runtime.node").state, "blocked");
    assert.equal(report.checks.find((item) => item.id === "config.local").state, "action_required");
    assert.equal(report.checks.every((item) => typeof item.remediation === "string" || item.state === "healthy"), true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("doctor fails closed on native application and service substitution", async () => {
  const value = fixture();
  try {
    const report = await runProductionDoctor({ configDir: value.configDir, application: value.application, expectedAppOwner: process.getuid(), client: "claude-code", projectDir: value.project, verbose: true }, {
      platform: "darwin",
      nodeVersion: "22.14.0",
      run: successfulRun,
      inspectApplication: () => { throw new Error("substituted manager"); },
      nativeStatus: async () => { throw new Error("XPC identity rejected"); }
    });
    assert.equal(report.state, "blocked");
    assert.match(report.checks.find((item) => item.id === "app.layout").detail, /substituted/);
    assert.match(report.checks.find((item) => item.id === "service.health").detail, /XPC identity/);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});
