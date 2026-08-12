import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  UNINSTALL_CODES,
  executeProductionUninstall,
  planProductionUninstall
} from "../lib/platform-uninstall.mjs";
import { renderRemoval } from "../lib/integrations.mjs";
import { canonicalJson } from "../lib/identity.mjs";

function fixture({ app = true, broker = true, receipt = true, integration = true } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-uninstall-")));
  const home = path.join(root, "home");
  const applications = path.join(root, "Applications");
  const systemLibrary = path.join(root, "Library", "Application Support");
  fs.mkdirSync(path.join(home, "Library", "LaunchAgents"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(home, ".agentpass", "keys"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, ".agentpass", "keys", "id_git_sign"), "protected", { mode: 0o600 });
  fs.mkdirSync(applications, { recursive: true, mode: 0o700 });
  fs.mkdirSync(systemLibrary, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(systemLibrary, "AgentPass"), { recursive: true, mode: 0o700 });
  const manager = path.join(applications, "AgentPass.app", "Contents", "MacOS", "agentpass-native-manager");
  const client = path.join(applications, "AgentPass.app", "Contents", "Library", "HelperTools", "AgentPassNativeClient.app", "Contents", "MacOS", "agentpass-native-client");
  if (app) {
    fs.mkdirSync(path.dirname(manager), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(client), { recursive: true, mode: 0o700 });
    fs.writeFileSync(manager, "manager", { mode: 0o700 });
    fs.writeFileSync(client, "client", { mode: 0o700 });
  }
  const brokerPath = path.join(home, "Library", "LaunchAgents", "dev.agentpass.broker.plist");
  if (broker) fs.writeFileSync(brokerPath, "<key>Label</key><string>dev.agentpass.broker</string><key>ProgramArguments</key><string>agentpassd.mjs</string>", { mode: 0o600 });
  const project = path.join(root, "project");
  fs.mkdirSync(project, { recursive: true, mode: 0o700 });
  const expectedServer = { command: "/usr/local/bin/node", args: ["/opt/agentpass-mcp.mjs"], env: { AGENTPASS_PROJECT_DIR: project } };
  const integrationPath = path.join(project, ".mcp.json");
  if (integration) fs.writeFileSync(integrationPath, JSON.stringify({ keep: true, mcpServers: { other: { command: "other" }, agentpass: expectedServer } }, null, 2) + "\n", { mode: 0o600 });
  const calls = [];
  let packageInstalled = receipt;
  let serviceStatus = app ? "enabled" : "not_registered";
  const run = (command, args) => {
    calls.push({ command, args });
    if (command === manager && args[0] === "unregister") { serviceStatus = "not_registered"; return { status: 0, stdout: JSON.stringify({ ok: true, status: serviceStatus }), stderr: "" }; }
    if (command === manager && args[0] === "status") return { status: 0, stdout: JSON.stringify({ ok: true, status: serviceStatus, bundle_path: path.join(applications, "AgentPass.app"), plist_present: true }), stderr: "" };
    if (command === "/usr/sbin/pkgutil" && args[0] === "--pkg-info") return packageInstalled ? { status: 0, stdout: "package-id: dev.agentpass.installer\n", stderr: "" } : { status: 1, stdout: "", stderr: "No receipt for 'dev.agentpass.installer' found." };
    if (command === "/usr/sbin/pkgutil" && args[0] === "--forget") { packageInstalled = false; return { status: 0, stdout: "", stderr: "" }; }
    return { status: 0, stdout: "", stderr: "" };
  };
  return { root, home, applications, project, expectedServer, manager, brokerPath, calls, run };
}

function options(value) {
  return {
    platform: "darwin",
    systemRoot: value.root,
    homeDir: value.home,
    uid: 0,
    expectedUserOwner: process.getuid(),
    expectedSystemOwner: process.getuid(),
    expectedTeamId: null,
    run: value.run,
    integrations: [{ client: "claude-code", projectDir: value.project, expectedServer: value.expectedServer }]
  };
}

test("dry-run enumerates exact targets and preserves both protected state roots", () => {
  const value = fixture();
  try {
    const plan = planProductionUninstall(options(value));
    assert.equal(plan.code, UNINSTALL_CODES.PLAN_READY);
    assert.equal(plan.dryRun, true);
    assert.deepEqual(plan.targets.map((item) => item.kind), ["service", "service", "package", "application", "integration"]);
    assert.equal(plan.targets.find((item) => item.id === "native-service").status, "enabled");
    assert.equal(plan.targets.find((item) => item.id === "integration-1").code, UNINSTALL_CODES.TARGET_PRESENT);
    assert.equal(plan.preserves.length, 2);
    assert.ok(plan.preserves.every((item) => item.code === UNINSTALL_CODES.PRESERVED));
    assert.equal(fs.existsSync(path.join(value.home, ".agentpass", "keys", "id_git_sign")), true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("execution is explicit, removes only owned targets, and is idempotent", () => {
  const value = fixture();
  try {
    const plan = planProductionUninstall(options(value));
    const preview = executeProductionUninstall(plan, { ...options(value), execute: false });
    assert.equal(preview.code, UNINSTALL_CODES.EXECUTE_REQUIRED);
    assert.equal(fs.existsSync(path.join(value.applications, "AgentPass.app")), true);

    const first = executeProductionUninstall(plan, options(value));
    assert.equal(first.code, UNINSTALL_CODES.COMPLETE);
    assert.equal(fs.existsSync(path.join(value.applications, "AgentPass.app")), false);
    assert.equal(fs.existsSync(value.brokerPath), false);
    assert.equal(fs.existsSync(path.join(value.home, ".agentpass", "keys", "id_git_sign")), true);
    assert.equal(JSON.parse(fs.readFileSync(path.join(value.project, ".mcp.json"), "utf8")).mcpServers.agentpass, undefined);
    assert.deepEqual(value.calls.filter((call) => call.command === "/bin/launchctl")[0].args, ["bootout", `gui/${process.getuid()}/dev.agentpass.broker`]);
    assert.ok(value.calls.some((call) => call.command === value.manager && call.args[0] === "unregister"));
    assert.ok(value.calls.some((call) => call.command === "/usr/sbin/pkgutil" && call.args[0] === "--forget"));

    const second = executeProductionUninstall(plan, options(value));
    assert.equal(second.code, UNINSTALL_CODES.NOOP);
    assert.ok(second.results.every((item) => item.removed === false));
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("user phase preserves unrelated integration bytes and defers privileged targets", () => {
  const value = fixture();
  try {
    const integration = path.join(value.project, ".mcp.json");
    const before = fs.readFileSync(integration, "utf8");
    const expected = renderRemoval({ target: integration, expected_server: value.expectedServer }, before).content;
    const plan = planProductionUninstall({ ...options(value), uid: process.getuid() });
    const result = executeProductionUninstall(plan, { ...options(value), uid: process.getuid(), scope: "user" });
    assert.equal(result.scope, "user");
    assert.equal(fs.existsSync(path.join(value.applications, "AgentPass.app")), true);
    assert.ok(result.results.find((item) => item.id === "application").deferred);
    const after = fs.readFileSync(integration, "utf8");
    assert.equal(JSON.parse(after).keep, true);
    assert.equal(JSON.parse(after).mcpServers.other.command, "other");
    assert.equal(after, expected);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("production user-file removal uses the atomic no-replace helper boundary", () => {
  const value = fixture();
  const calls = [];
  const atomicRename = (request) => {
    calls.push(request);
    assert.equal(request.platform, "darwin");
    assert.equal(request.owner, process.getuid());
    assert.equal(fs.existsSync(request.destination), false);
    fs.renameSync(request.source, request.destination);
  };
  const dependencies = { ...options(value), uid: process.getuid(), requireAtomicRename: true, atomicRename };
  try {
    const result = executeProductionUninstall(planProductionUninstall(dependencies), { ...dependencies, scope: "user" });
    assert.equal(result.code, UNINSTALL_CODES.COMPLETE);
    assert.ok(calls.some((call) => call.source === path.join(value.project, ".mcp.json")));
    assert.ok(calls.some((call) => call.source === value.brokerPath));
    assert.ok(calls.every((call) => call.destination.endsWith(".agentpass-remove.quarantine")));
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("refuses substituted files, insecure parents, and foreign integrations", () => {
  const substituted = fixture({ app: false, broker: false, receipt: false, integration: false });
  try {
    const brokerParent = path.join(substituted.home, "Library", "LaunchAgents");
    fs.symlinkSync(path.join(substituted.root, "project"), path.join(brokerParent, "dev.agentpass.broker.plist"));
    assert.throws(() => planProductionUninstall(options(substituted)), (error) => error.code === UNINSTALL_CODES.UNSAFE_TARGET);
  } finally { fs.rmSync(substituted.root, { recursive: true, force: true }); }

  const hardlinked = fixture({ app: true, broker: false, receipt: false, integration: false });
  try {
    fs.linkSync(hardlinked.manager, path.join(hardlinked.root, "manager-copy"));
    assert.throws(() => planProductionUninstall(options(hardlinked)), (error) => error.code === UNINSTALL_CODES.UNSAFE_TARGET);
  } finally { fs.rmSync(hardlinked.root, { recursive: true, force: true }); }

  const insecure = fixture({ app: false, broker: false, receipt: false, integration: false });
  try {
    fs.chmodSync(path.join(insecure.home, "Library", "LaunchAgents"), 0o777);
    assert.throws(() => planProductionUninstall(options(insecure)), (error) => error.code === UNINSTALL_CODES.UNSAFE_TARGET);
  } finally { fs.rmSync(insecure.root, { recursive: true, force: true }); }

  const foreign = fixture({ app: false, broker: false, receipt: false, integration: true });
  try {
    const text = JSON.stringify({ mcpServers: { agentpass: { command: "user-owned" } } }) + "\n";
    fs.writeFileSync(path.join(foreign.project, ".mcp.json"), text, { mode: 0o600 });
    const plan = planProductionUninstall(options(foreign));
    assert.equal(plan.targets.find((item) => item.kind === "integration").code, UNINSTALL_CODES.NOT_OWNED);
    const result = executeProductionUninstall(plan, options(foreign));
    assert.equal(result.code, UNINSTALL_CODES.NOOP);
    assert.equal(fs.readFileSync(path.join(foreign.project, ".mcp.json"), "utf8"), text);
  } finally { fs.rmSync(foreign.root, { recursive: true, force: true }); }
});

test("rejects non-macOS execution before inspecting mutable state", () => {
  const value = fixture({ app: false, broker: false, receipt: false, integration: false });
  try {
    assert.throws(() => planProductionUninstall({ ...options(value), platform: "linux", run: () => { throw new Error("must not run"); } }), (error) => error.code === UNINSTALL_CODES.UNSUPPORTED_PLATFORM);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("rejects a modified or synthetic uninstall plan and failed unregister postcondition", () => {
  const modified = fixture();
  try {
    const plan = planProductionUninstall(options(modified));
    plan.targets[0].target = "/tmp/substituted";
    assert.throws(() => executeProductionUninstall(plan, options(modified)), { code: UNINSTALL_CODES.INVALID_PLAN });
    assert.throws(() => executeProductionUninstall({ version: 1, operation: "uninstall", dryRun: true, targets: [], preserves: [] }, options(modified)), { code: UNINSTALL_CODES.INVALID_PLAN });
  } finally { fs.rmSync(modified.root, { recursive: true, force: true }); }

  const stale = fixture();
  try {
    const base = options(stale);
    const run = (command, args) => command === stale.manager
      ? { status: 0, stdout: JSON.stringify({ ok: true, status: "enabled", bundle_path: path.join(stale.applications, "AgentPass.app"), plist_present: true }), stderr: "" }
      : stale.run(command, args);
    const plan = planProductionUninstall({ ...base, run });
    assert.throws(() => executeProductionUninstall(plan, { ...base, run }), { code: UNINSTALL_CODES.COMMAND_FAILED });
    assert.equal(fs.existsSync(path.join(stale.applications, "AgentPass.app")), true);
  } finally { fs.rmSync(stale.root, { recursive: true, force: true }); }
});

test("a concurrent integration writer is never overwritten by final installation", () => {
  const value = fixture({ app: false, broker: false, receipt: false });
  try {
    const target = path.join(value.project, ".mcp.json");
    const realLink = fs.linkSync;
    let injected = false;
    const filesystem = Object.create(fs);
    filesystem.linkSync = (source, destination) => {
      if (!injected && destination === target && source.endsWith(".agentpass-remove.replacement")) {
        injected = true;
        fs.writeFileSync(destination, '{"mcpServers":{"other":{"command":"concurrent"}}}\n', { flag: "wx", mode: 0o600 });
      }
      return realLink(source, destination);
    };
    const plan = planProductionUninstall({ ...options(value), fs: filesystem });
    assert.throws(() => executeProductionUninstall(plan, { ...options(value), fs: filesystem, scope: "user" }), { code: UNINSTALL_CODES.UNSAFE_TARGET });
    assert.equal(fs.readFileSync(target, "utf8"), '{"mcpServers":{"other":{"command":"concurrent"}}}\n');
    assert.equal(fs.readdirSync(value.project).some((name) => name.includes(".agentpass-remove.")), true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("a quarantined integration is recovered and completed on the next uninstall", () => {
  const value = fixture({ app: false, broker: false, receipt: false });
  try {
    const target = path.join(value.project, ".mcp.json");
    fs.renameSync(target, `${target}.agentpass-remove.quarantine`);
    const dependencies = options(value);
    const plan = planProductionUninstall(dependencies);
    assert.equal(plan.targets.find((item) => item.kind === "integration").state, "present");
    const result = executeProductionUninstall(plan, { ...dependencies, scope: "user" });
    assert.equal(result.results.find((item) => item.id === "integration-1").removed, true);
    assert.equal(fs.existsSync(`${target}.agentpass-remove.quarantine`), false);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("journal recovery never overwrites a concurrent integration writer", () => {
  const value = fixture({ app: false, broker: false, receipt: false });
  try {
    const target = path.join(value.project, ".mcp.json");
    const quarantine = `${target}.agentpass-remove.quarantine`;
    fs.renameSync(target, quarantine);
    const realLink = fs.linkSync;
    const filesystem = Object.create(fs);
    filesystem.linkSync = (source, destination) => {
      if (source === quarantine && destination === target) fs.writeFileSync(destination, "concurrent\n", { flag: "wx", mode: 0o600 });
      return realLink(source, destination);
    };
    const dependencies = { ...options(value), fs: filesystem };
    const plan = planProductionUninstall(dependencies);
    assert.throws(() => executeProductionUninstall(plan, { ...dependencies, scope: "user" }), { code: UNINSTALL_CODES.UNSAFE_TARGET });
    assert.equal(fs.readFileSync(target, "utf8"), "concurrent\n");
    assert.equal(fs.existsSync(quarantine), true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("application removal writes a canonical root-owned identity manifest and resumes partial deletion", () => {
  const value = fixture({ broker: false, receipt: false, integration: false });
  try {
    const application = path.join(value.applications, "AgentPass.app");
    const manifestPath = `${application}.agentpass-remove.manifest`;
    let crashed = false;
    let fsyncCount = 0;
    const realUnlink = fs.unlinkSync;
    const realFsync = fs.fsyncSync;
    const filesystem = Object.create(fs);
    filesystem.fsyncSync = (descriptor) => { fsyncCount += 1; return realFsync(descriptor); };
    filesystem.unlinkSync = (target) => {
      if (!crashed && typeof target === "string" && target.includes(".agentpass-remove.") && !target.endsWith(".manifest")) {
        crashed = true;
        const error = new Error("simulated process crash during recursive deletion");
        error.code = "SIMULATED_CRASH";
        throw error;
      }
      return realUnlink(target);
    };
    const dependencies = { ...options(value), fs: filesystem };
    const plan = planProductionUninstall(dependencies);
    assert.throws(() => executeProductionUninstall(plan, { ...dependencies, scope: "system" }), { code: "SIMULATED_CRASH" });
    assert.equal(crashed, true);
    assert.ok(fsyncCount > 0);
    assert.equal(fs.existsSync(application), false);
    const manifestStat = fs.lstatSync(manifestPath);
    const manifestText = fs.readFileSync(manifestPath, "utf8");
    const manifest = JSON.parse(manifestText);
    assert.equal(manifestText, `${canonicalJson(manifest)}\n`);
    assert.equal(manifestStat.uid, process.getuid());
    assert.equal(manifestStat.mode & 0o777, 0o600);
    assert.equal(manifest.phase, "deleting");
    assert.equal(manifest.application_identity.bundle_id, "dev.agentpass");
    assert.equal(manifest.application_identity.manager_identifier, "dev.agentpass");
    assert.equal(manifest.application_identity.client_identifier, "dev.agentpass.native-client");
    assert.equal(manifest.application_identity.service_identifier, "dev.agentpass.native-service");
    assert.equal(manifest.root_identity.dev, fs.lstatSync(manifest.quarantine).dev);
    assert.equal(manifest.root_identity.ino, fs.lstatSync(manifest.quarantine).ino);

    const resumePlan = planProductionUninstall(options(value));
    assert.equal(resumePlan.targets.find((item) => item.id === "application").removalJournal, manifest.quarantine);
    const result = executeProductionUninstall(resumePlan, { ...options(value), scope: "system" });
    assert.equal(result.results.find((item) => item.id === "application").removed, true);
    assert.equal(fs.existsSync(manifestPath), false);
    assert.equal(fs.existsSync(manifest.quarantine), false);
    assert.equal(fs.existsSync(path.join(value.home, ".agentpass", "keys", "id_git_sign")), true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("a crash before the app rename resumes from the prepared manifest", () => {
  const value = fixture({ broker: false, receipt: false, integration: false });
  try {
    const application = path.join(value.applications, "AgentPass.app");
    const manifestPath = `${application}.agentpass-remove.manifest`;
    let crashed = false;
    const realRename = fs.renameSync;
    const filesystem = Object.create(fs);
    filesystem.renameSync = (source, destination) => {
      if (!crashed && source === application && destination.includes(".agentpass-remove.")) {
        crashed = true;
        const error = new Error("simulated crash after manifest commit");
        error.code = "SIMULATED_CRASH";
        throw error;
      }
      return realRename(source, destination);
    };
    const dependencies = { ...options(value), fs: filesystem };
    assert.throws(() => executeProductionUninstall(planProductionUninstall(dependencies), { ...dependencies, scope: "system" }), { code: "SIMULATED_CRASH" });
    assert.equal(crashed, true);
    assert.equal(fs.existsSync(application), true);
    assert.equal(JSON.parse(fs.readFileSync(manifestPath, "utf8")).phase, "prepared");

    const resumed = executeProductionUninstall(planProductionUninstall(options(value)), { ...options(value), scope: "system" });
    assert.equal(resumed.results.find((item) => item.id === "application").removed, true);
    assert.equal(fs.existsSync(application), false);
    assert.equal(fs.existsSync(manifestPath), false);
    assert.equal(fs.existsSync(path.join(value.home, ".agentpass", "keys", "id_git_sign")), true);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("resume rejects a substituted app quarantine root and preserves protected state", () => {
  const value = fixture({ broker: false, receipt: false, integration: false });
  try {
    const application = path.join(value.applications, "AgentPass.app");
    let crashed = false;
    const filesystem = Object.create(fs);
    const realUnlink = fs.unlinkSync;
    filesystem.unlinkSync = (target) => {
      if (!crashed && typeof target === "string" && target.includes(".agentpass-remove.") && !target.endsWith(".manifest")) {
        crashed = true;
        const error = new Error("simulated process crash before app deletion completed");
        error.code = "SIMULATED_CRASH";
        throw error;
      }
      return realUnlink(target);
    };
    const dependencies = { ...options(value), fs: filesystem };
    assert.throws(() => executeProductionUninstall(planProductionUninstall(dependencies), { ...dependencies, scope: "system" }), { code: "SIMULATED_CRASH" });
    const manifestPath = `${application}.agentpass-remove.manifest`;
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const originalQuarantine = manifest.quarantine;
    const originalManifest = fs.readFileSync(manifestPath, "utf8");
    const substitutedIdentity = { ...manifest, application_identity: { ...manifest.application_identity, bundle_id: "dev.substituted" } };
    fs.writeFileSync(manifestPath, `${canonicalJson(substitutedIdentity)}\n`, { mode: 0o600 });
    assert.throws(() => planProductionUninstall(options(value)), { code: UNINSTALL_CODES.UNSAFE_TARGET });
    fs.writeFileSync(manifestPath, originalManifest, { mode: 0o600 });
    const backup = `${originalQuarantine}.backup`;
    fs.renameSync(originalQuarantine, backup);
    fs.mkdirSync(originalQuarantine, { mode: 0o700 });
    assert.throws(() => planProductionUninstall(options(value)), { code: UNINSTALL_CODES.UNSAFE_TARGET });
    assert.equal(fs.existsSync(manifestPath), true);
    assert.equal(fs.existsSync(path.join(value.home, ".agentpass", "keys", "id_git_sign")), true);
    fs.rmSync(backup, { recursive: true, force: true });
    fs.rmSync(originalQuarantine, { recursive: true, force: true });
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});
