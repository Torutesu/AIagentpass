import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { renderRemoval } from "./integrations.mjs";

const PACKAGE_ID = "dev.agentpass.installer";
const APP_RELATIVE = path.join("Applications", "AgentPass.app");
const SYSTEM_STATE_RELATIVE = path.join("Library", "Application Support", "AgentPass");
const NATIVE_DAEMON_PLIST = "dev.agentpass.native-service.plist";
const NATIVE_SERVICE_LABEL = "dev.agentpass.native-service";
const BROKER_LABEL = "dev.agentpass.broker";
const BROKER_PLIST_NAME = `${BROKER_LABEL}.plist`;
const BROKER_PLIST_RELATIVE = path.join("Library", "LaunchAgents", BROKER_PLIST_NAME);
const CLIENTS = Object.freeze({
  "claude-code": ".mcp.json",
  cursor: path.join(".cursor", "mcp.json")
});
const ISSUED_PLANS = new WeakMap();

export const UNINSTALL_CODES = Object.freeze({
  PLAN_READY: "UNINSTALL_PLAN_READY",
  EXECUTE_REQUIRED: "UNINSTALL_EXECUTE_REQUIRED",
  COMPLETE: "UNINSTALL_COMPLETE",
  NOOP: "UNINSTALL_NOOP",
  TARGET_PRESENT: "TARGET_PRESENT",
  TARGET_ABSENT: "TARGET_ABSENT",
  REMOVED: "TARGET_REMOVED",
  PRESERVED: "PROTECTED_STATE_PRESERVED",
  NOT_OWNED: "TARGET_NOT_AGENTPASS_OWNED",
  UNSUPPORTED_PLATFORM: "UNSUPPORTED_PLATFORM",
  INVALID_PLAN: "INVALID_UNINSTALL_PLAN",
  INVALID_TARGET: "INVALID_UNINSTALL_TARGET",
  UNSAFE_TARGET: "UNSAFE_UNINSTALL_TARGET",
  COMMAND_FAILED: "UNINSTALL_COMMAND_FAILED",
  ROOT_REQUIRED: "UNINSTALL_ROOT_REQUIRED"
});

export const UNINSTALL_TARGETS = Object.freeze({
  application: APP_RELATIVE,
  packageId: PACKAGE_ID,
  nativeService: NATIVE_SERVICE_LABEL,
  nativeDaemonPlist: NATIVE_DAEMON_PLIST,
  brokerService: BROKER_LABEL,
  brokerPlist: BROKER_PLIST_NAME,
  integrations: Object.freeze(Object.keys(CLIENTS))
});

export class ProductionUninstallError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProductionUninstallError";
    this.code = code;
  }
}

const defaultRun = (command, args) => spawnSync(command, args, {
  encoding: "utf8",
  env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
});

function fail(code, message) {
  throw new ProductionUninstallError(code, message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function absolute(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    fail(UNINSTALL_CODES.INVALID_TARGET, `${label} must be an absolute path`);
  }
  return path.resolve(value);
}

function uidOf(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function contextFrom(options = {}, dependencies = {}) {
  const source = { ...dependencies, ...options };
  const uid = uidOf(source.uid) ?? uidOf(process.getuid?.());
  const homeDir = absolute(source.homeDir ?? os.homedir(), "homeDir");
  const systemRoot = absolute(source.systemRoot ?? "/", "systemRoot");
  const userOwner = uidOf(source.expectedUserOwner) ?? uid;
  const systemOwner = uidOf(source.expectedSystemOwner) ?? 0;
  if (uid === undefined || userOwner === undefined || systemOwner === undefined) {
    fail(UNINSTALL_CODES.INVALID_TARGET, "uninstall ownership identities must be numeric");
  }
  return {
    fs: source.fs ?? fs,
    run: source.run ?? defaultRun,
    platform: source.platform ?? process.platform,
    uid,
    userOwner,
    systemOwner,
    expectedUserOwner: userOwner,
    expectedSystemOwner: systemOwner,
    homeDir,
    systemRoot,
    includeUser: source.includeUser !== false,
    integrations: source.integrations ?? source.integrationTargets ?? []
  };
}

function pathExists(filesystem, target) {
  try {
    return filesystem.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function safeDirectory(filesystem, directory, owner, label) {
  const stat = filesystem.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} is not a trusted directory: ${directory}`);
  }
  return stat;
}

function safeParentChain(filesystem, parent, boundary, owner, label) {
  const resolvedParent = absolute(parent, `${label} parent`);
  const resolvedBoundary = absolute(boundary, `${label} boundary`);
  const relative = path.relative(resolvedBoundary, resolvedParent);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} parent escapes its trusted boundary`);
  }
  let current = resolvedBoundary;
  safeDirectory(filesystem, current, owner, label);
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = pathExists(filesystem, current);
    if (!stat) return;
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} has an unsafe parent: ${current}`);
    }
  }
}

function safeRegularFile(filesystem, file, owner, label) {
  const stat = filesystem.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} is not a trusted single-link file: ${file}`);
  }
  return stat;
}

function safeExecutable(filesystem, file, owner, label) {
  const stat = safeRegularFile(filesystem, file, owner, label);
  if ((stat.mode & 0o111) === 0) fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} is not executable: ${file}`);
  return stat;
}

function validateTree(filesystem, root, owner, label, rootDevice = undefined) {
  const stat = safeDirectory(filesystem, root, owner, label);
  const device = rootDevice ?? stat.dev;
  for (const entry of filesystem.readdirSync(root, { withFileTypes: true })) {
    const child = path.join(root, entry.name);
    const childStat = filesystem.lstatSync(child);
    if (childStat.dev !== undefined && device !== undefined && childStat.dev !== device) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} crosses a filesystem boundary: ${child}`);
    }
    if (childStat.isSymbolicLink()) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} contains a symlink: ${child}`);
    }
    if (childStat.isDirectory()) {
      if (childStat.uid !== owner || (childStat.mode & 0o022) !== 0) {
        fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} contains an unsafe directory: ${child}`);
      }
      validateTree(filesystem, child, owner, label, device);
    } else if (!childStat.isFile() || childStat.nlink !== 1 || childStat.uid !== owner || (childStat.mode & 0o022) !== 0) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} contains an unsafe file: ${child}`);
    }
  }
  return stat;
}

function fsyncDirectory(filesystem, directory) {
  try {
    const descriptor = filesystem.openSync(directory, "r");
    try { filesystem.fsyncSync(descriptor); } finally { filesystem.closeSync(descriptor); }
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP'].includes(error?.code)) throw error;
  }
}

function applicationRemovalJournal(context, appParent) {
  const prefix = "AgentPass.app.agentpass-remove.";
  const matches = context.fs.readdirSync(appParent).filter((name) => name.startsWith(prefix));
  if (matches.some((name) => !/^AgentPass\.app\.agentpass-remove\.[0-9a-f]{32}$/.test(name)) || matches.length > 1) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal journal is ambiguous");
  }
  if (matches.length === 0) return null;
  const journal = path.join(appParent, matches[0]);
  validateTree(context.fs, journal, context.systemOwner, "Application removal journal");
  return journal;
}

function targetResult(id, kind, target, state, code, extra = {}) {
  return { id, kind, target, state, code, ...extra };
}

function planDigest(plan) {
  return crypto.createHash("sha256").update(JSON.stringify(plan)).digest("hex");
}

function commandResult(context, command, args, label) {
  const result = context.run(command, args);
  if (!result || typeof result.status !== "number") {
    fail(UNINSTALL_CODES.COMMAND_FAILED, `${label} returned an invalid result`);
  }
  return result;
}

function packageStatus(context) {
  const result = commandResult(context, "/usr/sbin/pkgutil", ["--pkg-info", PACKAGE_ID], "Package receipt status");
  if (result.status === 0) return "present";
  const detail = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (/no receipt|not found|does not exist|no such package/i.test(detail)) return "absent";
  fail(UNINSTALL_CODES.COMMAND_FAILED, `Unable to inspect package receipt ${PACKAGE_ID}`);
}

function managerStatus(context, app, manager) {
  safeRegularFile(context.fs, manager, context.systemOwner, "Native manager");
  const result = commandResult(context, manager, ["status"], "Native manager status");
  if (result.status !== 0) fail(UNINSTALL_CODES.COMMAND_FAILED, result.stderr?.trim() || "Native manager status failed");
  let status;
  try { status = JSON.parse(result.stdout); } catch { fail(UNINSTALL_CODES.COMMAND_FAILED, "Native manager returned invalid status JSON"); }
  if (!isObject(status) || status.ok !== true || status.bundle_path !== app || status.plist_present !== true || !["not_registered", "enabled", "requires_approval"].includes(status.status)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Native manager returned an untrusted service status");
  }
  return status;
}

function brokerOwned(text) {
  return text.includes(`<key>Label</key><string>${BROKER_LABEL}</string>`)
    && text.includes("<key>ProgramArguments</key>")
    && text.includes("agentpassd.mjs");
}

function integrationDefinition(descriptor, context) {
  if (!isObject(descriptor) || !Object.hasOwn(descriptor, "client") || !Object.hasOwn(CLIENTS, descriptor.client)) {
    fail(UNINSTALL_CODES.INVALID_TARGET, "integration client is not allowlisted");
  }
  const projectDir = absolute(descriptor.projectDir, "integration projectDir");
  const target = path.join(projectDir, CLIENTS[descriptor.client]);
  const expectedServer = descriptor.expectedServer ?? (
    typeof descriptor.nodePath === "string" && typeof descriptor.mcpServerPath === "string"
      ? { command: absolute(descriptor.nodePath, "integration nodePath"), args: [absolute(descriptor.mcpServerPath, "integration mcpServerPath")], env: { AGENTPASS_PROJECT_DIR: projectDir } }
      : null
  );
  if (!isObject(expectedServer)) fail(UNINSTALL_CODES.INVALID_TARGET, "integration expectedServer is required");
  if (target === context.homeDir || target.startsWith(`${context.homeDir}${path.sep}.agentpass${path.sep}`)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "integration target overlaps protected AgentPass state");
  }
  return { client: descriptor.client, projectDir, target, expectedServer };
}

function integrationState(context, definition) {
  const parent = path.dirname(definition.target);
  if (!pathExists(context.fs, definition.projectDir)) return { state: "absent", code: UNINSTALL_CODES.TARGET_ABSENT };
  safeParentChain(context.fs, parent, definition.projectDir, context.userOwner, "Integration");
  const recovery = inspectIntegrationRecovery(context, definition);
  if (recovery) return { state: "present", code: UNINSTALL_CODES.TARGET_PRESENT, recovery };
  const stat = pathExists(context.fs, definition.target);
  if (!stat) return { state: "absent", code: UNINSTALL_CODES.TARGET_ABSENT };
  safeRegularFile(context.fs, definition.target, context.userOwner, "Integration file");
  if (stat.size > 1024 * 1024) fail(UNINSTALL_CODES.UNSAFE_TARGET, `Integration file is too large: ${definition.target}`);
  let rendered;
  try {
    rendered = renderRemoval({ target: definition.target, expected_server: definition.expectedServer }, context.fs.readFileSync(definition.target, "utf8"));
  } catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, `Integration file cannot be removed safely: ${definition.target}`); }
  if (rendered.changed) return { state: "present", code: UNINSTALL_CODES.TARGET_PRESENT };
  return rendered.reason === "not_agentpass_owned"
    ? { state: "foreign", code: UNINSTALL_CODES.NOT_OWNED }
    : { state: "absent", code: UNINSTALL_CODES.TARGET_ABSENT };
}

function protectedState(context, target, owner, label, boundary) {
  safeParentChain(context.fs, path.dirname(target), boundary, owner, label);
  const stat = pathExists(context.fs, target);
  if (stat && (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== owner || (stat.mode & 0o022) !== 0)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} is not a trusted protected directory: ${target}`);
  }
  return { id: label.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-"), kind: "protected-state", target, state: stat ? "present" : "absent", code: UNINSTALL_CODES.PRESERVED };
}

function buildPlan(options, dependencies) {
  const context = contextFrom(options, dependencies);
  if (context.platform !== "darwin") fail(UNINSTALL_CODES.UNSUPPORTED_PLATFORM, "Production AgentPass uninstall is supported only on macOS");
  if (context.includeUser) safeDirectory(context.fs, context.homeDir, context.userOwner, "Home");
  safeDirectory(context.fs, context.systemRoot, context.systemOwner, "System root");

  const app = path.join(context.systemRoot, APP_RELATIVE);
  const appParent = path.dirname(app);
  safeParentChain(context.fs, appParent, context.systemRoot, context.systemOwner, "Application");
  const appStat = pathExists(context.fs, app);
  const appJournal = applicationRemovalJournal(context, appParent);
  if (appStat && appJournal) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application and removal journal both exist");
  let manager = path.join(app, "Contents", "MacOS", "agentpass-native-manager");
  let nativeStatus = { status: "not_registered" };
  if (appStat) {
    validateTree(context.fs, app, context.systemOwner, "AgentPass application");
    safeExecutable(context.fs, manager, context.systemOwner, "Native manager");
    const client = path.join(app, "Contents", "Library", "HelperTools", "AgentPassNativeClient.app", "Contents", "MacOS", "agentpass-native-client");
    safeExecutable(context.fs, client, context.systemOwner, "Native client");
    nativeStatus = managerStatus(context, app, manager);
  }

  const broker = path.join(context.homeDir, BROKER_PLIST_RELATIVE);
  if (context.includeUser) safeParentChain(context.fs, path.dirname(broker), context.homeDir, context.userOwner, "Broker LaunchAgent");
  const brokerQuarantine = `${broker}.agentpass-remove.quarantine`;
  const brokerStat = context.includeUser ? pathExists(context.fs, broker) : null;
  const brokerJournalStat = context.includeUser ? pathExists(context.fs, brokerQuarantine) : null;
  if (brokerJournalStat) {
    safeRecoveryFile(context, brokerQuarantine, "Broker LaunchAgent removal journal");
    const journalIdentity = context.fs.lstatSync(brokerQuarantine);
    if (brokerStat) {
      safeRecoveryFile(context, broker, "Broker LaunchAgent");
      const targetIdentity = context.fs.lstatSync(broker);
      if (targetIdentity.dev !== journalIdentity.dev || targetIdentity.ino !== journalIdentity.ino) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Concurrent Broker LaunchAgent changes require manual recovery");
    }
    if (!brokerOwned(context.fs.readFileSync(brokerQuarantine, "utf8"))) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Broker LaunchAgent removal journal is invalid");
  }
  if (brokerStat) {
    safeRegularFile(context.fs, broker, context.userOwner, "Broker LaunchAgent");
    const brokerText = context.fs.readFileSync(broker, "utf8");
    if (!brokerOwned(brokerText)) fail(UNINSTALL_CODES.UNSAFE_TARGET, `Broker LaunchAgent is not an AgentPass-owned registration: ${broker}`);
  }

  const receiptState = packageStatus(context);
  const definitions = context.includeUser ? context.integrations.map((descriptor) => integrationDefinition(descriptor, context)) : [];
  const targets = [
    targetResult("native-service", "service", manager, nativeStatus.status === "not_registered" ? "absent" : "present", nativeStatus.status === "not_registered" ? UNINSTALL_CODES.TARGET_ABSENT : UNINSTALL_CODES.TARGET_PRESENT, { label: NATIVE_SERVICE_LABEL, status: nativeStatus.status }),
    targetResult("broker-launch-agent", "service", broker, brokerStat || brokerJournalStat ? "present" : "absent", brokerStat || brokerJournalStat ? UNINSTALL_CODES.TARGET_PRESENT : UNINSTALL_CODES.TARGET_ABSENT, { label: BROKER_LABEL }),
    targetResult("package-receipt", "package", PACKAGE_ID, receiptState, receiptState === "present" ? UNINSTALL_CODES.TARGET_PRESENT : UNINSTALL_CODES.TARGET_ABSENT),
    targetResult("application", "application", app, appStat || appJournal ? "present" : "absent", appStat || appJournal ? UNINSTALL_CODES.TARGET_PRESENT : UNINSTALL_CODES.TARGET_ABSENT, { removalJournal: appJournal }),
    ...definitions.map((definition, index) => {
      const state = integrationState(context, definition);
      return targetResult(`integration-${index + 1}`, "integration", definition.target, state.state, state.code, { client: definition.client, projectDir: definition.projectDir, expectedServer: definition.expectedServer });
    })
  ];
  const protectedTargets = [
    ...(context.includeUser ? [protectedState(context, path.join(context.homeDir, ".agentpass"), context.userOwner, "user-protected-state", context.homeDir)] : []),
    protectedState(context, path.join(context.systemRoot, SYSTEM_STATE_RELATIVE), context.systemOwner, "system-protected-state", context.systemRoot)
  ];
  return {
    version: 1,
    operation: "uninstall",
    dryRun: true,
    code: UNINSTALL_CODES.PLAN_READY,
    homeDir: context.homeDir,
    systemRoot: context.systemRoot,
    uid: context.uid,
    expectedUserOwner: context.userOwner,
    expectedSystemOwner: context.systemOwner,
    includeUser: context.includeUser,
    packageId: PACKAGE_ID,
    requiresRoot: targets.some((item) => ["application", "package", "native-service"].includes(item.kind) && item.state === "present"),
    preserves: protectedTargets,
    targets
  };
}

export function planProductionUninstall(options = {}, dependencies = {}) {
  const plan = buildPlan(options, dependencies);
  ISSUED_PLANS.set(plan, planDigest(plan));
  return plan;
}

export const prepareProductionUninstall = planProductionUninstall;
export const createProductionUninstallPlan = planProductionUninstall;

function validatePlan(plan) {
  if (!isObject(plan) || plan.version !== 1 || plan.operation !== "uninstall" || plan.dryRun !== true || !Array.isArray(plan.targets) || !Array.isArray(plan.preserves)) {
    fail(UNINSTALL_CODES.INVALID_PLAN, "Expected a dry-run AgentPass uninstall plan");
  }
  if (ISSUED_PLANS.get(plan) !== planDigest(plan)) fail(UNINSTALL_CODES.INVALID_PLAN, "Uninstall plan was not issued by this process or was modified after preview");
}

function benignServiceFailure(result) {
  return /not found|no such process|could not find|does not exist|not loaded/i.test(`${result.stdout ?? ""}\n${result.stderr ?? ""}`);
}

function restoreQuarantine(context, quarantine, target) {
  try {
    context.fs.linkSync(quarantine, target);
    fsyncDirectory(context.fs, path.dirname(target));
    context.fs.unlinkSync(quarantine);
    fsyncDirectory(context.fs, path.dirname(target));
    return true;
  } catch { return false; }
}

function quarantineValidatedFile(context, target, expected, validate, label) {
  const quarantine = `${target}.agentpass-remove.quarantine`;
  try { context.fs.linkSync(target, quarantine); }
  catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} has an unresolved or competing removal journal`); }
  try {
    const current = context.fs.lstatSync(quarantine);
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 2 || current.uid !== expected.uid || (current.mode & 0o022) !== 0) {
      context.fs.unlinkSync(quarantine);
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} journal reservation is unsafe`);
    }
    if (current.dev !== expected.dev || current.ino !== expected.ino || current.mtimeMs !== expected.mtimeMs || current.size !== expected.size || !validate(quarantine)) {
      context.fs.unlinkSync(quarantine);
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} changed during removal`);
    }
    const live = context.fs.lstatSync(target);
    if (live.dev !== current.dev || live.ino !== current.ino) {
      context.fs.unlinkSync(quarantine);
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} changed during journal reservation`);
    }
    fsyncDirectory(context.fs, path.dirname(target));
    context.fs.unlinkSync(target);
    fsyncDirectory(context.fs, path.dirname(target));
    if (context.fs.lstatSync(quarantine).nlink !== 1) fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} journal reservation did not stabilize`);
    return quarantine;
  } catch (error) {
    if (pathExists(context.fs, quarantine) && !pathExists(context.fs, target)) restoreQuarantine(context, quarantine, target);
    throw error;
  }
}

function integrationRecoveryPaths(target) {
  return {
    quarantine: `${target}.agentpass-remove.quarantine`,
    replacement: `${target}.agentpass-remove.replacement`
  };
}

function safeRecoveryFile(context, file, label) {
  const stat = context.fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || ![1, 2].includes(stat.nlink) || stat.uid !== context.userOwner || (stat.mode & 0o022) !== 0 || stat.size > 1024 * 1024) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} is unsafe`);
  }
  return context.fs.readFileSync(file, "utf8");
}

function inspectIntegrationRecovery(context, definition) {
  const paths = integrationRecoveryPaths(definition.target);
  const quarantineStat = pathExists(context.fs, paths.quarantine);
  const replacementStat = pathExists(context.fs, paths.replacement);
  if (!quarantineStat && !replacementStat) return null;
  let quarantined = null;
  let replacement = null;
  if (quarantineStat) {
    quarantined = safeRecoveryFile(context, paths.quarantine, "Integration removal quarantine");
    let rendered;
    try { rendered = renderRemoval({ target: definition.target, expected_server: definition.expectedServer }, quarantined); }
    catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, "Integration removal quarantine is invalid"); }
    if (!rendered.changed) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Integration removal quarantine is not AgentPass-owned");
    replacement = rendered.content;
  }
  if (replacementStat) {
    const staged = safeRecoveryFile(context, paths.replacement, "Integration removal replacement");
    if (replacement !== null && staged !== replacement) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Integration removal journal is inconsistent");
  }
  const targetStat = pathExists(context.fs, definition.target);
  if (targetStat && quarantineStat) {
    safeRecoveryFile(context, definition.target, "Integration recovery target");
    if (targetStat.dev === quarantineStat.dev && targetStat.ino === quarantineStat.ino) return "journal_reserved";
    const targetText = context.fs.readFileSync(definition.target, "utf8");
    if (targetText !== replacement) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Concurrent integration changes require manual recovery");
  }
  return quarantineStat ? "quarantined" : "replacement_staged";
}

function recoverIntegrationRemoval(context, definition) {
  if (!inspectIntegrationRecovery(context, definition)) return;
  const paths = integrationRecoveryPaths(definition.target);
  const quarantine = pathExists(context.fs, paths.quarantine);
  const target = pathExists(context.fs, definition.target);
  if (quarantine && !target) {
    if (!restoreQuarantine(context, paths.quarantine, definition.target)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Concurrent integration changes prevented journal recovery");
  } else if (quarantine && target) {
    context.fs.unlinkSync(paths.quarantine);
  }
  if (pathExists(context.fs, paths.replacement)) context.fs.unlinkSync(paths.replacement);
  fsyncDirectory(context.fs, path.dirname(definition.target));
}

function removeIntegration(context, target) {
  const definition = { client: target.client, projectDir: target.projectDir, target: target.target, expectedServer: target.expectedServer };
  recoverIntegrationRemoval(context, definition);
  const state = integrationState(context, definition);
  if (state.code === UNINSTALL_CODES.TARGET_ABSENT || state.code === UNINSTALL_CODES.NOT_OWNED) return { id: target.id, code: state.code, removed: false };
  const descriptor = context.fs.openSync(target.target, "r");
  let before, sourceStat;
  try { sourceStat = context.fs.fstatSync(descriptor); before = context.fs.readFileSync(descriptor, "utf8"); }
  catch (error) { context.fs.closeSync(descriptor); throw error; }
  let rendered;
  try { rendered = renderRemoval({ target: target.target, expected_server: target.expectedServer }, before); }
  catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, `Integration file cannot be removed safely: ${target.target}`); }
  if (!rendered.changed) return { id: target.id, code: rendered.reason === "not_agentpass_owned" ? UNINSTALL_CODES.NOT_OWNED : UNINSTALL_CODES.TARGET_ABSENT, removed: false };
  safeParentChain(context.fs, path.dirname(target.target), target.projectDir, context.userOwner, "Integration");
  const stat = safeRegularFile(context.fs, target.target, context.userOwner, "Integration file");
  const temporary = integrationRecoveryPaths(target.target).replacement;
  try {
    const outputDescriptor = context.fs.openSync(temporary, "wx", stat.mode & 0o777);
    try {
      context.fs.writeFileSync(outputDescriptor, rendered.content, "utf8");
      context.fs.fsyncSync(outputDescriptor);
    } finally { context.fs.closeSync(outputDescriptor); }
    const currentStat = safeRegularFile(context.fs, target.target, context.userOwner, "Integration file");
    const heldStat = context.fs.fstatSync(descriptor);
    if (currentStat.dev !== sourceStat.dev || currentStat.ino !== sourceStat.ino || heldStat.size !== sourceStat.size || heldStat.mtimeMs !== sourceStat.mtimeMs) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Integration file changed during removal");
    const current = context.fs.readFileSync(target.target, "utf8");
    if (current !== before) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Integration file changed during removal");
    context.fs.closeSync(descriptor);
    const quarantine = quarantineValidatedFile(context, target.target, {
      dev: sourceStat.dev,
      ino: sourceStat.ino,
      mtimeMs: sourceStat.mtimeMs,
      size: sourceStat.size,
      uid: context.userOwner,
    }, (file) => context.fs.readFileSync(file, "utf8") === before, "Integration file");
    try {
      // link(2) is an atomic no-replace install: a concurrently-created target
      // makes this fail instead of overwriting unrelated editor changes.
      context.fs.linkSync(temporary, target.target);
    } catch (error) {
      restoreQuarantine(context, quarantine, target.target);
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `Integration file changed during final installation: ${target.target}`, error);
    }
    context.fs.unlinkSync(temporary);
    context.fs.unlinkSync(quarantine);
    try {
      const parentDescriptor = context.fs.openSync(path.dirname(target.target), "r");
      try { context.fs.fsyncSync(parentDescriptor); } finally { context.fs.closeSync(parentDescriptor); }
    } catch (error) { if (!['EINVAL', 'ENOTSUP'].includes(error?.code)) throw error; }
  } finally {
    try { context.fs.closeSync(descriptor); } catch {}
    try { context.fs.unlinkSync(temporary); } catch {}
  }
  return { id: target.id, code: UNINSTALL_CODES.REMOVED, removed: true };
}

function executeCurrentPlan(context, current, scope) {
  if ((scope === "all" || scope === "system") && current.requiresRoot && context.uid !== 0) fail(UNINSTALL_CODES.ROOT_REQUIRED, "Production application, service, or package removal requires root");
  const results = [];
  const byId = new Map(current.targets.map((item) => [item.id, item]));

  const native = byId.get("native-service");
  if (scope === "user") {
    results.push({ id: "native-service", code: UNINSTALL_CODES.TARGET_PRESENT, removed: false, deferred: native?.state === "present" });
  } else
  if (native?.state === "present") {
    const result = commandResult(context, native.target, ["unregister"], "Native service unregister");
    if (result.status !== 0) fail(UNINSTALL_CODES.COMMAND_FAILED, result.stderr?.trim() || "Native service unregister failed");
    let response;
    try { response = JSON.parse(result.stdout); } catch { fail(UNINSTALL_CODES.COMMAND_FAILED, "Native service unregister returned invalid status JSON"); }
    if (!isObject(response) || response.ok !== true || response.status !== "not_registered") fail(UNINSTALL_CODES.COMMAND_FAILED, "Native service remains registered after unregister");
    const confirmed = managerStatus(context, path.dirname(path.dirname(path.dirname(native.target))), native.target);
    if (confirmed.status !== "not_registered") fail(UNINSTALL_CODES.COMMAND_FAILED, "Native service unregister postcondition failed");
    results.push({ id: native.id, code: UNINSTALL_CODES.REMOVED, removed: true });
  } else results.push({ id: "native-service", code: UNINSTALL_CODES.TARGET_ABSENT, removed: false });

  const broker = byId.get("broker-launch-agent");
  if (scope === "system") {
    results.push({ id: "broker-launch-agent", code: broker?.code ?? UNINSTALL_CODES.TARGET_ABSENT, removed: false, deferred: broker?.state === "present" });
  } else
  if (broker?.state === "present") {
    const brokerQuarantine = `${broker.target}.agentpass-remove.quarantine`;
    if (pathExists(context.fs, brokerQuarantine)) {
      safeRecoveryFile(context, brokerQuarantine, "Broker LaunchAgent removal journal");
      const journal = context.fs.lstatSync(brokerQuarantine);
      if (journal.size > 1024 * 1024 || !brokerOwned(context.fs.readFileSync(brokerQuarantine, "utf8"))) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Broker LaunchAgent removal journal is invalid");
      const live = pathExists(context.fs, broker.target);
      if (live && (live.dev !== journal.dev || live.ino !== journal.ino)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Concurrent Broker LaunchAgent changes require manual recovery");
      if (live) context.fs.unlinkSync(brokerQuarantine);
      else if (!restoreQuarantine(context, brokerQuarantine, broker.target)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Concurrent Broker LaunchAgent changes prevented journal recovery");
    }
    const brokerIdentity = safeRegularFile(context.fs, broker.target, context.userOwner, "Broker LaunchAgent");
    const bootout = commandResult(context, "/bin/launchctl", [`bootout`, `gui/${context.userOwner}/${BROKER_LABEL}`], "Broker LaunchAgent unregister");
    if (bootout.status !== 0 && !benignServiceFailure(bootout)) fail(UNINSTALL_CODES.COMMAND_FAILED, bootout.stderr?.trim() || "Broker LaunchAgent unregister failed");
    const currentBroker = safeRegularFile(context.fs, broker.target, context.userOwner, "Broker LaunchAgent");
    if (currentBroker.dev !== brokerIdentity.dev || currentBroker.ino !== brokerIdentity.ino || currentBroker.mtimeMs !== brokerIdentity.mtimeMs || currentBroker.size !== brokerIdentity.size) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Broker LaunchAgent changed during removal");
    if (!brokerOwned(context.fs.readFileSync(broker.target, "utf8"))) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Broker LaunchAgent ownership changed during removal");
    const quarantine = quarantineValidatedFile(context, broker.target, {
      dev: brokerIdentity.dev,
      ino: brokerIdentity.ino,
      mtimeMs: brokerIdentity.mtimeMs,
      size: brokerIdentity.size,
      uid: context.userOwner,
    }, (file) => brokerOwned(context.fs.readFileSync(file, "utf8")), "Broker LaunchAgent");
    context.fs.unlinkSync(quarantine);
    fsyncDirectory(context.fs, path.dirname(broker.target));
    results.push({ id: broker.id, code: UNINSTALL_CODES.REMOVED, removed: true });
  } else results.push({ id: "broker-launch-agent", code: UNINSTALL_CODES.TARGET_ABSENT, removed: false });

  const app = byId.get("application");
  if (scope === "user") {
    results.push({ id: "application", code: app?.code ?? UNINSTALL_CODES.TARGET_ABSENT, removed: false, deferred: app?.state === "present" });
  } else
  if (app?.state === "present") {
    safeParentChain(context.fs, path.dirname(app.target), context.systemRoot, context.systemOwner, "Application");
    let journal = app.removalJournal;
    if (!journal) {
      const identity = validateTree(context.fs, app.target, context.systemOwner, "AgentPass application");
      journal = `${app.target}.agentpass-remove.${crypto.randomBytes(16).toString("hex")}`;
      if (pathExists(context.fs, journal)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal journal collision");
      context.fs.renameSync(app.target, journal);
      const quarantined = validateTree(context.fs, journal, context.systemOwner, "Application removal journal");
      if (quarantined.dev !== identity.dev || quarantined.ino !== identity.ino) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application changed during removal journal creation");
      fsyncDirectory(context.fs, path.dirname(app.target));
    } else {
      validateTree(context.fs, journal, context.systemOwner, "Application removal journal");
    }
    context.fs.rmSync(journal, { recursive: true, force: false });
    fsyncDirectory(context.fs, path.dirname(app.target));
    results.push({ id: app.id, code: UNINSTALL_CODES.REMOVED, removed: true });
  } else results.push({ id: "application", code: UNINSTALL_CODES.TARGET_ABSENT, removed: false });

  const receipt = byId.get("package-receipt");
  if (scope === "user") {
    results.push({ id: "package-receipt", code: receipt?.code ?? UNINSTALL_CODES.TARGET_ABSENT, removed: false, deferred: receipt?.state === "present" });
  } else
  if (receipt?.state === "present") {
    const result = commandResult(context, "/usr/sbin/pkgutil", ["--forget", PACKAGE_ID], "Package receipt removal");
    if (result.status !== 0 && !/no receipt|not found|does not exist/i.test(`${result.stdout ?? ""}\n${result.stderr ?? ""}`)) {
      fail(UNINSTALL_CODES.COMMAND_FAILED, result.stderr?.trim() || "Package receipt removal failed");
    }
    results.push({ id: receipt.id, code: UNINSTALL_CODES.REMOVED, removed: true });
  } else results.push({ id: "package-receipt", code: UNINSTALL_CODES.TARGET_ABSENT, removed: false });

  for (const target of current.targets.filter((item) => item.kind === "integration")) {
    results.push(scope === "system"
      ? { id: target.id, code: target.code, removed: false, deferred: target.state === "present" }
      : removeIntegration(context, target));
  }
  return results;
}

export function executeProductionUninstall(plan, options = {}, dependencies = {}) {
  validatePlan(plan);
  const execute = options.execute ?? dependencies.execute ?? true;
  const scope = options.scope ?? dependencies.scope ?? "all";
  if (!["all", "user", "system"].includes(scope)) fail(UNINSTALL_CODES.INVALID_PLAN, "Uninstall scope must be all, user, or system");
  if (execute !== true) return { ...plan, dryRun: true, executed: false, code: UNINSTALL_CODES.EXECUTE_REQUIRED };
  const context = contextFrom({
    ...dependencies,
    ...options,
    homeDir: plan.homeDir,
    systemRoot: plan.systemRoot,
    uid: options.uid ?? dependencies.uid ?? plan.uid,
    expectedUserOwner: plan.expectedUserOwner,
    expectedSystemOwner: plan.expectedSystemOwner,
    includeUser: options.includeUser ?? dependencies.includeUser ?? plan.includeUser,
    integrations: plan.targets.filter((item) => item.kind === "integration")
      .map((item) => ({ client: item.client, projectDir: item.projectDir, expectedServer: item.expectedServer }))
  }, {});
  const current = buildPlan(context, {});
  const results = executeCurrentPlan(context, current, scope);
  const removed = results.filter((item) => item.removed).length;
  return {
    ...current,
    dryRun: false,
    executed: true,
    scope,
    code: removed > 0 ? UNINSTALL_CODES.COMPLETE : UNINSTALL_CODES.NOOP,
    results,
    preserves: current.preserves.map((item) => ({ ...item, code: UNINSTALL_CODES.PRESERVED }))
  };
}
