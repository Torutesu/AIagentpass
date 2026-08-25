import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { renderRemoval } from "./integrations.mjs";
import { canonicalJson } from "./identity.mjs";
import { verifyNativeApplicationIdentity } from "./platform-setup.mjs";
import { atomicRenameNoReplaceSync } from "./macos-atomic-rename.mjs";

const PACKAGE_ID = "dev.agentpass.installer";
const APP_RELATIVE = path.join("Applications", "AgentPass.app");
const SYSTEM_STATE_RELATIVE = path.join("Library", "Application Support", "AgentPass");
const NATIVE_DAEMON_PLIST = "dev.agentpass.native-service.plist";
const NATIVE_SERVICE_LABEL = "dev.agentpass.native-service";
const BROKER_LABEL = "dev.agentpass.broker";
const BROKER_PLIST_NAME = `${BROKER_LABEL}.plist`;
const BROKER_PLIST_RELATIVE = path.join("Library", "LaunchAgents", BROKER_PLIST_NAME);
const APPLICATION_MANIFEST_SUFFIX = ".agentpass-remove.manifest";
const APPLICATION_QUARANTINE_PREFIX = "AgentPass.app.agentpass-remove.";
const APPLICATION_QUARANTINE_PATTERN = /^AgentPass\.app\.agentpass-remove\.[0-9a-f]{32}$/;
const APPLICATION_MANIFEST_VERSION = 1;
const TRUSTED_APPLICATION_IDENTITY = Object.freeze({
  bundle_id: "dev.agentpass",
  manager_identifier: "dev.agentpass",
  client_identifier: "dev.agentpass.native-client",
  service_identifier: "dev.agentpass.native-service"
});
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
    expectedTeamId: source.expectedTeamId ?? source.teamId ?? null,
    trustedAppIdentity: source.trustedAppIdentity ?? source.expectedAppIdentity ?? null,
    atomicRename: source.atomicRename ?? atomicRenameNoReplaceSync,
    requireAtomicRename: source.requireAtomicRename ?? systemRoot === "/",
    atomicRenameHelper: source.atomicRenameHelper ?? path.join(systemRoot, APP_RELATIVE, "Contents", "Library", "HelperTools", "agentpass-atomic-rename"),
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

function applicationManifestPath(app) { return `${app}${APPLICATION_MANIFEST_SUFFIX}`; }

function applicationIdentity(context) {
  const supplied = context.trustedAppIdentity;
  if (supplied !== null) {
    if (!isObject(supplied) || Object.keys(supplied).sort().join(",") !== ["bundle_id", "client_identifier", "manager_identifier", "service_identifier", "team_id"].sort().join(",")) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Trusted AgentPass application identity is invalid");
    }
    if (supplied.bundle_id !== TRUSTED_APPLICATION_IDENTITY.bundle_id
      || supplied.manager_identifier !== TRUSTED_APPLICATION_IDENTITY.manager_identifier
      || supplied.client_identifier !== TRUSTED_APPLICATION_IDENTITY.client_identifier
      || supplied.service_identifier !== TRUSTED_APPLICATION_IDENTITY.service_identifier) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Trusted AgentPass application identity is not allowlisted");
    }
    if (supplied.team_id !== null && (typeof supplied.team_id !== "string" || !/^[A-Z0-9]{10}$/.test(supplied.team_id))) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Trusted AgentPass application Team ID is invalid");
    }
    if (context.expectedTeamId !== null && supplied.team_id !== context.expectedTeamId) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Trusted AgentPass application Team ID does not match the pinned value");
    }
    return { ...supplied };
  }
  if (context.expectedTeamId !== null && (typeof context.expectedTeamId !== "string" || !/^[A-Z0-9]{10}$/.test(context.expectedTeamId))) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Pinned AgentPass application Team ID is invalid");
  }
  return {
    ...TRUSTED_APPLICATION_IDENTITY,
    team_id: context.expectedTeamId
  };
}

function manifestIdentityEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function manifestInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(UNINSTALL_CODES.UNSAFE_TARGET, `Application removal manifest ${label} is invalid`);
  return value;
}

function verifyTrustedApplication(context, app) {
  if (context.expectedTeamId === null) return;
  try {
    const result = verifyNativeApplicationIdentity(app, { expectedTeamId: context.expectedTeamId, run: context.run });
    if (result?.verified !== true || result.teamId !== context.expectedTeamId) throw new Error("identity verification did not produce the pinned identity");
  } catch {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "AgentPass application code identity is not trusted");
  }
}

function readApplicationManifest(context, manifestPath, app, appParent) {
  const stat = pathExists(context.fs, manifestPath);
  if (!stat) return null;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== context.systemOwner || (stat.mode & 0o777) !== 0o600 || stat.size > 64 * 1024) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is not a trusted root-owned file");
  }
  let text;
  try { text = context.fs.readFileSync(manifestPath, "utf8"); } catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest cannot be read"); }
  let manifest;
  try { manifest = JSON.parse(text); } catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is not valid JSON"); }
  const expectedKeys = ["application_identity", "kind", "phase", "quarantine", "root_identity", "target", "version"];
  if (!isObject(manifest) || canonicalJson(manifest) + "\n" !== text || canonicalJson(Object.keys(manifest).sort()) !== canonicalJson(expectedKeys.sort())) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is not canonical");
  }
  if (manifest.version !== APPLICATION_MANIFEST_VERSION || manifest.kind !== "agentpass.application-removal") {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest version or kind is invalid");
  }
  if (!["prepared", "quarantined", "deleting", "complete"].includes(manifest.phase)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest phase is invalid");
  }
  if (manifest.target !== app || manifest.quarantine !== path.join(appParent, path.basename(manifest.quarantine)) || !APPLICATION_QUARANTINE_PATTERN.test(path.basename(manifest.quarantine))) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest target is invalid");
  }
  const identity = manifest.root_identity;
  if (!isObject(identity) || canonicalJson(Object.keys(identity).sort()) !== canonicalJson(["dev", "ino"].sort())) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest root identity is invalid");
  }
  manifestInteger(identity.dev, "device identity");
  manifestInteger(identity.ino, "inode identity");
  const expectedIdentity = applicationIdentity(context);
  if (!isObject(manifest.application_identity) || !manifestIdentityEqual(manifest.application_identity, expectedIdentity)) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest trusted identity does not match policy");
  }
  return { ...manifest, stat };
}

function applicationRemovalState(context, app, appParent, appStat) {
  const manifestPath = applicationManifestPath(app);
  const manifest = readApplicationManifest(context, manifestPath, app, appParent);
  const manifestName = path.basename(manifestPath);
  const matches = context.fs.readdirSync(appParent).filter((name) => name.startsWith(APPLICATION_QUARANTINE_PREFIX) && name !== manifestName);
  if (matches.some((name) => !APPLICATION_QUARANTINE_PATTERN.test(name))) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine name is invalid");
  }
  if (matches.length > 1) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine is ambiguous");
  if (!manifest) {
    if (matches.length > 0) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine has no durable identity manifest");
    return { manifestPath, manifest: null, journal: null };
  }
  const journal = matches.length === 1 ? path.join(appParent, matches[0]) : null;
  if (journal && journal !== manifest.quarantine) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest does not bind the quarantine");
  if (manifest.phase === "prepared") {
    if (appStat) {
      if (appStat.dev !== manifest.root_identity.dev || appStat.ino !== manifest.root_identity.ino) fail(UNINSTALL_CODES.UNSAFE_TARGET, "AgentPass application was substituted before quarantine");
      validateTree(context.fs, app, context.systemOwner, "AgentPass application");
    } else if (!journal) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Prepared application removal manifest has no application or quarantine");
    }
  } else if (appStat) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "AgentPass application reappeared while removal was in progress");
  }
  if (journal) {
    const quarantined = validateTree(context.fs, journal, context.systemOwner, "Application removal journal");
    if (quarantined.dev !== manifest.root_identity.dev || quarantined.ino !== manifest.root_identity.ino) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine was substituted");
    }
  } else if (manifest.phase === "quarantined") {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest lost its quarantine");
  }
  return { manifestPath, manifest, journal };
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
  if (context.systemRoot === "/" && (appStat || pathExists(context.fs, applicationManifestPath(app))) && context.expectedTeamId === null) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Production application removal requires a pinned Apple Team ID");
  }
  const appState = applicationRemovalState(context, app, appParent, appStat);
  const appJournal = appState.journal;
  let manager = path.join(app, "Contents", "MacOS", "agentpass-native-manager");
  let nativeStatus = { status: "not_registered" };
  const appIdentity = applicationIdentity(context);
  if (appStat) {
    validateTree(context.fs, app, context.systemOwner, "AgentPass application");
    verifyTrustedApplication(context, app);
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
    targetResult("application", "application", app, appStat || appJournal || appState.manifest ? "present" : "absent", appStat || appJournal || appState.manifest ? UNINSTALL_CODES.TARGET_PRESENT : UNINSTALL_CODES.TARGET_ABSENT, { removalJournal: appJournal, removalManifest: appState.manifestPath, applicationIdentity: appIdentity }),
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

function writeApplicationManifest(context, manifestPath, manifest, { create = false } = {}) {
  const parent = path.dirname(manifestPath);
  safeParentChain(context.fs, parent, context.systemRoot, context.systemOwner, "Application removal manifest");
  const encoded = `${canonicalJson(manifest)}\n`;
  const temporary = path.join(parent, `.agentpass-application-remove-manifest.${crypto.randomBytes(16).toString("hex")}.tmp`);
  let descriptor;
  try {
    descriptor = context.fs.openSync(temporary, "wx", 0o600);
    context.fs.writeFileSync(descriptor, Buffer.from(encoded, "utf8"));
    context.fs.fsyncSync(descriptor);
  } finally {
    try { if (descriptor !== undefined) context.fs.closeSync(descriptor); } catch {}
  }
  try {
    const staged = context.fs.lstatSync(temporary);
    if (!staged.isFile() || staged.isSymbolicLink() || staged.nlink !== 1 || staged.uid !== context.systemOwner || (staged.mode & 0o777) !== 0o600) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest staging file is unsafe");
    }
    if (create) {
      try { context.fs.linkSync(temporary, manifestPath); }
      catch { fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest already exists or cannot be installed safely"); }
      fsyncDirectory(context.fs, parent);
      context.fs.unlinkSync(temporary);
      fsyncDirectory(context.fs, parent);
    } else {
      const current = pathExists(context.fs, manifestPath);
      if (!current || !current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || current.uid !== context.systemOwner || (current.mode & 0o777) !== 0o600) {
        fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is not replaceable safely");
      }
      context.fs.renameSync(temporary, manifestPath);
      fsyncDirectory(context.fs, parent);
    }
  } finally {
    try { context.fs.unlinkSync(temporary); } catch {}
  }
}

function applicationManifestWithPhase(manifest, phase) {
  return {
    version: manifest.version,
    kind: manifest.kind,
    target: manifest.target,
    quarantine: manifest.quarantine,
    root_identity: manifest.root_identity,
    application_identity: manifest.application_identity,
    phase
  };
}

function verifyApplicationManifestRoot(context, manifest, journal) {
  if (!journal) return null;
  const stat = validateTree(context.fs, journal, context.systemOwner, "Application removal journal");
  if (stat.dev !== manifest.root_identity.dev || stat.ino !== manifest.root_identity.ino) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine was substituted");
  }
  return stat;
}

function removeApplicationTreeDurably(context, root, manifest) {
  const removeDirectoryContents = (directory, isRoot = false) => {
    const current = safeDirectory(context.fs, directory, context.systemOwner, "Application removal journal");
    if (isRoot && (current.dev !== manifest.root_identity.dev || current.ino !== manifest.root_identity.ino)) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine was substituted");
    }
    const entries = context.fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const child = path.join(directory, entry.name);
      const childStat = context.fs.lstatSync(child);
      if (childStat.isSymbolicLink() || childStat.dev !== current.dev) {
        fail(UNINSTALL_CODES.UNSAFE_TARGET, `Application removal journal contains an unsafe entry: ${child}`);
      }
      if (childStat.isDirectory()) {
        removeDirectoryContents(child);
        context.fs.rmdirSync(child);
        fsyncDirectory(context.fs, directory);
      } else {
        if (!childStat.isFile() || childStat.nlink !== 1 || childStat.uid !== context.systemOwner || (childStat.mode & 0o022) !== 0) {
          fail(UNINSTALL_CODES.UNSAFE_TARGET, `Application removal journal contains an unsafe file: ${child}`);
        }
        context.fs.unlinkSync(child);
        fsyncDirectory(context.fs, directory);
      }
    }
    const after = safeDirectory(context.fs, directory, context.systemOwner, "Application removal journal");
    if (isRoot && (after.dev !== manifest.root_identity.dev || after.ino !== manifest.root_identity.ino)) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal quarantine was substituted");
    }
  };
  removeDirectoryContents(root, true);
  context.fs.rmdirSync(root);
  fsyncDirectory(context.fs, path.dirname(root));
}

function removeApplicationManifest(context, manifestPath) {
  const stat = pathExists(context.fs, manifestPath);
  if (!stat) return;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== context.systemOwner || (stat.mode & 0o777) !== 0o600) {
    fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is not removable safely");
  }
  context.fs.unlinkSync(manifestPath);
  fsyncDirectory(context.fs, path.dirname(manifestPath));
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

function quarantineValidatedFile(context, target, expected, validate, label, boundary) {
  const quarantine = `${target}.agentpass-remove.quarantine`;
  const helperAvailable = Boolean(pathExists(context.fs, context.atomicRenameHelper));
  if (helperAvailable || context.requireAtomicRename) {
    try {
      context.atomicRename({
        fs: context.fs,
        platform: context.platform,
        source: target,
        destination: quarantine,
        boundary,
        owner: expected.uid,
        helperPath: context.atomicRenameHelper,
        helperBoundary: path.join(context.systemRoot, APP_RELATIVE),
        helperOwner: context.systemOwner
      });
    } catch {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} could not be moved through the verified atomic helper`);
    }
    const moved = safeRegularFile(context.fs, quarantine, expected.uid, `${label} journal`);
    if (moved.dev !== expected.dev || moved.ino !== expected.ino || moved.mtimeMs !== expected.mtimeMs || moved.size !== expected.size || !validate(quarantine)) {
      fail(UNINSTALL_CODES.UNSAFE_TARGET, `${label} changed during atomic quarantine`);
    }
    return quarantine;
  }
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
    }, (file) => context.fs.readFileSync(file, "utf8") === before, "Integration file", target.projectDir);
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
    }, (file) => brokerOwned(context.fs.readFileSync(file, "utf8")), "Broker LaunchAgent", context.homeDir);
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
    const manifestPath = app.removalManifest;
    let manifest = readApplicationManifest(context, manifestPath, app.target, path.dirname(app.target));
    let journal = app.removalJournal;
    if (!manifest) {
      if (!pathExists(context.fs, app.target)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal manifest is missing");
      const identity = validateTree(context.fs, app.target, context.systemOwner, "AgentPass application");
      if (identity.dev === undefined || identity.ino === undefined) fail(UNINSTALL_CODES.UNSAFE_TARGET, "AgentPass application has no stable root identity");
      journal = `${app.target}.agentpass-remove.${crypto.randomBytes(16).toString("hex")}`;
      if (!APPLICATION_QUARANTINE_PATTERN.test(path.basename(journal)) || pathExists(context.fs, journal)) fail(UNINSTALL_CODES.UNSAFE_TARGET, "Application removal journal collision");
      manifest = {
        version: APPLICATION_MANIFEST_VERSION,
        kind: "agentpass.application-removal",
        target: app.target,
        quarantine: journal,
        root_identity: { dev: identity.dev, ino: identity.ino },
        application_identity: app.applicationIdentity,
        phase: "prepared"
      };
      writeApplicationManifest(context, manifestPath, manifest, { create: true });
      manifest = readApplicationManifest(context, manifestPath, app.target, path.dirname(app.target));
    }
    if (manifest.phase === "prepared") {
      if (!journal || !pathExists(context.fs, journal)) {
        const identity = validateTree(context.fs, app.target, context.systemOwner, "AgentPass application");
        if (identity.dev !== manifest.root_identity.dev || identity.ino !== manifest.root_identity.ino) fail(UNINSTALL_CODES.UNSAFE_TARGET, "AgentPass application was substituted before quarantine");
        context.fs.renameSync(app.target, manifest.quarantine);
        fsyncDirectory(context.fs, path.dirname(app.target));
        journal = manifest.quarantine;
      } else {
        verifyApplicationManifestRoot(context, manifest, journal);
      }
      manifest = applicationManifestWithPhase(manifest, "quarantined");
      writeApplicationManifest(context, manifestPath, manifest);
    }
    if (manifest.phase === "quarantined") {
      journal = manifest.quarantine;
      verifyApplicationManifestRoot(context, manifest, journal);
      manifest = applicationManifestWithPhase(manifest, "deleting");
      writeApplicationManifest(context, manifestPath, manifest);
    }
    if (manifest.phase === "deleting") {
      journal = pathExists(context.fs, manifest.quarantine) ? manifest.quarantine : null;
      if (journal) {
        verifyApplicationManifestRoot(context, manifest, journal);
        removeApplicationTreeDurably(context, journal, manifest);
      }
      manifest = applicationManifestWithPhase(manifest, "complete");
      writeApplicationManifest(context, manifestPath, manifest);
    }
    if (manifest.phase === "complete") {
      if (pathExists(context.fs, manifest.quarantine)) {
        fail(UNINSTALL_CODES.UNSAFE_TARGET, "Completed application removal manifest still has a quarantine");
      }
      removeApplicationManifest(context, manifestPath);
    }
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
