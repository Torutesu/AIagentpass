import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

function trustedDirectory(directory, expectedOwner) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new Error("AgentPass application path must be absolute");
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedOwner || (stat.mode & 0o022) !== 0) {
    throw new Error("AgentPass application directory is not trusted");
  }
}

function trustedExecutable(file, expectedOwner) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== expectedOwner || (stat.mode & 0o022) !== 0 || (stat.mode & 0o111) === 0) {
    throw new Error(`AgentPass executable is not trusted: ${file}`);
  }
}

function runIdentityCheck(run, command, args, label) {
  const result = run(command, args);
  if (!result || result.status !== 0) throw new Error(`${label} failed`);
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

export function verifyNativeApplicationIdentity(application, { expectedTeamId, run = (command, args) => spawnSync(command, args, { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } }) } = {}) {
  if (typeof expectedTeamId !== "string" || !/^[A-Z0-9]{10}$/.test(expectedTeamId)) throw new Error("A pinned 10-character Apple Team ID is required");
  const components = [
    [application, "dev.agentpass"],
    [path.join(application, "Contents/MacOS/agentpass-native-manager"), "dev.agentpass"],
    [path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app"), "dev.agentpass.native-client"],
    [path.join(application, "Contents/Library/HelperTools/AgentPassNativeService.app"), "dev.agentpass.native-service"]
  ];
  runIdentityCheck(run, "/usr/bin/codesign", ["--verify", "--deep", "--strict", application], "AgentPass deep code-signature verification");
  for (const [component, identifier] of components) {
    runIdentityCheck(run, "/usr/bin/codesign", ["--verify", "--strict", component], `Code-signature verification for ${identifier}`);
    const detail = runIdentityCheck(run, "/usr/bin/codesign", ["-dv", "--verbose=4", component], `Code identity inspection for ${identifier}`);
    if (!detail.split(/\r?\n/).includes(`Identifier=${identifier}`) || !detail.split(/\r?\n/).includes(`TeamIdentifier=${expectedTeamId}`)) throw new Error(`AgentPass code identity does not match ${identifier} and the pinned Team ID`);
  }
  runIdentityCheck(run, "/usr/sbin/spctl", ["--assess", "--type", "execute", "--context", "context:primary-signature", "-vv", application], "AgentPass Gatekeeper assessment");
  return { verified: true, teamId: expectedTeamId, identifiers: components.map(([, identifier]) => identifier) };
}

function trustedAncestors(application, file, expectedOwner) {
  let current = path.dirname(file);
  while (current.length >= application.length) {
    trustedDirectory(current, expectedOwner);
    if (current === application) return;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error(`AgentPass executable escapes the application bundle: ${file}`);
}

export function inspectNativeApplication(application = "/Applications/AgentPass.app", { expectedOwner = 0, expectedTeamId = undefined, run = undefined } = {}) {
  trustedDirectory(application, expectedOwner);
  const manager = path.join(application, "Contents/MacOS/agentpass-native-manager");
  const client = path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client");
  const serviceExecutable = path.join(application, "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service");
  trustedAncestors(application, manager, expectedOwner);
  trustedAncestors(application, client, expectedOwner);
  trustedAncestors(application, serviceExecutable, expectedOwner);
  trustedExecutable(manager, expectedOwner);
  trustedExecutable(client, expectedOwner);
  trustedExecutable(serviceExecutable, expectedOwner);
  const identity = expectedTeamId === undefined ? null : verifyNativeApplicationIdentity(application, { expectedTeamId, ...(run ? { run } : {}) });
  const result = spawnSync(manager, ["status"], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
  if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "Native service status failed");
  let serviceStatus;
  try { serviceStatus = JSON.parse(result.stdout); } catch { throw new Error("Native manager returned invalid status JSON"); }
  if (serviceStatus.ok !== true || serviceStatus.bundle_path !== application || serviceStatus.plist_present !== true || !["not_registered", "enabled", "requires_approval"].includes(serviceStatus.status)) {
    throw new Error("Native manager returned an untrusted service status");
  }
  return {
    version: 1,
    application,
    manager,
    client,
    service: serviceExecutable,
    identity,
    serviceStatus: serviceStatus.status,
    requiresApproval: serviceStatus.requires_approval === true,
    nativeBroker: { enabled: true, mach_service: "dev.agentpass.native-service", client, manager }
  };
}
