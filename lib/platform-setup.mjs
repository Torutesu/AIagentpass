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

export function inspectNativeApplication(application = "/Applications/AgentPass.app", { expectedOwner = 0 } = {}) {
  trustedDirectory(application, expectedOwner);
  const manager = path.join(application, "Contents/MacOS/agentpass-native-manager");
  const client = path.join(application, "Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client");
  trustedAncestors(application, manager, expectedOwner);
  trustedAncestors(application, client, expectedOwner);
  trustedExecutable(manager, expectedOwner);
  trustedExecutable(client, expectedOwner);
  const result = spawnSync(manager, ["status"], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
  if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "Native service status failed");
  let service;
  try { service = JSON.parse(result.stdout); } catch { throw new Error("Native manager returned invalid status JSON"); }
  if (service.ok !== true || service.bundle_path !== application || service.plist_present !== true || !["not_registered", "enabled", "requires_approval"].includes(service.status)) {
    throw new Error("Native manager returned an untrusted service status");
  }
  return {
    version: 1,
    application,
    manager,
    client,
    serviceStatus: service.status,
    requiresApproval: service.requires_approval === true,
    nativeBroker: { enabled: true, mach_service: "dev.agentpass.native-service", client, manager }
  };
}
