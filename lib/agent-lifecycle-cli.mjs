import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { AGENT_LAUNCH_MAX_TTL_SECONDS, AGENT_LAUNCH_MIN_TTL_SECONDS } from "./agent-launch-contract.mjs";

const OPERATIONS = new Set(["launch", "close"]);
export const FIXED_NATIVE_HOST_LAUNCHER = "/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host";
const FIXED_NATIVE_HOST_APPLICATION = "/Applications/AgentPass.app";
const MAX_HOST_OUTPUT_BYTES = 256 * 1024;
export const AGENT_LIFECYCLE_DESCRIPTOR_VERSION = 1;
export const AGENT_LIFECYCLE_HANDOFF_FD = 3;

export const AGENT_LIFECYCLE_UNAVAILABLE = "AGENT_LIFECYCLE_NOT_AVAILABLE";
export const AGENT_LIFECYCLE_HANDOFF_UNAVAILABLE = "AGENT_LIFECYCLE_HANDOFF_NOT_AVAILABLE";
export const AGENT_LIFECYCLE_HOST_REJECTED = "AGENT_LIFECYCLE_NATIVE_HOST_REJECTED";

function publicError(operation, code, message) {
  return Object.freeze({ ok: false, operation, error: Object.freeze({ code, message }) });
}

export function unavailableAgentLifecycle(operation) {
  if (!OPERATIONS.has(operation)) throw new TypeError("agent lifecycle operation is invalid");
  return Object.freeze({
    ok: false,
    operation,
    error: Object.freeze({
      code: AGENT_LIFECYCLE_UNAVAILABLE,
      message: "The process-bound Agent lifecycle is not available in this build"
    })
  });
}

function validAbsoluteProject(project) {
  return typeof project === "string"
    && project.length > 0
    && project.length <= 4_096
    && path.isAbsolute(project)
    && !project.includes("\0")
    && project !== "/"
    && !project.endsWith(path.sep)
    && path.normalize(project) === project;
}

function exactKeys(value, expected) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === expected.slice().sort().join(",");
}

function validLaunchDescriptor(descriptor) {
  return exactKeys(descriptor, ["agent", "handoff_fd", "operation", "project", "ttl_seconds", "version"])
    && descriptor.version === AGENT_LIFECYCLE_DESCRIPTOR_VERSION
    && descriptor.operation === "launch"
    && descriptor.agent === "claude-code"
    && validAbsoluteProject(descriptor.project)
    && Number.isSafeInteger(descriptor.ttl_seconds)
    && descriptor.ttl_seconds >= AGENT_LAUNCH_MIN_TTL_SECONDS
    && descriptor.ttl_seconds <= AGENT_LAUNCH_MAX_TTL_SECONDS
    && descriptor.handoff_fd === AGENT_LIFECYCLE_HANDOFF_FD;
}

/**
 * Creates the only launch descriptor accepted by the lifecycle boundary.
 * It carries bounded public request data and the fixed inherited handoff
 * location; it cannot carry authority, credentials, or a host selector.
 */
export function createAgentLifecycleLaunchDescriptor(normalized) {
  if (!exactKeys(normalized, ["agent", "project", "ttl_seconds"]) || !validLaunchDescriptor({
    ...normalized,
    version: AGENT_LIFECYCLE_DESCRIPTOR_VERSION,
    operation: "launch",
    handoff_fd: AGENT_LIFECYCLE_HANDOFF_FD
  })) throw new TypeError("agent lifecycle launch descriptor is invalid");
  return Object.freeze({
    version: AGENT_LIFECYCLE_DESCRIPTOR_VERSION,
    operation: "launch",
    agent: "claude-code",
    project: normalized.project,
    ttl_seconds: normalized.ttl_seconds,
    handoff_fd: AGENT_LIFECYCLE_HANDOFF_FD
  });
}

function fixedLauncherIsSafe(launcher, lstat = fs.lstatSync, knownStat = undefined) {
  if (launcher !== FIXED_NATIVE_HOST_LAUNCHER || !path.isAbsolute(launcher)) return false;
  let stat = knownStat;
  if (!stat) {
    try { stat = lstat(launcher); } catch { return false; }
  }
  if (!(stat?.isFile?.() === true
    && stat.isSymbolicLink?.() !== true
    && stat.nlink === 1
    && stat.uid === 0
    && (stat.mode & 0o111) !== 0
    && (stat.mode & 0o022) === 0)) return false;
  let current = path.dirname(launcher);
  while (true) {
    let ancestor;
    try { ancestor = lstat(current); } catch { return false; }
    if (ancestor?.isDirectory?.() !== true
      || ancestor.isSymbolicLink?.() === true
      || ancestor.nlink !== 1
      || ancestor.uid !== 0
      || (ancestor.mode & 0o022) !== 0) return false;
    if (current === FIXED_NATIVE_HOST_APPLICATION) return true;
    const parent = path.dirname(current);
    if (parent === current || current.length <= FIXED_NATIVE_HOST_APPLICATION.length || !current.startsWith(`${FIXED_NATIVE_HOST_APPLICATION}${path.sep}`)) return false;
    current = parent;
  }
}

function hasInheritedHandoff(fstat = fs.fstatSync) {
  try {
    const stat = fstat(AGENT_LIFECYCLE_HANDOFF_FD);
    // The authority document must be a non-seekable, one-way handoff. A
    // regular file would let a compromised Host/child rewind and replay it.
    return stat && (stat.isFIFO?.() === true || stat.isSocket?.() === true);
  } catch {
    return false;
  }
}

function parseHostOutput(stdout) {
  if (typeof stdout !== "string" || Buffer.byteLength(stdout) > MAX_HOST_OUTPUT_BYTES) return null;
  const lines = stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length < 1 || lines.length > 2) return null;
  const outputs = [];
  for (const line of lines) {
    let value;
    try { value = JSON.parse(line); } catch { return null; }
    if (JSON.stringify(value) !== line) return null;
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const keys = Object.keys(value).sort().join(",");
    if (keys !== "error,ok,operation,status" || value.operation !== "host-launch" || typeof value.ok !== "boolean" || !["active", "closed", "error", "rejected"].includes(value.status) || (value.error !== null && typeof value.error !== "string")) return null;
    if (value.status === "active" && (value.ok !== true || value.error !== null)) return null;
    if ((value.status === "closed" || value.status === "error" || value.status === "rejected") && value.ok !== (value.status === "closed")) return null;
    outputs.push(Object.freeze({ ok: value.ok, operation: "host-launch", status: value.status, error: value.error }));
  }
  const last = outputs.at(-1);
  if (outputs.length !== 2 || outputs[0].status !== "active" || last.status !== "closed") return null;
  return last;
}

/**
 * Launches only the signed, fixed Native Host. The authority document is
 * deliberately not accepted as a JS value: it must already be inherited as
 * FD3 from the trusted setup/Console handoff and is passed through once.
 */
export function launchAgentLifecycle(normalized, options = {}) {
  if (options.platform !== "darwin") return unavailableAgentLifecycle("launch");
  if (!validLaunchDescriptor(normalized)) return publicError("launch", AGENT_LIFECYCLE_HOST_REJECTED, "The lifecycle launch descriptor is invalid");
  const launcher = options.launcher ?? FIXED_NATIVE_HOST_LAUNCHER;
  const lstat = options.lstat ?? fs.lstatSync;
  let launcherStat;
  try { launcherStat = lstat(launcher); } catch { return unavailableAgentLifecycle("launch"); }
  if (!fixedLauncherIsSafe(launcher, lstat, launcherStat)) return publicError("launch", AGENT_LIFECYCLE_HOST_REJECTED, "The fixed Native Host launcher is not trusted");
  const fstat = options.fstat ?? fs.fstatSync;
  if (!hasInheritedHandoff(fstat)) return publicError("launch", AGENT_LIFECYCLE_HANDOFF_UNAVAILABLE, "The one-time Native Host handoff is not available");
  const run = options.run ?? ((file, args) => spawnSync(file, args, {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    stdio: ["ignore", "pipe", "ignore", 3],
    maxBuffer: MAX_HOST_OUTPUT_BYTES,
    timeout: 86_400_000
  }));
  let result;
  try { result = run(launcher, [normalized.operation, normalized.project]); } catch { return publicError("launch", AGENT_LIFECYCLE_HOST_REJECTED, "The fixed Native Host could not be started"); }
  if (!result || result.error || result.signal || result.status !== 0) return publicError("launch", AGENT_LIFECYCLE_HOST_REJECTED, "The fixed Native Host rejected the launch");
  const output = parseHostOutput(result.stdout);
  if (!output) return publicError("launch", AGENT_LIFECYCLE_HOST_REJECTED, "The Native Host returned an invalid launch result");
  return Object.freeze({ ok: true, operation: "launch", status: output.status });
}
