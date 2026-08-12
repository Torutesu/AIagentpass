import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const defaultConfigDir = path.join(os.homedir(), ".agentpass");

export function configPath(dir = defaultConfigDir) { return path.join(dir, "config.json"); }
export function auditPath(dir = defaultConfigDir) { return path.join(dir, "audit.jsonl"); }
export function statePath(dir = defaultConfigDir) { return path.join(dir, "state.json"); }
export function sessionPath(dir = defaultConfigDir) { return path.join(dir, "session.json"); }
export function sessionDir(dir = defaultConfigDir) { return path.join(dir, "sessions"); }
export function socketPath(dir = defaultConfigDir) { return path.join(dir, "agentpass.sock"); }
export function checkpointPath(dir = defaultConfigDir) { return path.join(dir, "audit.checkpoints.jsonl"); }
export function auditPrivateKeyPath(dir = defaultConfigDir) { return path.join(dir, "audit", "checkpoint.pem"); }
export function controlBundlePath(dir = defaultConfigDir) { return path.join(dir, "control.bundle.json"); }
export function controlBundleV2StatePath(dir = defaultConfigDir) { return path.join(dir, "control-v2.state.json"); }
export function capabilityStatePath(dir = defaultConfigDir) { return path.join(dir, "capability.state.json"); }
export function anchorReceiptPath(dir = defaultConfigDir) { return path.join(dir, "anchor.receipts.jsonl"); }

export function loadConfig(dir = defaultConfigDir) {
  const file = configPath(dir);
  if (!fs.existsSync(file)) throw new Error(`AgentPass is not initialized: ${file}`);
  assertSecurePath(dir, file);
  let config;
  try { config = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid JSON configuration: ${file}`); }
  validateConfig(config);
  return config;
}

export function saveConfig(config, dir = defaultConfigDir) {
  validateConfig(config);
  secureMkdir(dir);
  atomicWrite(configPath(dir), `${JSON.stringify(config, null, 2)}\n`, 0o600);
}

export function loadState(dir = defaultConfigDir) {
  const file = statePath(dir);
  if (!fs.existsSync(file)) return { revoked: false, generation: 0 };
  assertSecurePath(dir, file);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid state file: ${file}`); }
}

export function saveState(state, dir = defaultConfigDir) {
  secureMkdir(dir);
  atomicWrite(statePath(dir), `${JSON.stringify(state, null, 2)}\n`, 0o600);
}

export function loadSession(token, dir = defaultConfigDir) {
  if (typeof token !== "string" || !token) return null;
  const directory = sessionDir(dir);
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const file = path.join(directory, `${tokenHash}.json`);
  if (!fs.existsSync(file)) return null;
  assertSecurePath(directory, file);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid session file: ${file}`); }
}

export function saveSession(session, dir = defaultConfigDir) {
  if (!/^[0-9a-f]{64}$/.test(session?.token_hash ?? "")) throw new Error("Session token hash is invalid");
  const directory = sessionDir(dir);
  secureMkdir(directory);
  atomicWrite(path.join(directory, `${session.token_hash}.json`), `${JSON.stringify(session, null, 2)}\n`, 0o600);
}

export function secureMkdir(dir) {
  if (fs.existsSync(dir)) {
    const before = fs.lstatSync(dir);
    const uid = process.getuid?.();
    if (!before.isDirectory() || before.isSymbolicLink()) throw new Error(`Refusing unsafe configuration directory: ${dir}`);
    if (uid !== undefined && before.uid !== uid) throw new Error(`Configuration directory is not owned by the current user: ${dir}`);
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const after = fs.lstatSync(dir);
  if (!after.isDirectory() || after.isSymbolicLink()) throw new Error(`Refusing unsafe configuration directory: ${dir}`);
}

export function atomicWrite(file, content, mode = 0o600) {
  const directory = path.dirname(file);
  const directoryStat = fs.lstatSync(directory);
  const uid = process.getuid?.();
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error(`Refusing unsafe configuration directory: ${directory}`);
  if (uid !== undefined && directoryStat.uid !== uid) throw new Error(`Configuration directory is not owned by the current user: ${directory}`);
  if (fs.existsSync(file)) {
    const existing = fs.lstatSync(file);
    if (!existing.isFile() || existing.isSymbolicLink()) throw new Error(`Refusing unsafe configuration file: ${file}`);
    if (uid !== undefined && existing.uid !== uid) throw new Error(`Configuration file is not owned by the current user: ${file}`);
  }
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, "wx", mode);
    fs.writeFileSync(descriptor, content);
    fs.fchmodSync(descriptor, mode);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, file);
    try {
      const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY);
      try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
    } catch (error) {
      // Some filesystems do not support directory fsync. Do not hide other I/O
      // errors, but tolerate the documented unsupported-operation cases.
      if (!["EINVAL", "ENOTSUP", "EISDIR"].includes(error.code)) throw error;
    }
  } catch (error) {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

function validateConfig(config) {
  if (!config || typeof config !== "object") throw new Error("Configuration must be an object");
  if (![1, 2, 3, 4].includes(config.version)) throw new Error("Unsupported configuration version");
  if (!Array.isArray(config.repositories) || config.repositories.length === 0) throw new Error("repositories must contain at least one path");
  if (config.repositories.some((item) => typeof item !== "string" || !path.isAbsolute(item))) throw new Error("repositories must be absolute paths");
  if (config.branches && typeof config.branches !== "object") throw new Error("branches must be an object");
  if (config.remotes && typeof config.remotes !== "object") throw new Error("remotes must be an object");
  if (config.signing && typeof config.signing !== "object") throw new Error("signing must be an object");
  if (config.version >= 3) {
    if (!Array.isArray(config.agents) || config.agents.length === 0) throw new Error("version 3 configuration requires agents");
    const ids = config.agents.map((agent) => agent?.id);
    if (ids.some((id) => typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))) throw new Error("agent IDs must be UUIDv4 values");
    if (new Set(ids).size !== ids.length) throw new Error("agent IDs must be unique");
    if (!ids.includes(config.default_agent_id)) throw new Error("default_agent_id must identify an enrolled agent");
    if (config.agents.some((agent) => typeof agent.name !== "string" || !agent.name || agent.name.length > 64 || !isEd25519PublicKey(agent.public_key))) throw new Error("agents require a valid name and Ed25519 public key");
    if (config.version >= 4 && config.agents.some((agent) => !isValidScope(agent.scope))) throw new Error("version 4 agents require an explicit authorization scope");
  }
  if (config.version >= 4) {
    if (!stringArray(config.operations) || !stringArray(config.branches?.allow) || !stringArray(config.remotes?.allow, true)) throw new Error("version 4 global policy requires operations, branches, and remotes");
    if (config.branches?.deny !== undefined && !stringArray(config.branches.deny, true)) throw new Error("branch deny rules must be strings");
    if (config.remotes?.deny !== undefined && !stringArray(config.remotes.deny, true)) throw new Error("remote deny rules must be strings");
    if (typeof config.session?.required !== "boolean" || !Number.isFinite(config.session?.ttl_seconds) || config.session.ttl_seconds < 60 || config.session.ttl_seconds > 86400) throw new Error("version 4 session policy requires a boolean required flag and TTL between 60 and 86400 seconds");
    if (!isEd25519PublicKey(config.audit_signing?.public_key)) throw new Error("version 4 configuration requires an Ed25519 audit signing key");
    if (config.control !== undefined) {
      if (config.control?.required !== true || !isEd25519PublicKey(config.control.public_key)) throw new Error("remote control requires a pinned Ed25519 public key and required=true");
      if (config.control.url !== undefined && (!isHttpsUrl(config.control.url) || !Number.isInteger(config.control.refresh_seconds) || config.control.refresh_seconds < 15 || config.control.refresh_seconds > 3600)) throw new Error("remote control URL must use HTTPS with a refresh interval between 15 and 3600 seconds");
    }
    if (config.control_v2 !== undefined) {
      const control = config.control_v2;
      if (control?.required !== true || control.capability_required !== true || !isEd25519PublicKey(control.public_key)) throw new Error("ControlBundle v2 requires a pinned Ed25519 key, required=true, and capability_required=true");
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(control.issuer ?? "") || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(control.key_id ?? "")) throw new Error("ControlBundle v2 issuer and key ID are invalid");
      if (!isUuid(control.organization_id) || !isUuid(control.device_id)) throw new Error("ControlBundle v2 organization and device IDs must be UUIDs");
      if (control.state_path !== undefined && (typeof control.state_path !== "string" || !path.isAbsolute(control.state_path))) throw new Error("ControlBundle v2 state path must be absolute");
      if (control.url !== undefined && (!isHttpsUrl(control.url) || !Number.isInteger(control.refresh_seconds) || control.refresh_seconds < 15 || control.refresh_seconds > 3600)) throw new Error("ControlBundle v2 URL must use HTTPS with a refresh interval between 15 and 3600 seconds");
      if (control.allow_offline !== undefined && typeof control.allow_offline !== "boolean") throw new Error("ControlBundle v2 allow_offline must be boolean");
      if (control.url !== undefined && config.native_broker?.enabled !== true && (typeof control.device_private_key_path !== "string" || !path.isAbsolute(control.device_private_key_path))) throw new Error("Non-native ControlBundle v2 sync requires an absolute device_private_key_path");
    }
    if (config.audit_anchor !== undefined) {
      if (!isHttpsUrl(config.audit_anchor?.url) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(config.audit_anchor?.tenant ?? "") || !isEd25519PublicKey(config.audit_anchor?.public_key)) throw new Error("audit anchor requires an HTTPS URL, tenant slug, and Ed25519 public key");
    }
    if (config.native_broker !== undefined) {
      if (config.native_broker?.enabled !== true || typeof config.native_broker.mach_service !== "string" || !/^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$/.test(config.native_broker.mach_service) || typeof config.native_broker.client !== "string" || !path.isAbsolute(config.native_broker.client)) throw new Error("native broker requires enabled=true, a Mach service name, and an absolute client path");
      if (config.native_broker.manager !== undefined && (typeof config.native_broker.manager !== "string" || !path.isAbsolute(config.native_broker.manager))) throw new Error("native broker manager must be an absolute path");
      if (config.native_broker.control_url !== undefined && !isHttpsUrl(config.native_broker.control_url)) throw new Error("native control source must use HTTPS");
    }
  }
}

function isHttpsUrl(value) {
  try { return new URL(value).protocol === "https:"; }
  catch { return false; }
}

function isValidScope(scope) {
  if (!scope || typeof scope !== "object") return false;
  if (!stringArray(scope.operations) || !stringArray(scope.repositories) || scope.repositories.some((item) => !path.isAbsolute(item))) return false;
  if (!stringArray(scope.branches?.allow) || !stringArray(scope.remotes?.allow, true)) return false;
  if (scope.branches?.deny !== undefined && !stringArray(scope.branches.deny, true)) return false;
  if (scope.remotes?.deny !== undefined && !stringArray(scope.remotes.deny, true)) return false;
  return true;
}

function stringArray(value, allowEmpty = false) {
  return Array.isArray(value) && (allowEmpty || value.length > 0) && value.every((item) => typeof item === "string" && item.length > 0);
}

function isEd25519PublicKey(value) {
  if (typeof value !== "string") return false;
  try { return crypto.createPublicKey(value).asymmetricKeyType === "ed25519"; }
  catch { return false; }
}

function isUuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }

function assertSecurePath(dir, file) {
  const dirStat = fs.lstatSync(dir);
  const fileStat = fs.lstatSync(file);
  const currentUid = process.getuid?.();
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) throw new Error(`Config directory is not a real directory: ${dir}`);
  if (!fileStat.isFile() || fileStat.isSymbolicLink()) throw new Error(`Config file is not a regular file: ${file}`);
  if (currentUid !== undefined && dirStat.uid !== currentUid) throw new Error(`Config directory is not owned by the current user: ${dir}`);
  if ((dirStat.mode & 0o077) !== 0) throw new Error(`Config directory is too permissive: ${dir}`);
  if (currentUid !== undefined && fileStat.uid !== currentUid) throw new Error(`Config file is not owned by the current user: ${file}`);
  if ((fileStat.mode & 0o077) !== 0) throw new Error(`Config file is too permissive: ${file}`);
}
