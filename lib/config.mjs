import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const defaultConfigDir = path.join(os.homedir(), ".agentpass");

export function configPath(dir = defaultConfigDir) { return path.join(dir, "config.json"); }
export function auditPath(dir = defaultConfigDir) { return path.join(dir, "audit.jsonl"); }
export function statePath(dir = defaultConfigDir) { return path.join(dir, "state.json"); }
export function sessionPath(dir = defaultConfigDir) { return path.join(dir, "session.json"); }
export function socketPath(dir = defaultConfigDir) { return path.join(dir, "agentpass.sock"); }

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

export function loadSession(dir = defaultConfigDir) {
  const file = sessionPath(dir);
  if (!fs.existsSync(file)) return null;
  assertSecurePath(dir, file);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid session file: ${file}`); }
}

export function saveSession(session, dir = defaultConfigDir) {
  secureMkdir(dir);
  atomicWrite(sessionPath(dir), `${JSON.stringify(session, null, 2)}\n`, 0o600);
}

export function secureMkdir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch {}
}

export function atomicWrite(file, content, mode = 0o600) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporary, content, { mode });
  fs.chmodSync(temporary, mode);
  fs.renameSync(temporary, file);
}

function validateConfig(config) {
  if (!config || typeof config !== "object") throw new Error("Configuration must be an object");
  if (![1, 2, 3].includes(config.version)) throw new Error("Unsupported configuration version");
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
    if (config.agents.some((agent) => typeof agent.name !== "string" || !agent.name || typeof agent.public_key !== "string" || !agent.public_key.includes("BEGIN PUBLIC KEY"))) throw new Error("agents require a name and public key");
  }
}

function assertSecurePath(dir, file) {
  const dirStat = fs.statSync(dir);
  const fileStat = fs.statSync(file);
  const currentUid = process.getuid?.();
  if (currentUid !== undefined && dirStat.uid !== currentUid) throw new Error(`Config directory is not owned by the current user: ${dir}`);
  if ((dirStat.mode & 0o077) !== 0) throw new Error(`Config directory is too permissive: ${dir}`);
  if (currentUid !== undefined && fileStat.uid !== currentUid) throw new Error(`Config file is not owned by the current user: ${file}`);
  if ((fileStat.mode & 0o077) !== 0) throw new Error(`Config file is too permissive: ${file}`);
}
