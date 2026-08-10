import fs from "node:fs";
import path from "node:path";

export const defaultConfigDir = path.join(process.env.HOME ?? ".", ".agentpass");

export function configPath(dir = defaultConfigDir) {
  return path.join(dir, "config.json");
}

export function auditPath(dir = defaultConfigDir) {
  return path.join(dir, "audit.jsonl");
}

export function loadConfig(dir = defaultConfigDir) {
  const file = configPath(dir);
  if (!fs.existsSync(file)) throw new Error(`AgentPass is not initialized: ${file}`);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function saveConfig(config, dir = defaultConfigDir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath(dir), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}
