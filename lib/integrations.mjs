import fs from "node:fs";
import path from "node:path";

const CLIENTS = Object.freeze({
  "claude-code": { relativeFile: ".mcp.json" },
  cursor: { relativeFile: path.join(".cursor", "mcp.json") }
});

export function integrationPlan({ client, projectDir, nodePath, mcpServerPath }) {
  const definition = CLIENTS[client];
  if (!definition) throw new Error(`Unsupported agent integration: ${client}`);
  for (const [name, value] of Object.entries({ projectDir, nodePath, mcpServerPath })) {
    if (typeof value !== "string" || !path.isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  }
  const target = path.join(fs.realpathSync(projectDir), definition.relativeFile);
  const server = {
    command: nodePath,
    args: [mcpServerPath],
    env: { AGENTPASS_PROJECT_DIR: fs.realpathSync(projectDir) }
  };
  return { version: 1, client, target, server_name: "agentpass", server };
}

export function renderIntegration(plan, existingText = null) {
  let document = {};
  if (existingText !== null && existingText.trim()) {
    try { document = JSON.parse(existingText); }
    catch { throw new Error(`Refusing to modify invalid JSON integration file: ${plan.target}`); }
  }
  if (!isPlainObject(document)) throw new Error("Integration configuration must be a JSON object");
  if (document.mcpServers !== undefined && !isPlainObject(document.mcpServers)) throw new Error("mcpServers must be a JSON object");
  return `${JSON.stringify({
    ...document,
    mcpServers: { ...(document.mcpServers ?? {}), [plan.server_name]: plan.server }
  }, null, 2)}\n`;
}

export function installIntegration(plan, { dryRun = true } = {}) {
  const existing = fs.existsSync(plan.target) ? readSafeRegularFile(plan.target) : null;
  const content = renderIntegration(plan, existing);
  const changed = existing !== content;
  if (dryRun || !changed) return { ...plan, changed, installed: false, content };

  const parent = path.dirname(plan.target);
  ensureSafeParent(parent);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  ensureSafeParent(parent);
  const temporary = `${plan.target}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporary, content, { flag: "wx", mode: 0o600 });
    fs.renameSync(temporary, plan.target);
  } finally {
    try { fs.unlinkSync(temporary); } catch {}
  }
  return { ...plan, changed: true, installed: true, content };
}

function ensureSafeParent(directory) {
  if (!fs.existsSync(directory)) return;
  const stat = fs.lstatSync(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Integration directory must be a real directory: ${directory}`);
  if (uid !== undefined && stat.uid !== uid) throw new Error(`Integration directory is not owned by the current user: ${directory}`);
}

function readSafeRegularFile(file) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Integration file must be a regular file: ${file}`);
  if (uid !== undefined && stat.uid !== uid) throw new Error(`Integration file is not owned by the current user: ${file}`);
  if (stat.size > 1024 * 1024) throw new Error(`Integration file is too large: ${file}`);
  return fs.readFileSync(file, "utf8");
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
