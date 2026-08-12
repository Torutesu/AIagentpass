import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

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

/**
 * Build a removal plan for an integration previously written by installIntegration.
 *
 * The expected server is intentionally part of the plan. A config entry named
 * "agentpass" is not enough evidence of ownership: a user may have created an
 * unrelated entry with the same name. Removal therefore only proceeds when the
 * complete AgentPass-generated server definition is still present.
 */
export function integrationRemovalPlan(options) {
  const plan = integrationPlan(options);
  return {
    ...plan,
    project_dir: fs.realpathSync(options.projectDir),
    operation: "remove",
    expected_server: plan.server
  };
}

/**
 * Render removal while retaining every byte outside the owned JSON member.
 * Invalid or ambiguous JSON fails closed. If the entry is absent or no longer
 * matches the AgentPass definition, the original bytes are returned unchanged.
 */
export function renderRemoval(plan, existingText = null) {
  if (existingText === null || existingText === "") {
    return { content: existingText, changed: false, owned: false, reason: "not_present" };
  }
  const document = parseIntegrationDocument(plan, existingText);
  const target = locateAgentPassMember(document, plan);
  if (!target) {
    return { content: existingText, changed: false, owned: false, reason: document.agentPassPresent ? "not_agentpass_owned" : "not_present" };
  }
  return {
    content: removeObjectMember(existingText, document.mcpServersObject, target),
    changed: true,
    owned: true,
    reason: "agentpass_removed"
  };
}

/**
 * Remove only the owned MCP member. Defaults to dry-run and applies changes via
 * a same-directory temporary file, fsync, and atomic rename. Re-running after a
 * successful removal is a no-op.
 */
export function removeIntegration(plan, { dryRun = true } = {}) {
  validateRemovalPlan(plan);
  const existing = readRemovalFile(plan);
  const rendered = renderRemoval(plan, existing);
  if (dryRun || !rendered.changed) {
    return {
      ...plan,
      dryRun,
      changed: rendered.changed,
      removed: false,
      owned: rendered.owned,
      reason: rendered.reason,
      atomic: false,
      content: rendered.content
    };
  }

  ensureRemovalParent(plan);
  const current = readRemovalFile(plan);
  const currentRendered = renderRemoval(plan, current);
  if (!currentRendered.changed) {
    return {
      ...plan,
      dryRun: false,
      changed: false,
      removed: false,
      owned: currentRendered.owned,
      reason: currentRendered.reason,
      atomic: false,
      content: currentRendered.content
    };
  }
  const stat = fs.lstatSync(plan.target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`Integration file changed before removal: ${plan.target}`);
  const mode = stat.mode & 0o777;
  const temporary = `${plan.target}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  try {
    const descriptor = fs.openSync(temporary, "wx", mode);
    try {
      fs.writeFileSync(descriptor, currentRendered.content, "utf8");
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    fs.chmodSync(temporary, mode);
    fs.renameSync(temporary, plan.target);
    fsyncDirectory(path.dirname(plan.target));
  } finally {
    try { fs.unlinkSync(temporary); } catch {}
  }
  return {
    ...plan,
    dryRun: false,
    changed: true,
    removed: true,
    owned: true,
    reason: "agentpass_removed",
    atomic: true,
    content: currentRendered.content
  };
}

function validateRemovalPlan(plan) {
  if (!isPlainObject(plan) || plan.operation !== "remove" || plan.server_name !== "agentpass" || !isPlainObject(plan.expected_server)) {
    throw new Error("Invalid AgentPass integration removal plan");
  }
  if (typeof plan.target !== "string" || !path.isAbsolute(plan.target) || typeof plan.project_dir !== "string" || !path.isAbsolute(plan.project_dir)) {
    throw new Error("Invalid AgentPass integration removal target");
  }
  const project = path.resolve(plan.project_dir);
  const target = path.resolve(plan.target);
  if (target !== project && !target.startsWith(`${project}${path.sep}`)) {
    throw new Error("Integration target escapes the project directory");
  }
}

function readRemovalFile(plan) {
  ensureRemovalParent(plan);
  if (!lstatIfPresent(plan.target)) return null;
  return readSafeRemovalFile(plan.target);
}

function ensureRemovalParent(plan) {
  const project = plan.project_dir;
  const parent = path.dirname(plan.target);
  if (parent === project) {
    ensureSafeOwnedDirectory(project);
    return;
  }
  const relative = path.relative(project, parent);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Integration target escapes the project directory");
  ensureSafeOwnedDirectory(project);
  let current = project;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (lstatIfPresent(current)) ensureSafeOwnedDirectory(current);
  }
}

function lstatIfPresent(file) {
  try { return fs.lstatSync(file); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function ensureSafeOwnedDirectory(directory) {
  const stat = fs.lstatSync(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Integration directory must be a real directory: ${directory}`);
  if (uid !== undefined && stat.uid !== uid) throw new Error(`Integration directory is not owned by the current user: ${directory}`);
  if ((stat.mode & 0o022) !== 0) throw new Error(`Integration directory must not be group/world writable: ${directory}`);
}

function readSafeRemovalFile(file) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Integration file must be a regular file: ${file}`);
  if (uid !== undefined && stat.uid !== uid) throw new Error(`Integration file is not owned by the current user: ${file}`);
  if (stat.nlink !== 1) throw new Error(`Integration file must not be hard-linked: ${file}`);
  if (stat.size > 1024 * 1024) throw new Error(`Integration file is too large: ${file}`);
  return fs.readFileSync(file, "utf8");
}

function parseIntegrationDocument(plan, source) {
  let document;
  try { document = JSON.parse(source); }
  catch { throw new Error(`Refusing to modify invalid JSON integration file: ${plan.target}`); }
  if (!isPlainObject(document)) throw new Error("Integration configuration must be a JSON object");
  if (document.mcpServers !== undefined && !isPlainObject(document.mcpServers)) throw new Error("mcpServers must be a JSON object");
  const root = scanJsonObject(source, 0);
  const mcp = root.members.find((member) => member.key === "mcpServers");
  let mcpServersObject = null;
  let agentPassPresent = false;
  if (mcp) {
    if (root.members.filter((member) => member.key === "mcpServers").length !== 1) throw new Error("Duplicate mcpServers keys are unsafe to remove");
    mcpServersObject = scanJsonObject(source, mcp.valueStart);
    const entries = mcpServersObject.members.filter((member) => member.key === "agentpass");
    if (entries.length > 1) throw new Error("Duplicate agentpass keys are unsafe to remove");
    agentPassPresent = entries.length === 1;
  }
  return { document, mcpServersObject, agentPassPresent };
}

function locateAgentPassMember(document, plan) {
  if (!document.mcpServersObject) return null;
  const member = document.mcpServersObject.members.find((entry) => entry.key === "agentpass");
  if (!member) return null;
  let value;
  try { value = JSON.parse(member.rawValue); } catch { throw new Error("Refusing to modify invalid JSON integration member"); }
  return deepEqual(value, plan.expected_server) ? member : null;
}

function removeObjectMember(source, object, target) {
  const index = object.members.indexOf(target);
  if (index < 0) throw new Error("Removal member is not part of its JSON object");
  if (object.members.length === 1) return source.slice(0, target.start) + source.slice(target.end);
  if (index < object.members.length - 1) {
    return source.slice(0, target.start) + source.slice(object.members[index + 1].start);
  }
  return source.slice(0, object.members[index - 1].end) + source.slice(target.end);
}

function scanJsonObject(source, start) {
  let index = skipWhitespace(source, start);
  if (source[index] !== "{") throw new Error("JSON object structure is unsafe to remove");
  index = skipWhitespace(source, index + 1);
  const members = [];
  if (source[index] === "}") return { start, end: index + 1, members };
  while (index < source.length) {
    const startMember = index;
    const key = scanJsonString(source, index);
    index = skipWhitespace(source, key.end);
    if (source[index] !== ":") throw new Error("JSON object structure is unsafe to remove");
    if (members.some((member) => member.key === key.value)) throw new Error(`Duplicate ${key.value} keys are unsafe to remove`);
    const valueStart = skipWhitespace(source, index + 1);
    const value = scanJsonValue(source, valueStart);
    members.push({ key: key.value, start: startMember, end: value.end, valueStart, valueEnd: value.end, rawValue: source.slice(valueStart, value.end) });
    index = skipWhitespace(source, value.end);
    if (source[index] === "}") return { start, end: index + 1, members };
    if (source[index] !== ",") throw new Error("JSON object structure is unsafe to remove");
    index = skipWhitespace(source, index + 1);
  }
  throw new Error("JSON object is unterminated");
}

function scanJsonValue(source, start) {
  if (source[start] === '"') return scanJsonString(source, start);
  if (source[start] === "{") return scanJsonObject(source, start);
  if (source[start] === "[") {
    let index = skipWhitespace(source, start + 1);
    if (source[index] === "]") return { end: index + 1 };
    while (index < source.length) {
      index = scanJsonValue(source, index).end;
      index = skipWhitespace(source, index);
      if (source[index] === "]") return { end: index + 1 };
      if (source[index] !== ",") throw new Error("JSON array structure is unsafe to remove");
      index = skipWhitespace(source, index + 1);
    }
    throw new Error("JSON array is unterminated");
  }
  const match = source.slice(start).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
  if (!match) throw new Error("JSON value structure is unsafe to remove");
  return { end: start + match[0].length };
}

function scanJsonString(source, start) {
  let index = start + 1;
  while (index < source.length) {
    if (source[index] === "\\") { index += 2; continue; }
    if (source[index] === '"') {
      const raw = source.slice(start, index + 1);
      return { end: index + 1, value: JSON.parse(raw) };
    }
    index += 1;
  }
  throw new Error("JSON string is unterminated");
}

function skipWhitespace(source, index) {
  while (index < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[index])) index += 1;
  return index;
}

function deepEqual(left, right) {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => deepEqual(value, right[index]));
  }
  if (!isPlainObject(left) || !isPlainObject(right)) return false;
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return leftKeys.length === rightKeys.length && leftKeys.every((key) => Object.hasOwn(right, key) && deepEqual(left[key], right[key]));
}

function fsyncDirectory(directory) {
  try {
    const descriptor = fs.openSync(directory, "r");
    try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  } catch (error) {
    if (error.code !== "EINVAL" && error.code !== "ENOTSUP") throw error;
  }
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
