import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { audit } from "./audit.mjs";
import { defaultConfigDir, loadConfig, loadSession, loadState, secureMkdir, socketPath } from "./config.mjs";
import { evaluateRequest } from "./policy.mjs";
import { verifyRequestIdentity } from "./identity.mjs";

const MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;

export function createBroker({ socket = socketPath(), signer = runSigner, configDir = defaultConfigDir } = {}) {
  secureMkdir(path.dirname(socket));
  const lock = acquireBrokerLock(socket);
  try {
    removeStaleSocket(socket, lock.recovered);
    const configDigest = digestConfig(loadConfig(configDir));
    const replayCache = new Map();
    const server = net.createServer({ allowHalfOpen: true }, (connection) => handleConnection(connection, signer, configDir, configDigest, replayCache));
    server.listen(socket, () => fs.chmodSync(socket, 0o600));
    server.on("error", () => releaseBrokerLock(lock));
    server.on("close", () => {
      try { fs.unlinkSync(socket); } catch {}
      releaseBrokerLock(lock);
    });
    return server;
  } catch (error) {
    releaseBrokerLock(lock);
    throw error;
  }
}

async function handleConnection(connection, signer, configDir, configDigest, replayCache) {
  let input = "";
  let inputBytes = 0;
  connection.setEncoding("utf8");
  connection.setTimeout(30_000, () => connection.destroy(new Error("Request timed out")));
  connection.on("data", (chunk) => {
    input += chunk;
    inputBytes += Buffer.byteLength(chunk);
    if (inputBytes > MAX_REQUEST_BYTES) connection.destroy(new Error("Request too large"));
  });
  connection.on("error", () => {});
  connection.on("end", async () => {
    let response;
    try {
      const request = JSON.parse(input.trim());
      response = await processRequest(request, signer, configDir, configDigest, replayCache);
    } catch (error) {
      response = { ok: false, error: error.message };
    }
    if (!connection.destroyed) connection.end(`${JSON.stringify(response)}\n`);
  });
}

export async function processRequest(request, signer = runSigner, configDir = defaultConfigDir, expectedConfigDigest = null, replayCache = new Map()) {
  if (!request || typeof request !== "object") throw new Error("Invalid broker request");
  if (request.operation === "ping") return { ok: true, version: 1 };
  if (request.operation !== "git.commit.sign") throw new Error("Unsupported broker operation");

  const requestId = crypto.randomUUID();
  const payload = decodePayload(request.payload_base64);
  const config = loadConfig(configDir);
  if (expectedConfigDigest && digestConfig(config) !== expectedConfigDigest) throw new Error("Broker configuration changed after startup; refusing requests until trusted restart");
  if (config.version < 3) throw new Error("Configuration version 3 is required; run agentpass migrate");
  const identity = verifyRequestIdentity(request, config, replayCache);
  const state = loadState(configDir);
  const context = trustedGitContext(request.cwd);
  const commit = validateCommitPayload(payload, context.cwd);
  const sessionValid = validateSession(loadSession(configDir), request.session, state.generation);
  const decision = evaluateRequest({
    policy: { ...config, session: { ...config.session, valid: sessionValid } },
    cwd: context.cwd,
    branch: context.branch,
    remote: context.remote,
    operation: "git.commit.sign",
    revoked: state.revoked
  });
  const key = expandHome(config.signing?.key);
  const payloadSha256 = crypto.createHash("sha256").update(payload).digest("hex");
  const baseEvent = { request_id: requestId, operation: "git.commit.sign", agent_id: identity.id, agent_name: identity.name, cwd: context.cwd, branch: context.branch, remote: context.remote, payload_sha256: payloadSha256, tree: commit.tree, parent: commit.parent, signing_key: key };
  if (!decision.allowed) {
    audit({ ...baseEvent, decision: "deny", reason: decision.reason }, configDir);
    throw new Error(`Denied by policy: ${decision.reason}`);
  }

  const signArgs = sanitizeSignArgs(request.sign_args, key);
  const result = await signer({ args: signArgs, payload, provider: config.signing?.provider || "/usr/lib/ssh-keychain.dylib" });
  if (result.status !== 0) {
    audit({ ...baseEvent, decision: "error", reason: "signer_failed", status: result.status }, configDir);
    throw new Error(result.stderr || "ssh-keygen failed");
  }
  audit({ ...baseEvent, decision: "allow", reason: "allowed" }, configDir);
  return { ok: true, request_id: requestId, stdout_base64: Buffer.from(result.stdout).toString("base64") };
}

export function sanitizeSignArgs(args, configuredKey) {
  if (!Array.isArray(args)) throw new Error("Missing signing arguments");
  let operation = false;
  let namespace = false;
  const options = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value === "-Y" && args[index + 1] === "sign") { operation = true; index += 1; continue; }
    if (value === "-n" && args[index + 1] === "git") { namespace = true; index += 1; continue; }
    if (value === "-f" && args[index + 1]) { index += 1; continue; }
    if (value === "-O" && ["hashalg=sha256", "hashalg=sha512"].includes(args[index + 1])) { options.push("-O", args[index + 1]); index += 1; continue; }
    if (value === "-q") continue;
    throw new Error(`Unsupported ssh-keygen argument: ${value}`);
  }
  if (!operation || !namespace) throw new Error("Only ssh-keygen -Y sign -n git is allowed");
  if (!configuredKey || !path.isAbsolute(configuredKey)) throw new Error("Configured signing key must resolve to an absolute path");
  return ["-Y", "sign", "-n", "git", "-f", configuredKey, ...options];
}

export function validateCommitPayload(payload, cwd) {
  const headerEnd = payload.indexOf(Buffer.from("\n\n"));
  if (headerEnd < 0) throw new Error("Signing payload is not a Git commit object");
  const headerText = payload.subarray(0, headerEnd).toString("utf8");
  const lines = headerText.split("\n");
  const treeLine = lines.find((line) => line.startsWith("tree "));
  const parents = lines.filter((line) => line.startsWith("parent ")).map((line) => line.slice(7));
  if (!treeLine || !lines.some((line) => line.startsWith("author ")) || !lines.some((line) => line.startsWith("committer "))) throw new Error("Signing payload is missing required commit headers");
  if (parents.length > 1) throw new Error("Merge commit signing is not enabled by the current policy engine");
  const tree = treeLine.slice(5);
  if (!/^[0-9a-f]{40,64}$/.test(tree) || parents.some((parent) => !/^[0-9a-f]{40,64}$/.test(parent))) throw new Error("Signing payload contains an invalid Git object ID");
  const expectedTree = git(cwd, ["write-tree"]);
  if (tree !== expectedTree) throw new Error("Signing payload tree does not match the repository index");
  const head = git(cwd, ["rev-parse", "--verify", "HEAD"], true);
  if (head && parents[0] !== head) throw new Error("Signing payload parent does not match HEAD");
  if (!head && parents.length !== 0) throw new Error("Initial commit payload must not contain a parent");
  return { tree, parent: parents[0] ?? null };
}

function trustedGitContext(requestedCwd) {
  if (typeof requestedCwd !== "string" || !path.isAbsolute(requestedCwd)) throw new Error("cwd must be an absolute path");
  const cwd = git(requestedCwd, ["rev-parse", "--show-toplevel"]);
  return {
    cwd: fs.realpathSync(cwd),
    branch: git(cwd, ["branch", "--show-current"], true) || "HEAD",
    remote: git(cwd, ["remote", "get-url", "origin"], true)
  };
}

function git(cwd, args, optional = false) {
  const result = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", env: { PATH: process.env.PATH } });
  if (result.status !== 0) {
    if (optional) return "";
    throw new Error(result.stderr.trim() || "Git context verification failed");
  }
  return result.stdout.trim();
}

function validateSession(session, supplied, generation) {
  if (!session || typeof supplied !== "string" || Date.now() >= Date.parse(session.expires_at) || session.generation !== generation) return false;
  const actual = crypto.createHash("sha256").update(supplied).digest();
  const expected = Buffer.from(session.token_hash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function decodePayload(value) {
  if (typeof value !== "string") throw new Error("Missing signing payload");
  if (value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("Signing payload is not valid base64");
  const payload = Buffer.from(value, "base64");
  if (payload.length === 0 || payload.length > MAX_PAYLOAD_BYTES) throw new Error("Signing payload size is invalid");
  return payload;
}

function runSigner({ args, payload, provider }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-sign-"));
  const input = path.join(directory, "payload");
  const signature = `${input}.sig`;
  try {
    fs.writeFileSync(input, payload, { mode: 0o600 });
    const result = spawnSync("/usr/bin/ssh-keygen", [...args, input], {
      maxBuffer: 16 * 1024 * 1024,
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", SSH_SK_PROVIDER: provider }
    });
    const output = result.status === 0 && fs.existsSync(signature) ? fs.readFileSync(signature) : Buffer.alloc(0);
    return { status: result.status ?? 1, stdout: output, stderr: String(result.stderr ?? "").trim() };
  } finally {
    try { fs.unlinkSync(signature); } catch {}
    try { fs.unlinkSync(input); } catch {}
    try { fs.rmdirSync(directory); } catch {}
  }
}

function expandHome(value) {
  if (!value) return "";
  return value.startsWith("~/") ? path.join(os.homedir(), value.slice(2)) : path.resolve(value);
}

function removeStaleSocket(socket, lockRecovered) {
  if (!fs.existsSync(socket)) return;
  const stat = fs.lstatSync(socket);
  const uid = process.getuid?.();
  if (!stat.isSocket() || (uid !== undefined && stat.uid !== uid)) throw new Error(`Refusing to replace unsafe broker socket: ${socket}`);
  if (!lockRecovered) throw new Error(`Broker socket exists without a recoverable lease; inspect before removing: ${socket}`);
  fs.unlinkSync(socket);
}

function acquireBrokerLock(socket) {
  const lock = `${socket}.lock`;
  let recovered = false;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = fs.openSync(lock, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, started_at: Date.now() }));
      fs.closeSync(fd);
      return { path: lock, recovered };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let lease;
      try { lease = JSON.parse(fs.readFileSync(lock, "utf8")); } catch { throw new Error(`Broker lock is invalid; inspect before removing: ${lock}`); }
      if (!Number.isInteger(lease.pid)) throw new Error(`Broker lock is invalid; inspect before removing: ${lock}`);
      try {
        process.kill(lease.pid, 0);
        throw new Error(`AgentPass broker is already running with PID ${lease.pid}`);
      } catch (probeError) {
        if (probeError.code !== "ESRCH") throw probeError;
        const stat = fs.lstatSync(lock);
        const uid = process.getuid?.();
        if (!stat.isFile() || stat.isSymbolicLink() || (uid !== undefined && stat.uid !== uid)) throw new Error(`Refusing to replace unsafe broker lock: ${lock}`);
        fs.unlinkSync(lock);
        recovered = true;
      }
    }
  }
  throw new Error(`Unable to acquire broker lock: ${lock}`);
}

function releaseBrokerLock(lock) {
  try {
    const lease = JSON.parse(fs.readFileSync(lock.path, "utf8"));
    if (lease.pid === process.pid) fs.unlinkSync(lock.path);
  } catch {}
}

function digestConfig(config) {
  return crypto.createHash("sha256").update(JSON.stringify(config)).digest("hex");
}
