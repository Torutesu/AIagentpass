import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { audit } from "./audit.mjs";
import { capabilityStatePath, controlBundleV2StatePath, defaultConfigDir, loadConfig, loadSession, loadState, secureMkdir, socketPath } from "./config.mjs";
import { evaluateAgentRequest } from "./policy.mjs";
import { canonicalJson as canonicalIdentityJson, verifyRequestIdentity } from "./identity.mjs";
import { evaluateRemoteControl, loadControlBundle, startControlRefresh } from "./remote-control.mjs";
import { evaluateControlBundle, loadControlBundleState, policyScopeAllows, verifyCachedControlBundle } from "./control-bundle-v2.mjs";
import { scopeAllows, verifyCapability } from "../packages/capability/src/index.mjs";
import { createAuthorizationTransaction } from "./audit-transaction.mjs";
import { loadCapabilityState, reserveCapabilityUse } from "./capability-state.mjs";
import { createCloudControlClient } from "./cloud-control.mjs";

const MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;

export function createBroker({ socket = socketPath(), signer = runSigner, configDir = defaultConfigDir } = {}) {
  secureMkdir(path.dirname(socket));
  const lock = acquireBrokerLock(socket);
  try {
    removeStaleSocket(socket, lock.recovered);
    const startupConfig = loadConfig(configDir);
    const configDigest = digestConfig(startupConfig);
    const replayCache = new Map();
    const controlCache = { highestSequence: 0, bundle: null, capabilitySequence: {}, consumedCapabilities: new Set() };
    if (startupConfig.control) loadControlBundle(startupConfig, configDir, controlCache);
    const server = net.createServer({ allowHalfOpen: true }, (connection) => handleConnection(connection, signer, configDir, configDigest, replayCache, controlCache));
    const controlTimer = startControlRefresh(startupConfig, configDir, controlCache, { onEvent: (event) => {
      try { audit({ operation: "control.refresh", decision: event.result === "updated" ? "allow" : "error", ...event }, configDir); } catch {}
    } });
    server.listen(socket, () => fs.chmodSync(socket, 0o600));
    server.on("error", () => {
      if (controlTimer) clearInterval(controlTimer);
      releaseBrokerLock(lock);
    });
    server.on("close", () => {
      try { fs.unlinkSync(socket); } catch {}
      if (controlTimer) clearInterval(controlTimer);
      releaseBrokerLock(lock);
    });
    return server;
  } catch (error) {
    releaseBrokerLock(lock);
    throw error;
  }
}

async function handleConnection(connection, signer, configDir, configDigest, replayCache, controlCache) {
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
      response = await processRequest(request, signer, configDir, configDigest, replayCache, controlCache);
    } catch (error) {
      response = { ok: false, error: error.message };
    }
    if (!connection.destroyed) connection.end(`${JSON.stringify(response)}\n`);
  });
}

export async function processRequest(request, signer = runSigner, configDir = defaultConfigDir, expectedConfigDigest = null, replayCache = new Map(), controlCache = { highestSequence: 0, bundle: null, capabilitySequence: {}, consumedCapabilities: new Set() }) {
  if (!request || typeof request !== "object") throw new Error("Invalid broker request");
  if (request.operation === "ping") return { ok: true, version: 2, control: { sequence: controlCache.highestSequence ?? 0, expires_at: controlCache.bundle?.expires_at ?? null, global_revoked: controlCache.bundle?.global_revoked ?? false, revoked_agents: controlCache.bundle?.revoked_agents?.length ?? 0, revoked_capabilities: controlCache.bundle?.revoked_capabilities?.length ?? 0, last_fetch_at: controlCache.last_fetch_at ?? null, last_fetch_error: controlCache.last_fetch_error ?? null } };
  if (request.operation !== "git.commit.sign") throw new Error("Unsupported broker operation");

  const requestId = request.request_id;
  if (typeof requestId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId)) throw new Error("A signed UUID request_id is required");
  const payload = decodePayload(request.payload_base64);
  const config = loadConfig(configDir);
  if (expectedConfigDigest && digestConfig(config) !== expectedConfigDigest) throw new Error("Broker configuration changed after startup; refusing requests until trusted restart");
  if (config.version < 4) throw new Error("Configuration version 4 is required; run agentpass migrate");
  const authorizationTransaction = createAuthorizationTransaction({ directory: configDir });
  const unsignedRequest = { ...request };
  delete unsignedRequest.signature;
  const requestDigest = crypto.createHash("sha256").update(canonicalIdentityJson(unsignedRequest)).digest("hex");
  const existingOutcome = authorizationTransaction.getOutcome(requestId, { requestDigest });
  if (existingOutcome) {
    // Re-authenticate the exact signed envelope without consuming the live
    // nonce cache. This permits an idempotent transport retry while preventing
    // request_id-only signature disclosure.
    verifyRequestIdentity(request, config, new Map());
    if (existingOutcome.outcome === "allow" && existingOutcome.signature) return { ok: true, request_id: requestId, stdout_base64: existingOutcome.signature.toString("base64"), replayed: true };
    throw new Error(`Previous authorization outcome is ${existingOutcome.outcome}: ${existingOutcome.reason}`);
  }
  const identity = verifyRequestIdentity(request, config, replayCache);
  const controlBundle = config.control_v2 ? null : loadControlBundle(config, configDir, controlCache);
  const controlDecision = config.control_v2 ? { allowed: true } : evaluateRemoteControl(controlBundle, identity.id);
  if (!controlDecision.allowed) {
    audit({ request_id: requestId, operation: "git.commit.sign", agent_id: identity.id, agent_name: identity.name, payload_sha256: crypto.createHash("sha256").update(payload).digest("hex"), decision: "deny", reason: controlDecision.reason, control_sequence: controlDecision.sequence }, configDir);
    throw new Error(`Denied by remote control: ${controlDecision.reason}`);
  }
  const state = loadState(configDir);
  const context = trustedGitContext(request.cwd);
  const commit = validateCommitPayload(payload, context.cwd);
  let cloudBundle = null;
  let verifiedCapability = null;
  if (config.control_v2) {
    if (config.control_v2.url && config.native_broker?.enabled !== true) {
      const client = createCloudControlClient({
        endpoint: config.control_v2.url,
        organizationId: config.control_v2.organization_id,
        deviceId: config.control_v2.device_id,
        issuer: config.control_v2.issuer,
        keyId: config.control_v2.key_id,
        publicKey: config.control_v2.public_key,
        privateKey: readProtectedDevicePrivateKey(config.control_v2.device_private_key_path),
        statePath: config.control_v2.state_path ?? controlBundleV2StatePath(configDir)
      });
      try {
        const synced = await client.sync();
        controlCache.highestSequence = synced.sequence;
        controlCache.bundle = synced.bundle;
        controlCache.last_fetch_at = synced.last_fetch_at;
        controlCache.last_fetch_error = null;
      } catch (error) {
        controlCache.last_fetch_error = error.code ?? "control_sync_failed";
        if (config.control_v2.allow_offline !== true) throw new Error(`ControlBundle v2 online synchronization failed: ${controlCache.last_fetch_error}`);
      }
    }
    const stateFile = config.control_v2.state_path ?? controlBundleV2StatePath(configDir);
    const durable = loadControlBundleState(stateFile);
    if (!durable.active_bundle) throw new Error("Required ControlBundle v2 state is missing");
    cloudBundle = verifyCachedControlBundle(durable.active_bundle, {
      public_key: config.control_v2.public_key,
      issuer: config.control_v2.issuer,
      key_id: config.control_v2.key_id,
      audience: { organization_id: config.control_v2.organization_id, device_id: config.control_v2.device_id },
      sequenceState: durable
    }, { audience: { organization_id: config.control_v2.organization_id, device_id: config.control_v2.device_id }, sequenceState: durable });
    const remoteDecision = evaluateControlBundle(cloudBundle, { organization_id: config.control_v2.organization_id, device_id: config.control_v2.device_id, agent_id: identity.id });
    if (!remoteDecision.allowed) throw new Error(`Denied by ControlBundle v2: ${remoteDecision.reason}`);
    if (!policyScopeAllows(cloudBundle, { operation: "git.commit.sign", repository: context.cwd, branch: context.branch, remote: context.remote })) throw new Error("Denied by ControlBundle v2 policy scope");
    if (!request.capability || typeof request.capability !== "object") throw new Error("A short-lived cloud capability is required");
    const capabilityFile = capabilityStatePath(configDir);
    const durableCapabilities = loadCapabilityState(capabilityFile);
    const durableHead = durableCapabilities.agents[identity.id];
    const capabilityState = { highestSequence: durableHead?.highest_sequence ?? 0, ...(durableHead?.highest_capability_hash ? { highestCapabilityHash: durableHead.highest_capability_hash } : {}) };
    verifiedCapability = verifyCapability(request.capability, { public_key: config.control_v2.public_key, issuer: config.control_v2.issuer, key_id: config.control_v2.key_id }, { audience: { agent_id: identity.id, device_id: config.control_v2.device_id }, sequenceState: capabilityState });
    const capabilityDecision = evaluateControlBundle(cloudBundle, { capability_id: verifiedCapability.capability_id });
    if (!capabilityDecision.allowed) throw new Error(`Denied by ControlBundle v2: ${capabilityDecision.reason}`);
    if (!scopeAllows(verifiedCapability.scope, { operation: "git.commit.sign", repository: context.cwd, branch: context.branch, remote: context.remote })) throw new Error("Denied by cloud capability scope");
  }
  const sessionValid = validateSession(loadSession(request.session, configDir), request.session, state.generation, identity.id);
  const requestContext = {
    policy: { ...config, session: { ...config.session, valid: sessionValid } },
    cwd: context.cwd,
    branch: context.branch,
    remote: context.remote,
    operation: "git.commit.sign",
    revoked: state.revoked
  };
  const decision = evaluateAgentRequest(requestContext, identity);
  const key = expandHome(config.signing?.key);
  const payloadSha256 = crypto.createHash("sha256").update(payload).digest("hex");
  const baseEvent = { request_id: requestId, operation: "git.commit.sign", agent_id: identity.id, agent_name: identity.name, cwd: context.cwd, branch: context.branch, remote: context.remote, payload_sha256: payloadSha256, tree: commit.tree, parents: commit.parents, signing_key: key };
  if (!decision.allowed) {
    audit({ ...baseEvent, decision: "deny", reason: decision.reason }, configDir);
    throw new Error(`Denied by policy: ${decision.reason}`);
  }
  // Re-evaluate all trusted Git facts immediately before crossing the signer
  // boundary. Repository state is mutable and the earlier policy check must not
  // become a stale authorization for a different tree, branch, or remote.
  const finalContext = trustedGitContext(context.cwd);
  if (finalContext.cwd !== context.cwd || finalContext.branch !== context.branch || finalContext.remote !== context.remote) {
    audit({ ...baseEvent, decision: "deny", reason: "git_context_changed" }, configDir);
    throw new Error("Denied because trusted Git context changed before signing");
  }
  try {
    validateCommitPayload(payload, finalContext.cwd);
  } catch (error) {
    audit({ ...baseEvent, decision: "deny", reason: "git_context_changed" }, configDir);
    throw new Error(`Denied because trusted Git context changed before signing: ${error.message}`);
  }

  // Consume only after the final trusted Git revalidation. A mutable repository
  // must not be able to burn a one-shot capability before authorization settles.
  if (verifiedCapability) reserveCapabilityUse(capabilityStatePath(configDir), { capability: verifiedCapability, agentId: identity.id, requestId });

  const signArgs = sanitizeSignArgs(request.sign_args, key);
  const trustedContextDigest = crypto.createHash("sha256").update(JSON.stringify({ cwd: context.cwd, branch: context.branch, remote: context.remote, tree: commit.tree, parents: commit.parents })).digest("hex");
  const outcome = await authorizationTransaction.execute({
    intent: {
      request_id: requestId,
      request_digest: requestDigest,
      trusted_context_digest: trustedContextDigest,
      policy_sequence: cloudBundle?.sequence ?? 0,
      capability_sequence: verifiedCapability?.sequence ?? 0,
      payload_digest: payloadSha256
    },
    signer: async () => signer({ args: signArgs, payload, provider: config.signing?.provider || "/usr/lib/ssh-keychain.dylib" })
  });
  if (outcome.outcome !== "allow" || !outcome.signature) throw new Error(`Signing failed: ${outcome.reason}`);
  return { ok: true, request_id: requestId, stdout_base64: outcome.signature.toString("base64") };
}

function readProtectedDevicePrivateKey(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("ControlBundle v2 device private key path is invalid");
  const parent = fs.lstatSync(path.dirname(file));
  const before = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || (uid !== undefined && parent.uid !== uid) || (parent.mode & 0o077) !== 0) throw new Error("ControlBundle v2 device key directory is unsafe");
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (uid !== undefined && before.uid !== uid) || (before.mode & 0o077) !== 0 || before.size > 16 * 1024) throw new Error("ControlBundle v2 device private key is unsafe");
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1) throw new Error("ControlBundle v2 device private key changed during open");
    const key = crypto.createPrivateKey(fs.readFileSync(descriptor));
    if (!['ed25519', 'ec'].includes(key.asymmetricKeyType) || (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')) throw new Error("ControlBundle v2 device private key must be Ed25519 or P-256");
    return key;
  } finally { fs.closeSync(descriptor); }
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
  if (!Buffer.isBuffer(payload) || payload.length === 0 || payload.length > MAX_PAYLOAD_BYTES) throw new Error("Signing payload size is invalid");
  if (payload.includes(0)) throw new Error("Signing payload contains a NUL byte");
  if (payload.includes(13)) throw new Error("Signing payload contains a carriage return");
  const headerEnd = payload.indexOf(Buffer.from("\n\n"));
  if (headerEnd < 0) throw new Error("Signing payload is not a Git commit object");
  const headerText = payload.subarray(0, headerEnd).toString("utf8");
  const lines = headerText.split("\n");
  if (lines.some((line) => line.startsWith(" "))) throw new Error("Signing payload contains an unsupported continued header");
  if (lines.some((line) => line.startsWith("gpgsig ") || line.startsWith("gpgsig-sha256 "))) throw new Error("Signing payload already contains a signature header");
  const treeLines = lines.filter((line) => line.startsWith("tree "));
  const authorLines = lines.filter((line) => line.startsWith("author "));
  const committerLines = lines.filter((line) => line.startsWith("committer "));
  if (treeLines.length !== 1 || authorLines.length !== 1 || committerLines.length !== 1) throw new Error("Signing payload must contain exactly one tree, author, and committer header");
  const treeLine = treeLines[0];
  const parents = lines.filter((line) => line.startsWith("parent ")).map((line) => line.slice(7));
  const tree = treeLine.slice(5);
  if (!/^[0-9a-f]{40,64}$/.test(tree) || parents.some((parent) => !/^[0-9a-f]{40,64}$/.test(parent))) throw new Error("Signing payload contains an invalid Git object ID");
  const expectedTree = git(cwd, ["write-tree"]);
  if (tree !== expectedTree) throw new Error("Signing payload tree does not match the repository index");
  const head = git(cwd, ["rev-parse", "--verify", "HEAD"], true);
  if (!head) {
    if (parents.length !== 0) throw new Error("Initial commit payload must not contain a parent");
    return { tree, parents: [] };
  }
  const expectedParents = [head, ...readMergeHeads(cwd)];
  if (parents.length !== expectedParents.length || parents.some((parent, index) => parent !== expectedParents[index])) throw new Error("Signing payload parents do not match HEAD and MERGE_HEAD");
  return { tree, parents };
}

function readMergeHeads(cwd) {
  const gitPath = git(cwd, ["rev-parse", "--git-path", "MERGE_HEAD"], true);
  if (!gitPath) return [];
  const file = path.isAbsolute(gitPath) ? gitPath : path.resolve(cwd, gitPath);
  if (!fs.existsSync(file)) return [];
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Repository MERGE_HEAD is not a regular file");
  const heads = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
  if (!heads.length || heads.some((head) => !/^[0-9a-f]{40,64}$/.test(head))) throw new Error("Repository MERGE_HEAD is invalid");
  return heads;
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
  const result = spawnSync("/usr/bin/git", ["-C", cwd, ...args], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }
  });
  if (result.status !== 0) {
    if (optional) return "";
    throw new Error(result.stderr.trim() || "Git context verification failed");
  }
  return result.stdout.trim();
}

function validateSession(session, supplied, generation, agentId) {
  if (!session || typeof supplied !== "string" || Date.now() >= Date.parse(session.expires_at) || session.generation !== generation || session.agent_id !== agentId) return false;
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
  const { audit_anchor: _auditAnchor, ...brokerConfig } = config;
  return crypto.createHash("sha256").update(JSON.stringify(brokerConfig)).digest("hex");
}
