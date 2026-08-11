#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { addAgent, revokeAgent, rotateAgent, setAgentScope, setDefaultAgent } from "../lib/agent-admin.mjs";
import { anchorPendingCheckpoints, verifyStoredAnchorReceipts } from "../lib/anchor-client.mjs";
import { audit, createAuditCheckpoint, publicKeyFingerprint, verifyAudit, verifyAuditCheckpoints } from "../lib/audit.mjs";
import { brokerRequest } from "../lib/broker-client.mjs";
import { anchorReceiptPath, auditPath, controlBundlePath, defaultConfigDir, loadConfig, loadSession, loadState, saveConfig, saveSession, saveState, socketPath } from "../lib/config.mjs";
import { createAgentIdentity, createAuditIdentity, signRequest } from "../lib/identity.mjs";
import { readGitSigningInvocation, writeGitSignature } from "../lib/git-signing.mjs";
import { evaluateAgentRequest } from "../lib/policy.mjs";
import { applyControlBundle, controlKeyFingerprint, fetchControlBundle, generateControlKeyPair, loadControlBundle, signControlBundle } from "../lib/remote-control.mjs";

const [, , command, ...args] = process.argv;

function usage() {
  console.log(`AgentPass 0.15.0

Commands:
  init              create a secure local policy
  migrate           upgrade an older policy to signed-agent format
  status            show policy and revocation status
  check             evaluate the current repository
  doctor            check local prerequisites
  broker ping       verify that the signing broker is running
  broker install    install and start the macOS LaunchAgent
  broker stop       stop the macOS LaunchAgent
  native status     verify protected native audit and broker health
  native public-key print the native Git signing public key
  native audit-key  print the native audit checkpoint public key
  native checkpoint create a protected native audit checkpoint
  native session-approval-key  create/print the human-presence approval key
  native revoke-sessions       immediately invalidate protected native sessions
  native daemon-register       register the bundled privileged service
  native daemon-unregister     unregister the bundled privileged service
  native daemon-status         inspect Service Management registration
  native daemon-open-settings  open macOS Login Items settings
  agent list        list enrolled agent identities
  agent add NAME    enroll a new agent identity
  agent set-default ID
  agent scope ID    replace per-agent authorization scope
  agent rotate ID   replace an agent identity key
  agent revoke ID   revoke an identity (--confirm REVOKE)
  setup-macos       show Secure Enclave setup (use --execute to run)
  install-hook      install a policy-enforcing pre-push hook
  push-check        evaluate a pre-push request
  session start     issue a short-lived agent session token
  revoke            immediately deny all operations
  restore           re-enable operations after revocation
  git-sign [args]   send a signing request to the broker
  audit [--verify]  print or verify audit logs and checkpoints
  audit checkpoint  sign the current audit head
  audit public-key  print the checkpoint verification key
  audit anchor trust --url HTTPS_URL --tenant TENANT --key PUBLIC_KEY
  audit anchor push
  audit anchor status
  control keygen DIR
  control trust PUBLIC_KEY [--url HTTPS_URL]
  control sign       create an offline-signed control bundle
  control source URL configure the native HTTPS distribution URL
  control apply FILE verify and install a control bundle
  control fetch      fetch and install the configured HTTPS bundle
  control status     inspect active remote revocation state
`);
}

function git(gitArgs, optional = false) {
  const result = spawnSync("git", gitArgs, { encoding: "utf8" });
  if (result.status !== 0) {
    if (optional) return "";
    throw new Error(result.stderr.trim() || `git ${gitArgs.join(" ")} failed`);
  }
  return result.stdout.trim();
}

function init() {
  const dir = defaultConfigDir;
  if (fs.existsSync(path.join(dir, "config.json"))) throw new Error(`Already initialized: ${dir}`);
  const repository = git(["rev-parse", "--show-toplevel"], true) || process.cwd();
  const origin = git(["remote", "get-url", "origin"], true);
  const identity = createAgentIdentity(dir, process.env.AGENTPASS_AGENT ?? "coding-agent");
  const auditIdentity = createAuditIdentity(dir);
  const operations = ["git.commit.sign"];
  const repositories = [path.resolve(repository)];
  const branches = { allow: ["feature/*", "fix/*", "chore/*"], deny: ["main", "master", "production"] };
  const remotes = { allow: origin ? [origin] : [] };
  saveConfig({
    version: 4,
    agent: { name: process.env.AGENTPASS_AGENT ?? "coding-agent" },
    agents: [{ id: identity.id, name: identity.name, public_key: identity.public_key, scope: { operations, repositories, branches, remotes } }],
    default_agent_id: identity.id,
    operations,
    repositories,
    branches,
    remotes,
    signing: { key: path.join(defaultConfigDir, "keys", "id_git_sign"), provider: "/usr/lib/ssh-keychain.dylib" },
    audit_signing: { public_key: auditIdentity.public_key },
    session: { required: true, ttl_seconds: 3600 }
  }, dir);
  saveState({ revoked: false, generation: 0 }, dir);
  audit({ operation: "config.init", decision: "allow", agent: process.env.AGENTPASS_AGENT ?? "coding-agent" }, dir);
  console.log(`Initialized ${dir}`);
}

function migrate() {
  const config = loadConfig();
  if (config.version >= 4) throw new Error("Configuration is already at version 4");
  const identity = config.version >= 3 ? null : createAgentIdentity(defaultConfigDir, config.agent?.name ?? "coding-agent");
  const auditIdentity = createAuditIdentity(defaultConfigDir);
  const policy = scopeFromPolicy(config);
  const previousTtl = Number(config.session?.ttl_seconds);
  const ttlSeconds = Number.isFinite(previousTtl) ? Math.max(60, Math.min(previousTtl, 86400)) : 3600;
  const migrated = {
    ...config,
    version: 4,
    agents: (identity ? [{ id: identity.id, name: identity.name, public_key: identity.public_key }] : config.agents).map((agent) => ({ ...agent, scope: agent.scope ?? policy })),
    default_agent_id: identity ? identity.id : config.default_agent_id,
    operations: policy.operations,
    repositories: policy.repositories,
    branches: policy.branches,
    remotes: policy.remotes,
    audit_signing: { public_key: auditIdentity.public_key },
    session: { ...config.session, ttl_seconds: ttlSeconds, required: true }
  };
  saveConfig(migrated);
  audit({ operation: "config.migrate", decision: "allow", from_version: config.version, to_version: 4, agent_id: identity?.id ?? config.default_agent_id }, defaultConfigDir);
  console.log("Migrated to configuration version 4. Restart the AgentPass broker.");
}

function context(config) {
  const root = git(["rev-parse", "--show-toplevel"]);
  const supplied = process.env.AGENTPASS_SESSION;
  const session = loadSession(supplied);
  const agentId = process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id;
  const sessionValid = isSessionValid(session, supplied, agentId);
  return {
    cwd: root,
    branch: git(["branch", "--show-current"], true) || "HEAD",
    remote: git(["remote", "get-url", "origin"], true),
    revoked: loadState().revoked,
    policy: { ...config, session: { ...config.session, valid: sessionValid } }
  };
}

function isSessionValid(session, supplied, agentId) {
  return Boolean(session && supplied && session.agent_id === agentId && crypto.createHash("sha256").update(supplied).digest("hex") === session.token_hash && Date.now() < Date.parse(session.expires_at) && session.generation === loadState().generation);
}

async function sessionStart() {
  const config = loadConfig();
  const agentFlag = args.indexOf("--agent");
  const agentId = agentFlag >= 0 ? args[agentFlag + 1] : (process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id);
  if (!config.agents?.some((agent) => agent.id === agentId)) throw new Error("Cannot create a session for an unknown agent identity");
  const ttlArgument = args.slice(1).find((value, index, values) => value !== "--agent" && values[index - 1] !== "--agent");
  const ttl = Math.max(60, Math.min(Number(ttlArgument ?? config.session?.ttl_seconds ?? 3600), 86400));
  if (!Number.isFinite(ttl)) throw new Error("Session TTL must be a number of seconds");
  if (config.native_broker?.enabled) {
    const result = await brokerRequest({ operation: "native.session.start", agent_id: agentId, ttl_seconds: ttl }, { native: config.native_broker, timeoutMs: 120_000 });
    const issued = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
    if (typeof issued.token !== "string" || typeof issued.expires_at !== "string" || issued.agent_id !== agentId) throw new Error("Native service returned an invalid session");
    console.log(issued.token);
    console.error(`Session expires at ${issued.expires_at}`);
    return;
  }
  const token = crypto.randomBytes(32).toString("base64url");
  const state = loadState();
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  saveSession({ token_hash: crypto.createHash("sha256").update(token).digest("hex"), expires_at: expiresAt, generation: state.generation, agent_id: agentId });
  audit({ operation: "session.start", decision: "allow", expires_at: expiresAt, generation: state.generation, agent_id: agentId }, defaultConfigDir);
  console.log(token);
  console.error(`Session expires at ${expiresAt}`);
}

function check() {
  const config = loadConfig();
  const identity = selectedAgent(config);
  const result = evaluateAgentRequest({ ...context(config), operation: "git.commit.sign" }, identity);
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: process.cwd() }, defaultConfigDir);
  console.log(JSON.stringify(result, null, 2));
  if (!result.allowed) process.exitCode = 1;
}

function status() {
  const config = loadConfig();
  const state = loadState();
  console.log(JSON.stringify({
    version: config.version,
    agent: config.agent,
    agents: config.agents?.map((agent) => ({ id: agent.id, name: agent.name, default: agent.id === config.default_agent_id })),
    operations: config.operations,
    repositories: config.repositories,
    revoked: state.revoked,
    generation: state.generation,
    audit: auditPath(),
    audit_key_fingerprint: config.audit_signing?.public_key ? publicKeyFingerprint(config.audit_signing.public_key) : null
  }, null, 2));
}

function revoke() {
  const config = loadConfig();
  if (config.native_broker?.enabled) throw new Error("User-state revoke does not control the native service; use `agentpass native revoke-sessions`");
  const state = loadState();
  saveState({ ...state, revoked: true, generation: (state.generation ?? 0) + 1, revoked_at: new Date().toISOString() });
  audit({ operation: "control.revoke", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("All AgentPass operations revoked.");
}

function restore() {
  const config = loadConfig();
  if (config.native_broker?.enabled) throw new Error("User-state restore does not control the native service; start a new protected native session instead");
  if (args[0] !== "--confirm" || args[1] !== "RESTORE") throw new Error("Restoring requires: agentpass restore --confirm RESTORE");
  const state = loadState();
  saveState({ ...state, revoked: false, generation: (state.generation ?? 0) + 1, restored_at: new Date().toISOString() });
  audit({ operation: "control.restore", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("AgentPass operations restored.");
}

function doctor() {
  const checks = [
    { name: "node", ok: Number(process.versions.node.split(".")[0]) >= 20, detail: process.versions.node },
    { name: "platform", ok: process.platform === "darwin", detail: `${process.platform}/${process.arch}` },
    { name: "git", ok: Boolean(spawnSync("git", ["--version"], { encoding: "utf8" }).stdout), detail: git(["--version"], true) },
    { name: "ssh-keygen", ok: fs.existsSync("/usr/bin/ssh-keygen"), detail: "/usr/bin/ssh-keygen" },
    { name: "config", ok: fs.existsSync(path.join(defaultConfigDir, "config.json")), detail: defaultConfigDir },
    { name: "broker-socket", ok: fs.existsSync(socketPath()), detail: socketPath() }
  ];
  if (fs.existsSync(path.join(defaultConfigDir, "config.json"))) {
    try {
      const config = loadConfig();
      if (config.control) {
        const bundle = loadControlBundle(config, defaultConfigDir);
        checks.push({ name: "remote-control", ok: true, detail: `sequence=${bundle.sequence} expires=${bundle.expires_at}` });
      }
    } catch (error) {
      checks.push({ name: "remote-control", ok: false, detail: error.message });
    }
  }
  console.log(JSON.stringify({ ok: checks.every((check) => check.ok), checks }, null, 2));
  if (!checks.every((check) => check.ok)) process.exitCode = 1;
}

function setupMacos() {
  if (process.platform !== "darwin") throw new Error("Secure Enclave setup is currently supported only on macOS");
  const commands = [
    "sc_auth create-ctk-identity -l agentpass-git-sign -k p-256-ne -t none",
    "mkdir -p ~/.agentpass/keys",
    "cd ~/.agentpass/keys && ssh-keygen -w /usr/lib/ssh-keychain.dylib -K -N \"\"",
    "mv ~/.agentpass/keys/id_ecdsa_sk_rk ~/.agentpass/keys/id_git_sign",
    "mv ~/.agentpass/keys/id_ecdsa_sk_rk.pub ~/.agentpass/keys/id_git_sign.pub"
  ];
  if (!args.includes("--execute")) {
    console.log(commands.join("\n"));
    console.log("\nDry run only. Re-run with --execute after reviewing the commands.");
    return;
  }
  const keyDir = path.join(defaultConfigDir, "keys");
  if (!args.includes("--force") && (fs.existsSync(path.join(keyDir, "id_git_sign")) || fs.existsSync(path.join(keyDir, "id_git_sign.pub")))) {
    throw new Error("AgentPass signing key already exists; use --force only if you intend to replace it");
  }
  if (args.includes("--force")) {
    const backup = `${Date.now()}.bak`;
    for (const file of ["id_git_sign", "id_git_sign.pub"]) {
      const target = path.join(keyDir, file);
      if (fs.existsSync(target)) fs.renameSync(target, `${target}.${backup}`);
    }
  }
  let result = spawnSync("sc_auth", ["create-ctk-identity", "-l", "agentpass-git-sign", "-k", "p-256-ne", "-t", "none"], { stdio: "inherit" });
  if (result.status !== 0) throw new Error("Setup command failed: sc_auth");
  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  result = spawnSync("/usr/bin/ssh-keygen", ["-w", "/usr/lib/ssh-keychain.dylib", "-K", "-N", ""], { stdio: "inherit", cwd: keyDir });
  if (result.status !== 0) throw new Error("Setup command failed: ssh-keygen");
  fs.renameSync(path.join(keyDir, "id_ecdsa_sk_rk"), path.join(keyDir, "id_git_sign"));
  fs.renameSync(path.join(keyDir, "id_ecdsa_sk_rk.pub"), path.join(keyDir, "id_git_sign.pub"));
  fs.chmodSync(path.join(keyDir, "id_git_sign"), 0o600);
  fs.chmodSync(path.join(keyDir, "id_git_sign.pub"), 0o644);
  console.log("Secure Enclave-backed SSH signing key created.");
}

function installHook() {
  const root = git(["rev-parse", "--show-toplevel"]);
  const hook = path.join(root, ".git", "hooks", "pre-push");
  if (fs.existsSync(hook) && !args.includes("--force")) throw new Error(`${hook} exists; use --force to replace it`);
  const wrapper = fileURLToPath(new URL("./agentpass-pre-push.mjs", import.meta.url));
  fs.writeFileSync(hook, `#!/bin/sh\nexec /usr/bin/env node ${JSON.stringify(wrapper)} "$@"\n`, { mode: 0o755 });
  fs.chmodSync(hook, 0o755);
  console.log(`Installed ${hook}`);
}

async function pushCheck() {
  const config = loadConfig();
  const state = loadState();
  const remote = args[0] ?? "origin";
  const remoteUrl = args[1] ?? git(["remote", "get-url", remote], true);
  const lines = fs.readFileSync(0, "utf8").trim().split("\n").filter(Boolean);
  const refs = lines.length ? lines : [`local 0000000 refs/heads/${git(["branch", "--show-current"], true)} 0000000`];
  const identity = selectedAgent(config);
  let sessionValid;
  let controlValid = true;
  if (config.native_broker?.enabled) {
    const [sessionResponse, controlResponse] = await Promise.all([
      brokerRequest({ operation: "native.session.validate", agent_id: identity.id, session: process.env.AGENTPASS_SESSION ?? null }, { native: config.native_broker }),
      brokerRequest({ operation: "native.control.validate", agent_id: identity.id }, { native: config.native_broker })
    ]);
    const sessionStatus = JSON.parse(Buffer.from(sessionResponse.stdout_base64, "base64").toString("utf8"));
    const controlStatus = JSON.parse(Buffer.from(controlResponse.stdout_base64, "base64").toString("utf8"));
    sessionValid = sessionStatus.valid === true;
    controlValid = controlStatus.valid === true;
  } else {
    sessionValid = isSessionValid(loadSession(process.env.AGENTPASS_SESSION), process.env.AGENTPASS_SESSION, identity.id);
  }
  const results = refs.map((line) => {
    const [, , remoteRef] = line.split(/\s+/);
    const isTag = remoteRef?.startsWith("refs/tags/");
    const operation = isTag ? "git.tag.push" : "git.push";
    const branch = (remoteRef ?? `refs/heads/${git(["branch", "--show-current"], true)}`).replace(/^refs\/(heads|tags)\//, "");
    const agentId = identity.id;
    const requestContext = { policy: { ...config, session: { ...config.session, valid: sessionValid } }, cwd: git(["rev-parse", "--show-toplevel"]), branch, remote: remoteUrl, operation, revoked: config.native_broker?.enabled ? !controlValid : state.revoked };
    const result = evaluateAgentRequest(requestContext, identity);
    audit({ operation, decision: result.allowed ? "allow" : "deny", reason: result.reason, branch, remote: remoteUrl }, defaultConfigDir);
    return { operation, branch, ...result };
  });
  console.log(JSON.stringify(results, null, 2));
  if (results.some((result) => !result.allowed)) process.exitCode = 1;
}

async function gitSign(signArgs = args) {
  const config = loadConfig();
  const { payloadPath, payload, brokerArgs } = readGitSigningInvocation(signArgs);
  const agentId = selectedAgent(config).id;
  const privatePath = path.join(defaultConfigDir, "agents", `${agentId}.pem`);
  const request = signRequest({
    operation: "git.commit.sign",
    cwd: process.cwd(),
    sign_args: brokerArgs,
    payload_base64: payload.toString("base64"),
    session: process.env.AGENTPASS_SESSION ?? null,
    agent_id: agentId,
    timestamp_ms: Date.now(),
    nonce: crypto.randomBytes(24).toString("base64url")
  }, privatePath);
  const response = await brokerRequest(request, { timeoutMs: 30000, native: config.native_broker });
  writeGitSignature(payloadPath, Buffer.from(response.stdout_base64, "base64"));
}

function selectedAgent(config) {
  const agentId = process.env.AGENTPASS_AGENT_ID ?? config.default_agent_id;
  const identity = config.agents?.find((agent) => agent.id === agentId);
  if (!identity) throw new Error("Selected agent identity is not enrolled");
  return identity;
}

async function brokerPing() {
  const config = loadConfig();
  const response = await brokerRequest({ operation: "ping" }, { native: config.native_broker });
  console.log(JSON.stringify(response, null, 2));
}

async function nativeManage() {
  const config = loadConfig();
  if (!config.native_broker?.enabled) throw new Error("Native broker is not configured");
  const action = args[0];
  if (["daemon-register", "daemon-unregister", "daemon-status", "daemon-open-settings"].includes(action)) {
    const manager = config.native_broker.manager ?? path.join(path.dirname(config.native_broker.client), "agentpass-native-manager");
    const stat = fs.lstatSync(manager);
    const currentUid = process.getuid?.();
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (currentUid !== undefined && stat.uid !== currentUid && stat.uid !== 0)) throw new Error("Native manager executable permissions are unsafe");
    const managerAction = { "daemon-register": "register", "daemon-unregister": "unregister", "daemon-status": "status", "daemon-open-settings": "open-settings" }[action];
    const result = spawnSync(manager, [managerAction], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    if (result.status !== 0) throw new Error(result.stderr.trim() || result.stdout.trim() || "Native service management failed");
    console.log(JSON.stringify(JSON.parse(result.stdout.trim()), null, 2));
  } else if (action === "status") {
    const health = await brokerRequest({ operation: "ping" }, { native: config.native_broker });
    const auditResult = await brokerRequest({ operation: "native.audit.status" }, { native: config.native_broker });
    console.log(JSON.stringify({ health, audit: JSON.parse(Buffer.from(auditResult.stdout_base64, "base64").toString("utf8")) }, null, 2));
  } else if (action === "public-key") {
    const result = await brokerRequest({ operation: "native.public-key" }, { native: config.native_broker });
    console.log(result.public_key);
  } else if (action === "audit-key") {
    const result = await brokerRequest({ operation: "native.audit.public-key" }, { native: config.native_broker });
    console.log(result.public_key);
  } else if (action === "checkpoint") {
    const result = await brokerRequest({ operation: "native.audit.checkpoint" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else if (action === "session-approval-key") {
    const result = await brokerRequest({ operation: "native.session.approval-public-key" }, { native: config.native_broker, timeoutMs: 30_000 });
    console.log(result.public_key);
  } else if (action === "revoke-sessions") {
    const result = await brokerRequest({ operation: "native.session.revoke" }, { native: config.native_broker });
    console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
  } else {
    throw new Error("Unknown native command");
  }
}

async function controlManage() {
  const action = args[0];
  if (action === "keygen") {
    if (!args[1]) throw new Error("Control key generation requires an output directory");
    console.log(JSON.stringify(generateControlKeyPair(path.resolve(args[1])), null, 2));
    return;
  }
  if (action === "sign") {
    const privateFile = requiredFlag("--key");
    const sequence = Number(requiredFlag("--sequence"));
    const expiresAt = requiredFlag("--expires");
    const revokedAgents = repeatedFlag("--revoke-agent");
    const bundle = signControlBundle({ sequence, expiresAt, globalRevoked: args.includes("--global-revoke"), revokedAgents }, path.resolve(privateFile));
    console.log(JSON.stringify(bundle, null, 2));
    return;
  }

  const config = loadConfig();
  const native = config.native_broker?.enabled === true;
  if (action === "source") {
    if (!native) throw new Error("Control source is only used by the native broker; local mode configures it with control trust --url");
    if (!args[1]) throw new Error("Control source requires an HTTPS URL");
    const url = new URL(args[1]);
    if (url.protocol !== "https:") throw new Error("Native control source must use HTTPS");
    saveConfig({ ...config, native_broker: { ...config.native_broker, control_url: url.toString() } });
    console.log(JSON.stringify({ url: url.toString(), trust: "root-owned native policy" }, null, 2));
  } else if (action === "trust") {
    if (native) throw new Error("Native control trust is defined only by the root-owned service policy; update it through the operator provisioning flow");
    if (!args[1]) throw new Error("Control trust requires a public key file");
    const publicKey = fs.readFileSync(path.resolve(args[1]), "utf8");
    const urlIndex = args.indexOf("--url");
    const refreshIndex = args.indexOf("--refresh");
    const url = urlIndex >= 0 ? args[urlIndex + 1] : undefined;
    const refreshSeconds = refreshIndex >= 0 ? Number(args[refreshIndex + 1]) : 60;
    const control = { required: true, public_key: publicKey };
    if (url) Object.assign(control, { url, refresh_seconds: refreshSeconds });
    const newFingerprint = controlKeyFingerprint(publicKey);
    const currentFingerprint = config.control?.public_key ? controlKeyFingerprint(config.control.public_key) : null;
    if (currentFingerprint && currentFingerprint !== newFingerprint && !(args.includes("--confirm") && args.includes("ROTATE_TRUST"))) throw new Error("Replacing the control trust root requires --confirm ROTATE_TRUST");
    saveConfig({ ...config, control });
    const existingBundle = controlBundlePath();
    if (currentFingerprint !== newFingerprint && fs.existsSync(existingBundle)) fs.renameSync(existingBundle, `${existingBundle}.${Date.now()}.untrusted.bak`);
    audit({ operation: "control.trust", decision: "allow", key_fingerprint: newFingerprint, previous_key_fingerprint: currentFingerprint, url: url ?? null }, defaultConfigDir);
    console.log(JSON.stringify({ fingerprint: newFingerprint, url: url ?? null }, null, 2));
    console.error("Install a signed control bundle, then restart the broker.");
  } else if (action === "apply") {
    if (!args[1]) throw new Error("Control apply requires a bundle file");
    const bundle = readJsonFile(path.resolve(args[1]), 256 * 1024);
    if (native) {
      const result = await brokerRequest({ operation: "native.control.apply", bundle }, { native: config.native_broker, timeoutMs: 30_000 });
      console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
      return;
    }
    const verified = applyControlBundle(bundle, config, defaultConfigDir);
    audit({ operation: "control.apply", decision: "allow", sequence: verified.sequence, expires_at: verified.expires_at, global_revoked: verified.global_revoked, revoked_agents: verified.revoked_agents }, defaultConfigDir);
    console.log(JSON.stringify(verified, null, 2));
  } else if (action === "fetch") {
    const sourceURL = native ? config.native_broker.control_url : config.control?.url;
    if (!sourceURL) throw new Error("No remote control HTTPS URL is configured");
    const bundle = await fetchControlBundle(sourceURL);
    if (native) {
      const result = await brokerRequest({ operation: "native.control.apply", bundle }, { native: config.native_broker, timeoutMs: 30_000 });
      console.log(JSON.stringify(JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8")), null, 2));
      return;
    }
    const verified = applyControlBundle(bundle, config, defaultConfigDir);
    audit({ operation: "control.fetch", decision: "allow", sequence: verified.sequence, expires_at: verified.expires_at }, defaultConfigDir);
    console.log(JSON.stringify(verified, null, 2));
  } else if (action === "status") {
    if (native) {
      const result = await brokerRequest({ operation: "native.control.status" }, { native: config.native_broker });
      const status = JSON.parse(Buffer.from(result.stdout_base64, "base64").toString("utf8"));
      console.log(JSON.stringify({ ...status, source_url: config.native_broker.control_url ?? null }, null, 2));
      return;
    }
    if (!config.control) {
      console.log(JSON.stringify({ configured: false }, null, 2));
      return;
    }
    const bundle = loadControlBundle(config, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, fingerprint: controlKeyFingerprint(config.control.public_key), url: config.control.url ?? null, bundle }, null, 2));
  } else {
    throw new Error("Unknown control command");
  }
}

function requiredFlag(flag) {
  const index = args.indexOf(flag);
  if (index < 0 || !args[index + 1]) throw new Error(`Missing required ${flag} value`);
  return args[index + 1];
}

function repeatedFlag(flag) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) if (args[index] === flag && args[index + 1]) values.push(args[index + 1]);
  return values;
}

function readJsonFile(file, maxBytes) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > maxBytes) throw new Error("JSON input must be a bounded regular file");
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error(`Invalid JSON file: ${file}`); }
}

function agentManage() {
  const action = args[0];
  if (action === "list") {
    const config = loadConfig();
    console.log(JSON.stringify(config.agents.map((agent) => ({ id: agent.id, name: agent.name, default: agent.id === config.default_agent_id, fingerprint: publicKeyFingerprint(agent.public_key), scope: agent.scope ?? null })), null, 2));
    return;
  }
  if (action === "add") {
    const identity = addAgent(args[1], defaultConfigDir);
    console.log(JSON.stringify({ id: identity.id, name: identity.name }, null, 2));
  } else if (action === "set-default") {
    setDefaultAgent(args[1], defaultConfigDir);
    console.log(`Default agent set to ${args[1]}.`);
  } else if (action === "scope") {
    const scope = parseAgentScope(args.slice(2));
    setAgentScope(args[1], scope, defaultConfigDir);
    console.log(JSON.stringify(scope, null, 2));
  } else if (action === "rotate") {
    const identity = rotateAgent(args[1], defaultConfigDir);
    console.log(JSON.stringify({ previous_id: args[1], id: identity.id, name: identity.name }, null, 2));
  } else if (action === "revoke") {
    if (args[2] !== "--confirm" || args[3] !== "REVOKE") throw new Error("Agent revocation requires: agentpass agent revoke ID --confirm REVOKE");
    revokeAgent(args[1], defaultConfigDir);
    console.log(`Agent ${args[1]} revoked.`);
  } else {
    throw new Error("Unknown agent command");
  }
  console.error("Broker configuration changed. Restart it before the next signing request.");
}

function parseAgentScope(values) {
  const flags = { "--operation": [], "--repository": [], "--branch": [], "--remote": [] };
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(flags, flag) || !value) throw new Error("Scope requires repeated --operation, --repository, --branch, and --remote pairs");
    flags[flag].push(value);
  }
  if (Object.values(flags).some((items) => items.length === 0)) throw new Error("Scope requires at least one operation, repository, branch, and remote");
  if (flags["--repository"].some((repository) => !path.isAbsolute(repository))) throw new Error("Scoped repositories must be absolute paths");
  return { operations: flags["--operation"], repositories: flags["--repository"], branches: { allow: flags["--branch"] }, remotes: { allow: flags["--remote"] } };
}

function scopeFromPolicy(config) {
  return {
    operations: [...(config.operations ?? ["git.commit.sign"])],
    repositories: [...config.repositories],
    branches: structuredClone(Array.isArray(config.branches?.allow) ? config.branches : { allow: ["*"] }),
    remotes: structuredClone(Array.isArray(config.remotes?.allow) ? config.remotes : { allow: ["*"] })
  };
}

async function auditCommand() {
  const config = loadConfig();
  if (args[0] === "checkpoint") {
    const checkpoint = createAuditCheckpoint(config.audit_signing.public_key, defaultConfigDir);
    console.log(JSON.stringify(checkpoint, null, 2));
  } else if (args[0] === "public-key") {
    console.error(publicKeyFingerprint(config.audit_signing.public_key));
    console.log(config.audit_signing.public_key.trim());
  } else if (args[0] === "anchor") {
    await auditAnchorCommand(config);
  } else if (args.includes("--verify")) {
    const chain = verifyAudit(defaultConfigDir);
    const checkpoints = verifyAuditCheckpoints(config.audit_signing.public_key, defaultConfigDir);
    let anchor;
    try { anchor = verifyStoredAnchorReceipts(config, defaultConfigDir); }
    catch (error) { anchor = { valid: false, error: error.message }; }
    console.log(JSON.stringify({ valid: chain.valid && checkpoints.valid && anchor.valid, audit: chain, checkpoints, anchor }, null, 2));
    if (!chain.valid || !checkpoints.valid || !anchor.valid) process.exitCode = 1;
  } else {
    console.log(fs.existsSync(auditPath()) ? fs.readFileSync(auditPath(), "utf8") : "");
  }
}

async function auditAnchorCommand(config) {
  const action = args[1];
  if (action === "trust") {
    const url = requiredFlag("--url");
    const tenant = requiredFlag("--tenant");
    const publicKey = fs.readFileSync(path.resolve(requiredFlag("--key")), "utf8");
    const fingerprint = publicKeyFingerprint(publicKey);
    const previousFingerprint = config.audit_anchor?.public_key ? publicKeyFingerprint(config.audit_anchor.public_key) : null;
    const identityChanged = config.audit_anchor && (previousFingerprint !== fingerprint || config.audit_anchor.tenant !== tenant);
    if (identityChanged && !(args.includes("--confirm") && args.includes("ROTATE_ANCHOR_TRUST"))) {
      throw new Error("Replacing the audit anchor trust root requires --confirm ROTATE_ANCHOR_TRUST");
    }
    saveConfig({ ...config, audit_anchor: { url, tenant, public_key: publicKey } });
    const receiptFile = anchorReceiptPath();
    if (identityChanged && fs.existsSync(receiptFile)) fs.renameSync(receiptFile, `${receiptFile}.${Date.now()}.untrusted.bak`);
    audit({ operation: "audit.anchor.trust", decision: "allow", tenant, url, key_fingerprint: fingerprint, previous_key_fingerprint: previousFingerprint }, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, tenant, url, fingerprint }, null, 2));
  } else if (action === "push") {
    if (!config.audit_anchor) throw new Error("No audit anchor is configured");
    audit({ operation: "audit.anchor.push", decision: "allow", tenant: config.audit_anchor.tenant, url: config.audit_anchor.url }, defaultConfigDir);
    createAuditCheckpoint(config.audit_signing.public_key, defaultConfigDir);
    console.log(JSON.stringify(await anchorPendingCheckpoints(config, defaultConfigDir), null, 2));
  } else if (action === "status") {
    if (!config.audit_anchor) {
      console.log(JSON.stringify({ configured: false }, null, 2));
      return;
    }
    const receipts = verifyStoredAnchorReceipts(config, defaultConfigDir);
    console.log(JSON.stringify({ configured: true, tenant: config.audit_anchor.tenant, url: config.audit_anchor.url, fingerprint: publicKeyFingerprint(config.audit_anchor.public_key), ...receipts }, null, 2));
  } else {
    throw new Error("Unknown audit anchor command");
  }
}

function brokerInstall() {
  if (process.platform !== "darwin") throw new Error("LaunchAgent installation is supported only on macOS");
  const launchAgents = path.join(os.homedir(), "Library", "LaunchAgents");
  const plist = path.join(launchAgents, "dev.agentpass.broker.plist");
  if (fs.existsSync(plist) && !args.includes("--force")) throw new Error(`${plist} exists; use --force to replace it`);
  fs.mkdirSync(launchAgents, { recursive: true, mode: 0o700 });
  const daemon = fileURLToPath(new URL("./agentpassd.mjs", import.meta.url));
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.agentpass.broker</string>
  <key>ProgramArguments</key><array><string>${xmlEscape(process.execPath)}</string><string>${xmlEscape(daemon)}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>${xmlEscape(path.join(defaultConfigDir, "broker.out.log"))}</string>
  <key>StandardErrorPath</key><string>${xmlEscape(path.join(defaultConfigDir, "broker.err.log"))}</string>
</dict></plist>
`;
  const domain = `gui/${process.getuid()}`;
  if (args.includes("--force")) spawnSync("/bin/launchctl", ["bootout", `${domain}/dev.agentpass.broker`], { encoding: "utf8" });
  fs.writeFileSync(plist, xml, { mode: 0o600 });
  const result = spawnSync("/bin/launchctl", ["bootstrap", domain, plist], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "launchctl bootstrap failed");
  console.log(`Installed ${plist}`);
}

function brokerStop() {
  if (process.platform !== "darwin") throw new Error("LaunchAgent control is supported only on macOS");
  const result = spawnSync("/bin/launchctl", ["bootout", `gui/${process.getuid()}/dev.agentpass.broker`], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "launchctl bootout failed");
  console.log("AgentPass broker stopped.");
}

function xmlEscape(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}

try {
  if (command === "init") init();
  else if (command === "migrate") migrate();
  else if (command === "check") check();
  else if (command === "status") status();
  else if (command === "doctor") doctor();
  else if (command === "broker" && args[0] === "ping") await brokerPing();
  else if (command === "broker" && args[0] === "install") brokerInstall();
  else if (command === "broker" && args[0] === "stop") brokerStop();
  else if (command === "native") await nativeManage();
  else if (command === "agent") agentManage();
  else if (command === "control") await controlManage();
  else if (command === "setup-macos") setupMacos();
  else if (command === "install-hook") installHook();
  else if (command === "push-check") await pushCheck();
  else if (command === "session" && args[0] === "start") await sessionStart();
  else if (command === "revoke") revoke();
  else if (command === "restore") restore();
  else if (command === "git-sign") await gitSign();
  else if (command === "-Y") await gitSign([command, ...args]);
  else if (command === "audit") await auditCommand();
  else usage();
} catch (error) {
  console.error(`agentpass: ${error.message}`);
  process.exitCode = 1;
}
