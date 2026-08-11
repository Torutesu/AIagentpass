import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import { brokerRequest } from "../lib/broker-client.mjs";
import { createBroker, processRequest, sanitizeSignArgs } from "../lib/broker.mjs";
import { loadConfig, saveConfig, saveSession, saveState } from "../lib/config.mjs";
import { createAgentIdentity, createAuditIdentity, signRequest } from "../lib/identity.mjs";
import { applyControlBundle, generateControlKeyPair, signControlBundle } from "../lib/remote-control.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-broker-"));
  const repo = path.join(root, "repo");
  const configDir = path.join(root, "config");
  fs.mkdirSync(repo);
  execFileSync("git", ["-C", repo, "init", "-b", "main"]);
  execFileSync("git", ["-C", repo, "switch", "-c", "feature/broker"]);
  execFileSync("git", ["-C", repo, "remote", "add", "origin", "git@github.com:example/project.git"]);
  fs.writeFileSync(path.join(repo, "file.txt"), "content\n");
  execFileSync("git", ["-C", repo, "add", "file.txt"]);
  const tree = execFileSync("git", ["-C", repo, "write-tree"], { encoding: "utf8" }).trim();
  const payload = Buffer.from(`tree ${tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nTest commit\n`);
  const key = path.join(root, "id_git_sign");
  const identity = createAgentIdentity(configDir, "test-agent");
  const auditIdentity = createAuditIdentity(configDir);
  saveConfig({
    version: 4,
    agent: { name: "test-agent" },
    agents: [{ id: identity.id, name: identity.name, public_key: identity.public_key, scope: { operations: ["git.commit.sign"], repositories: [repo], branches: { allow: ["feature/*"], deny: ["main"] }, remotes: { allow: ["git@github.com:example/project.git"] } } }],
    default_agent_id: identity.id,
    operations: ["git.commit.sign"],
    repositories: [repo],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@github.com:example/project.git"] },
    signing: { key, provider: "/test/provider" },
    audit_signing: { public_key: auditIdentity.public_key },
    session: { required: false, ttl_seconds: 300 }
  }, configDir);
  saveState({ revoked: false, generation: 0 }, configDir);
  return { root, repo, configDir, key, identity, payload };
}

function signedRequest(fixtureData, overrides = {}) {
  return signRequest({
    operation: "git.commit.sign",
    cwd: fixtureData.repo,
    sign_args: ["-Y", "sign", "-n", "git", "-f", "/tmp/attacker-key"],
    payload_base64: fixtureData.payload.toString("base64"),
    session: null,
    agent_id: fixtureData.identity.id,
    timestamp_ms: Date.now(),
    nonce: crypto.randomBytes(24).toString("base64url"),
    ...overrides
  }, fixtureData.identity.private_path);
}

test("broker replaces caller key and signs an allowed Git payload", async () => {
  const data = fixture();
  const { configDir, key } = data;
  let signerRequest;
  const signer = async (request) => {
    signerRequest = request;
    return { status: 0, stdout: Buffer.from("signature"), stderr: "" };
  };
  const result = await processRequest(signedRequest(data), signer, configDir);
  assert.equal(Buffer.from(result.stdout_base64, "base64").toString(), "signature");
  assert.deepEqual(signerRequest.args, ["-Y", "sign", "-n", "git", "-f", key]);
});

test("broker rejects unsupported ssh-keygen arguments", () => {
  assert.throws(() => sanitizeSignArgs(["-Y", "sign", "-n", "git", "-f", "/tmp/key", "-I", "escape"], "/tmp/configured"), /Unsupported/);
});

test("broker denies a protected branch", async () => {
  const data = fixture();
  const { repo, configDir } = data;
  execFileSync("git", ["-C", repo, "branch", "-m", "main"]);
  await assert.rejects(processRequest(signedRequest(data), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), configDir), /branch_denied/);
});

test("Unix socket client and broker exchange one bounded request", async () => {
  const data = fixture();
  const { root, configDir } = data;
  const socket = path.join(root, "broker.sock");
  const server = createBroker({
    socket,
    configDir,
    signer: async () => ({ status: 0, stdout: Buffer.from("socket-signature"), stderr: "" })
  });
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const result = await brokerRequest(signedRequest(data), { socket });
    assert.equal(Buffer.from(result.stdout_base64, "base64").toString(), "socket-signature");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("broker client routes signed requests through the native bridge", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-bridge-"));
  const client = path.join(root, "native-client.mjs");
  fs.writeFileSync(client, `#!${process.execPath}
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => input += chunk);
process.stdin.on("end", () => {
  const request = JSON.parse(input);
  process.stdout.write(JSON.stringify({ ok: true, stdout_base64: Buffer.from(request.operation).toString("base64"), command: process.argv.at(-1) }) + "\\n");
});
`, { mode: 0o755 });
  const result = await brokerRequest({ operation: "git.commit.sign" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(Buffer.from(result.stdout_base64, "base64").toString(), "git.commit.sign");
  assert.equal(result.command, "sign");
  const auditStatus = await brokerRequest({ operation: "native.audit.status" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(auditStatus.command, "audit-status");
  const anchorPush = await brokerRequest({ operation: "native.audit.anchor.push" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(anchorPush.command, "audit-anchor-push");
  const anchorStatus = await brokerRequest({ operation: "native.audit.anchor.status" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(anchorStatus.command, "audit-anchor-status");
  const nativeSession = await brokerRequest({ operation: "native.session.start", agent_id: "agent", ttl_seconds: 300 }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(nativeSession.command, "session-start");
  const revokeSessions = await brokerRequest({ operation: "native.session.revoke" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(revokeSessions.command, "session-revoke");
  const validateSession = await brokerRequest({ operation: "native.session.validate", agent_id: "agent", session: "token" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(validateSession.command, "session-validate");
  const applyControl = await brokerRequest({ operation: "native.control.apply", bundle: { version: 1 } }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(applyControl.command, "control-apply");
  const controlStatus = await brokerRequest({ operation: "native.control.status" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(controlStatus.command, "control-status");
  const validateControl = await brokerRequest({ operation: "native.control.validate", agent_id: "agent" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(validateControl.command, "control-validate");
  fs.chmodSync(client, 0o777);
  assert.throws(() => brokerRequest({ operation: "ping" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } }), /permissions are unsafe/);
});

test("running broker fails closed after configuration mutation", async () => {
  const data = fixture();
  const { root, configDir } = data;
  const socket = path.join(root, "broker.sock");
  const server = createBroker({ socket, configDir, signer: async () => ({ status: 0, stdout: Buffer.from("unexpected"), stderr: "" }) });
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const changed = loadConfig(configDir);
    changed.operations.push("git.push");
    saveConfig(changed, configDir);
    await assert.rejects(brokerRequest(signedRequest(data), { socket }), /configuration changed/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("broker rejects replayed signed agent requests", async () => {
  const data = fixture();
  const replayCache = new Map();
  const request = signedRequest(data);
  const signer = async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" });
  await processRequest(request, signer, data.configDir, null, replayCache);
  await assert.rejects(processRequest(request, signer, data.configDir, null, replayCache), /replay/);
});

test("broker rejects a commit payload whose tree is not the current index", async () => {
  const data = fixture();
  const forged = Buffer.from(`tree ${"0".repeat(40)}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nForged\n`);
  await assert.rejects(processRequest(signedRequest(data, { payload_base64: forged.toString("base64") }), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), data.configDir), /tree does not match/);
});

test("broker rejects malformed base64 payloads", async () => {
  const data = fixture();
  await assert.rejects(processRequest(signedRequest(data, { payload_base64: "not base64!!!" }), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), data.configDir), /valid base64/);
});

test("a second broker cannot replace a live broker socket", async () => {
  const data = fixture();
  const socket = path.join(data.root, "broker.sock");
  const server = createBroker({ socket, configDir: data.configDir, signer: async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" }) });
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    assert.throws(() => createBroker({ socket, configDir: data.configDir }), /already running/);
    assert.equal(fs.existsSync(socket), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("broker allows merge parents only when they exactly match HEAD and MERGE_HEAD", async () => {
  const data = fixture();
  const env = { ...process.env, GIT_AUTHOR_NAME: "Test", GIT_AUTHOR_EMAIL: "test@example.com", GIT_COMMITTER_NAME: "Test", GIT_COMMITTER_EMAIL: "test@example.com" };
  execFileSync("git", ["-C", data.repo, "commit", "-m", "base"], { env });
  const head = execFileSync("git", ["-C", data.repo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["-C", data.repo, "write-tree"], { encoding: "utf8" }).trim();
  const mergeHead = execFileSync("git", ["-C", data.repo, "commit-tree", tree, "-m", "side"], { encoding: "utf8", env }).trim();
  const mergeHeadPath = execFileSync("git", ["-C", data.repo, "rev-parse", "--git-path", "MERGE_HEAD"], { encoding: "utf8" }).trim();
  fs.writeFileSync(path.isAbsolute(mergeHeadPath) ? mergeHeadPath : path.resolve(data.repo, mergeHeadPath), `${mergeHead}\n`);
  data.payload = Buffer.from(`tree ${tree}\nparent ${head}\nparent ${mergeHead}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nMerge\n`);
  const signer = async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" });
  await processRequest(signedRequest(data), signer, data.configDir);

  data.payload = Buffer.from(`tree ${tree}\nparent ${head}\nparent ${"0".repeat(40)}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nForged merge\n`);
  await assert.rejects(processRequest(signedRequest(data), signer, data.configDir), /parents do not match/);
});

test("broker enforces an agent scope in addition to global policy", async () => {
  const data = fixture();
  const config = loadConfig(data.configDir);
  config.agents[0].scope = {
    operations: ["git.commit.sign"],
    repositories: [data.repo],
    branches: { allow: ["fix/*"] },
    remotes: { allow: ["git@github.com:example/project.git"] }
  };
  saveConfig(config, data.configDir);
  await assert.rejects(processRequest(signedRequest(data), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), data.configDir), /agent_scope_branch_not_allowed/);
});

test("short-lived sessions are bound to one agent identity", async () => {
  const data = fixture();
  const config = loadConfig(data.configDir);
  config.session.required = true;
  saveConfig(config, data.configDir);
  const wrongToken = crypto.randomBytes(32).toString("base64url");
  saveSession({ token_hash: crypto.createHash("sha256").update(wrongToken).digest("hex"), expires_at: new Date(Date.now() + 60_000).toISOString(), generation: 0, agent_id: crypto.randomUUID() }, data.configDir);
  const signer = async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" });
  await assert.rejects(processRequest(signedRequest(data, { session: wrongToken }), signer, data.configDir), /session_required/);

  const matchingToken = crypto.randomBytes(32).toString("base64url");
  saveSession({ token_hash: crypto.createHash("sha256").update(matchingToken).digest("hex"), expires_at: new Date(Date.now() + 60_000).toISOString(), generation: 0, agent_id: data.identity.id }, data.configDir);
  const result = await processRequest(signedRequest(data, { session: matchingToken }), signer, data.configDir);
  assert.equal(result.ok, true);
});

test("broker refuses pre-v4 configuration instead of bypassing agent scopes", async () => {
  const data = fixture();
  const config = loadConfig(data.configDir);
  config.version = 3;
  delete config.audit_signing;
  saveConfig(config, data.configDir);
  await assert.rejects(processRequest(signedRequest(data), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), data.configDir), /version 4 is required/);
});

test("broker enforces an offline-signed remote agent revocation", async () => {
  const data = fixture();
  const keys = generateControlKeyPair(path.join(data.root, "control-keys"));
  const config = loadConfig(data.configDir);
  config.control = { required: true, public_key: fs.readFileSync(keys.public_file, "utf8") };
  saveConfig(config, data.configDir);
  const bundle = signControlBundle({ sequence: 1, expiresAt: Date.now() + 60_000, revokedAgents: [data.identity.id] }, keys.private_file);
  applyControlBundle(bundle, config, data.configDir);
  await assert.rejects(processRequest(signedRequest(data), async () => ({ status: 0, stdout: Buffer.from("bad"), stderr: "" }), data.configDir), /remote_agent_revoked/);
});

test("broker refuses to start when required remote control state is missing", () => {
  const data = fixture();
  const keys = generateControlKeyPair(path.join(data.root, "missing-control-keys"));
  const config = loadConfig(data.configDir);
  config.control = { required: true, public_key: fs.readFileSync(keys.public_file, "utf8") };
  saveConfig(config, data.configDir);
  assert.throws(() => createBroker({ socket: path.join(data.root, "missing-control.sock"), configDir: data.configDir }), /bundle is missing/);
});
