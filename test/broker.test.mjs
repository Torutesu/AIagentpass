import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import { brokerRequest } from "../lib/broker-client.mjs";
import { createBroker, processRequest, sanitizeSignArgs, validateCommitPayload } from "../lib/broker.mjs";
import { loadConfig, saveConfig, saveSession, saveState } from "../lib/config.mjs";
import { createAgentIdentity, createAuditIdentity, signRequest } from "../lib/identity.mjs";
import { applyControlBundle, generateControlKeyPair, signControlBundle } from "../lib/remote-control.mjs";
import { applyControlBundle as applyControlBundleV2, issueControlBundle } from "../lib/control-bundle-v2.mjs";
import { issueCapability } from "../packages/capability/src/index.mjs";

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
    request_id: crypto.randomUUID(),
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
  const auditRotate = await brokerRequest({ operation: "native.audit.rotate" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(auditRotate.command, "audit-rotate");
  const evidenceRotate = await brokerRequest({ operation: "native.audit.evidence.rotate" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(evidenceRotate.command, "audit-evidence-rotate");
  const lifecycleStatus = await brokerRequest({ operation: "native.key-lifecycle.status" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(lifecycleStatus.command, "key-lifecycle-status");
  const keyStage = await brokerRequest({ operation: "native.key.stage", role: "git_signing" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(keyStage.command, "key-stage");
  const keyActivate = await brokerRequest({ operation: "native.key.activate", role: "git_signing", generation: 2, reason: "test" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(keyActivate.command, "key-activate");
  const keyDelete = await brokerRequest({ operation: "native.key.delete", role: "git_signing", generation: 1, reason: "retained", minimum_retention_seconds: 2592000, proof: { version: 1 } }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(keyDelete.command, "key-delete");
  const recoveryRequest = await brokerRequest({ operation: "native.recovery.request", role: "git_signing" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(recoveryRequest.command, "recovery-request");
  const recoveryPrepare = await brokerRequest({ operation: "native.recovery.prepare", evidence_base64: "e30=" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(recoveryPrepare.command, "recovery-prepare");
  const recoveryInstall = await brokerRequest({ operation: "native.recovery.install", evidence_base64: "e30=" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(recoveryInstall.command, "recovery-install");
  const anchorRecoveryInstall = await brokerRequest({ operation: "native.recovery.anchor.install", evidence_base64: "e30=" }, { native: { enabled: true, client, mach_service: "dev.agentpass.native" } });
  assert.equal(anchorRecoveryInstall.command, "recovery-anchor-install");
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

test("native recovery and prune bridge pins protocol 13 and dedicated management routes", () => {
  const clientSource = fs.readFileSync(path.resolve(import.meta.dirname, "../native/macos/Sources/AgentPassNativeClient/main.swift"), "utf8");
  const serviceSource = fs.readFileSync(path.resolve(import.meta.dirname, "../native/macos/Sources/AgentPassNativeService/main.swift"), "utf8");
  const protocolSource = fs.readFileSync(path.resolve(import.meta.dirname, "../native/macos/Sources/AgentPassNativeCore/XPCProtocol.swift"), "utf8");
  assert.match(clientSource, /"audit-prune-submit"/);
  assert.match(clientSource, /"audit-prune-execute"/);
  assert.match(clientSource, /"control-refresh"/);
  assert.match(clientSource, /extendedTimeoutCommands\.contains\(command\) \? 120 : 30/);
  assert.match(clientSource, /case "audit-recovery-abort-expired":/);
  assert.match(clientSource, /case "audit-recovery-status":/);
  assert.match(clientSource, /Native service protocol 13 is required/);
  assert.match(serviceSource, /"protocol_version": 13, "key_backend": "secure-enclave"/);
  assert.match(protocolSource, /func abortExpiredAuditRecovery\(withReply/);
  assert.match(protocolSource, /func auditRecoveryStatus\(withReply/);
  assert.match(serviceSource, /abortExpiredUnsubmittedPending\(nowMilliseconds: nowMilliseconds\)/);
  assert.match(serviceSource, /preparedRecordVerifier: keyLifecycle/);
  assert.match(serviceSource, /lifecycleAncestryVerifier: keyLifecycle/);
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

test("broker returns an idempotent completed request but rejects nonce reuse under another request ID", async () => {
  const data = fixture();
  const replayCache = new Map();
  const request = signedRequest(data);
  const signer = async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" });
  const first = await processRequest(request, signer, data.configDir, null, replayCache);
  const retry = await processRequest(request, signer, data.configDir, null, replayCache);
  assert.equal(retry.replayed, true);
  assert.equal(retry.stdout_base64, first.stdout_base64);
  const nonceReuse = signedRequest(data, { request_id: crypto.randomUUID(), nonce: request.nonce });
  await assert.rejects(processRequest(nonceReuse, signer, data.configDir, null, replayCache), /replay/);
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

test("commit parser rejects duplicate required headers, existing signatures, continuations, NUL, and CRLF", () => {
  const data = fixture();
  const tree = execFileSync("git", ["-C", data.repo, "write-tree"], { encoding: "utf8" }).trim();
  const base = `tree ${tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000`;
  assert.throws(() => validateCommitPayload(Buffer.from(`tree ${tree}\n${base}\n\nmessage\n`), data.repo), /exactly one tree/);
  assert.throws(() => validateCommitPayload(Buffer.from(`${base}\ngpgsig forged\n\nmessage\n`), data.repo), /already contains a signature/);
  assert.throws(() => validateCommitPayload(Buffer.from(`${base}\n continued\n\nmessage\n`), data.repo), /continued header/);
  assert.throws(() => validateCommitPayload(Buffer.from(`${base}\n\nmessage\0hidden\n`), data.repo), /NUL/);
  assert.throws(() => validateCommitPayload(Buffer.from(`${base}\r\n\r\nmessage\r\n`), data.repo), /carriage return/);
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

test("broker intersects ControlBundle v2 and a one-shot short-lived capability", async () => {
  const data = fixture();
  const keys = crypto.generateKeyPairSync("ed25519");
  const organizationId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const statePath = path.join(data.configDir, "control-v2.state.json");
  const now = Date.now();
  const scope = {
    operations: ["git.commit.sign"], repositories: [fs.realpathSync(data.repo)],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@github.com:example/project.git"], deny: [] }
  };
  const bundle = issueControlBundle({
    format_epoch: 2, issuer: "agentpass-cloud", organization_id: organizationId, device_id: deviceId,
    audience: { organization_id: organizationId, device_id: deviceId }, issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 60_000).toISOString(), sequence: 1, policy_scope: scope, global_revoked: false,
    revoked_devices: [], revoked_agents: [], revoked_capabilities: [], offline_ttl_ms: 60_000, key_id: "control-v2"
  }, keys.privateKey, { now, maxTtlMs: 60_000, maxOfflineTtlMs: 60_000 });
  const trust = { public_key: keys.publicKey, issuer: "agentpass-cloud", key_id: "control-v2", audience: { organization_id: organizationId, device_id: deviceId } };
  applyControlBundleV2(bundle, trust, statePath, { now, audience: trust.audience });
  const config = loadConfig(data.configDir);
  config.control_v2 = { required: true, capability_required: true, public_key: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), issuer: "agentpass-cloud", key_id: "control-v2", organization_id: organizationId, device_id: deviceId, state_path: statePath };
  saveConfig(config, data.configDir);
  const capability = issueCapability({ issuer: "agentpass-cloud", key_id: "control-v2", audience: { agent_id: data.identity.id, device_id: deviceId }, scope, sequence: 1, ttl_ms: 60_000 }, keys.privateKey, { now, ttlMs: 60_000 });
  const cache = { highestSequence: 0, bundle: null, capabilitySequence: {}, consumedCapabilities: new Set() };
  const signer = async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" });
  const result = await processRequest(signedRequest(data, { capability }), signer, data.configDir, null, new Map(), cache);
  assert.equal(result.ok, true);
  assert.equal(fs.statSync(path.join(data.configDir, "capability.state.json")).mode & 0o777, 0o600);
  const revokedCapabilityId = crypto.randomUUID();
  const revokedBundle = issueControlBundle({
    ...Object.fromEntries(Object.entries(bundle).filter(([key]) => key !== "signature")), sequence: 2,
    revoked_capabilities: [revokedCapabilityId]
  }, keys.privateKey, { now, maxTtlMs: 60_000, maxOfflineTtlMs: 60_000 });
  applyControlBundleV2(revokedBundle, trust, statePath, { now, audience: trust.audience });
  const revokedCapability = issueCapability({ capability_id: revokedCapabilityId, issuer: "agentpass-cloud", key_id: "control-v2", audience: { agent_id: data.identity.id, device_id: deviceId }, scope, sequence: 2, ttl_ms: 60_000 }, keys.privateKey, { now, ttlMs: 60_000 });
  await assert.rejects(processRequest(signedRequest(data, { capability: revokedCapability }), signer, data.configDir, null, new Map(), cache), /capability_revoked/);
  const restartedCache = { highestSequence: 0, bundle: null, capabilitySequence: {}, consumedCapabilities: new Set() };
  await assert.rejects(processRequest(signedRequest(data, { capability }), signer, data.configDir, null, new Map(), restartedCache), /already been consumed/);
});

test("non-native broker synchronizes authenticated ControlBundle v2 before every signature", async () => {
  const data = fixture();
  const controlKeys = crypto.generateKeyPairSync("ed25519");
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const organizationId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const now = Date.now();
  const statePath = path.join(data.configDir, "online-control-v2.state.json");
  const deviceKeyPath = path.join(data.configDir, "device-auth.pem");
  fs.writeFileSync(deviceKeyPath, deviceKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const scope = { operations: ["git.commit.sign"], repositories: [fs.realpathSync(data.repo)], branches: { allow: ["feature/*"], deny: ["main"] }, remotes: { allow: ["git@github.com:example/project.git"], deny: [] } };
  const bundle = issueControlBundle({ format_epoch: 2, issuer: "agentpass-cloud", organization_id: organizationId, device_id: deviceId, audience: { organization_id: organizationId, device_id: deviceId }, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 60_000).toISOString(), sequence: 1, policy_scope: scope, global_revoked: false, revoked_devices: [], revoked_agents: [], revoked_capabilities: [], offline_ttl_ms: 60_000, key_id: "control-v2" }, controlKeys.privateKey, { now, maxTtlMs: 60_000, maxOfflineTtlMs: 60_000 });
  const config = loadConfig(data.configDir);
  config.control_v2 = { required: true, capability_required: true, public_key: controlKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), issuer: "agentpass-cloud", key_id: "control-v2", organization_id: organizationId, device_id: deviceId, state_path: statePath, url: `https://cloud.example.test/v1/organizations/${organizationId}/bundles/${deviceId}`, refresh_seconds: 15, device_private_key_path: deviceKeyPath };
  saveConfig(config, data.configDir);
  const capability = issueCapability({ issuer: "agentpass-cloud", key_id: "control-v2", audience: { agent_id: data.identity.id, device_id: deviceId }, scope, sequence: 1, ttl_ms: 60_000 }, controlKeys.privateKey, { now, ttlMs: 60_000 });
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async (_url, options) => {
    fetches += 1;
    assert.match(options.headers["AgentPass-Signature"], /^[A-Za-z0-9+/]+=*$/);
    assert.equal(options.headers["AgentPass-Device"], deviceId);
    return new Response(JSON.stringify({ bundle, request_id: crypto.randomUUID() }), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const result = await processRequest(signedRequest(data, { capability }), async () => ({ status: 0, stdout: Buffer.from("signature"), stderr: "" }), data.configDir);
    assert.equal(result.ok, true);
    assert.equal(fetches, 1);
    assert.equal(fs.existsSync(statePath), true);
  } finally { globalThis.fetch = originalFetch; }
});

test("completed request_id replay is bound to the exact signed envelope", async () => {
  const data = fixture();
  const request = signedRequest(data);
  let calls = 0;
  const signer = async () => { calls += 1; return { status: 0, stdout: Buffer.from("signature"), stderr: "" }; };
  await processRequest(request, signer, data.configDir);
  const exactRetry = await processRequest(request, signer, data.configDir);
  assert.equal(exactRetry.replayed, true);
  const substituted = signedRequest(data, { request_id: request.request_id });
  await assert.rejects(processRequest(substituted, signer, data.configDir), /request_id_reuse/);
  assert.equal(calls, 1);
});
