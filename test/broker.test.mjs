import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import { brokerRequest } from "../lib/broker-client.mjs";
import { createBroker, processRequest, sanitizeSignArgs } from "../lib/broker.mjs";
import { loadConfig, saveConfig, saveState } from "../lib/config.mjs";
import { createAgentIdentity, signRequest } from "../lib/identity.mjs";

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
  saveConfig({
    version: 3,
    agent: { name: "test-agent" },
    agents: [{ id: identity.id, name: identity.name, public_key: identity.public_key }],
    default_agent_id: identity.id,
    operations: ["git.commit.sign"],
    repositories: [repo],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@github.com:example/project.git"] },
    signing: { key, provider: "/test/provider" },
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
