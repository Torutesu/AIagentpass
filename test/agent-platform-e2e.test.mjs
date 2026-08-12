import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";

import { createApiTokenRecord, generateApiToken } from "../apps/cloud-api/src/auth.mjs";
import { createCloudApi } from "../apps/cloud-api/src/server.mjs";
import { createCloudStore } from "../apps/cloud-api/src/store.mjs";
import { processRequest } from "../lib/broker.mjs";
import { createCloudControlClient } from "../lib/cloud-control.mjs";
import { saveConfig, saveState } from "../lib/config.mjs";
import { createAgentIdentity, createAuditIdentity, signRequest } from "../lib/identity.mjs";

test("cloud policy, capability, signing, and emergency stop work end to end", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-platform-e2e-"));
  const cloudDir = path.join(root, "cloud");
  const configDir = path.join(root, "config");
  const repo = path.join(root, "repo");
  fs.mkdirSync(cloudDir, { mode: 0o700 });
  fs.mkdirSync(repo);
  execFileSync("git", ["-C", repo, "init", "-b", "main"]);
  execFileSync("git", ["-C", repo, "switch", "-c", "feature/e2e"]);
  execFileSync("git", ["-C", repo, "remote", "add", "origin", "git@github.com:example/platform.git"]);
  fs.writeFileSync(path.join(repo, "file.txt"), "agentpass\n");
  execFileSync("git", ["-C", repo, "add", "file.txt"]);
  const tree = execFileSync("git", ["-C", repo, "write-tree"], { encoding: "utf8" }).trim();
  const payload = Buffer.from(`tree ${tree}\nauthor Agent <agent@example.com> 0 +0000\ncommitter Agent <agent@example.com> 0 +0000\n\nE2E\n`);

  const organizationId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const ownerId = crypto.randomUUID();
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const controlKeys = crypto.generateKeyPairSync("ed25519");
  const identity = createAgentIdentity(configDir, "claude-code-e2e");
  const auditIdentity = createAuditIdentity(configDir);
  const scope = {
    operations: ["git.commit.sign"],
    repositories: [fs.realpathSync(repo)],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@github.com:example/platform.git"], deny: [] }
  };

  const store = await createCloudStore({ dataDir: cloudDir });
  t.after(async () => { await store.close(); fs.rmSync(root, { recursive: true, force: true }); });
  await store.createOrganization({ organizationId, name: "AgentPass E2E", idempotencyKey: "org" });
  await store.createDevice({ organizationId, deviceId, name: "Secure Enclave Mac", publicKey: deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), idempotencyKey: "device" });
  await store.createAgent({ organizationId, deviceId, version: 1, agentId: identity.id, name: "Claude Code", kind: "claude-code", publicKey: identity.public_key, createdAt: new Date().toISOString(), idempotencyKey: "agent" });
  await store.createPolicy({ organizationId, name: "Default", scope, sequence: 1, idempotencyKey: "policy" });
  const token = generateApiToken();
  const tokenRecord = createApiTokenRecord({ token, organizationId, memberId: ownerId, role: "owner" });
  const server = createCloudApi({ store, tokenRecords: [tokenRecord], bundleSigner: { privateKey: controlKeys.privateKey, issuer: "agentpass-cloud", keyId: "control-v2", ttlMs: 60_000, offlineTtlMs: 60_000 } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const statePath = path.join(configDir, "control-v2.state.json");
  const cloud = createCloudControlClient({ baseUrl, organizationId, deviceId, issuer: "agentpass-cloud", keyId: "control-v2", publicKey: controlKeys.publicKey, privateKey: deviceKeys.privateKey, statePath, loopbackTestMode: true });
  assert.equal((await cloud.sync()).sequence, 1);

  saveConfig({
    version: 4,
    agents: [{ id: identity.id, name: identity.name, public_key: identity.public_key, scope }],
    default_agent_id: identity.id,
    operations: scope.operations,
    repositories: scope.repositories,
    branches: scope.branches,
    remotes: scope.remotes,
    signing: { key: path.join(root, "git-signing-key"), provider: "/test/provider" },
    audit_signing: { public_key: auditIdentity.public_key },
    session: { required: false, ttl_seconds: 300 },
    control_v2: { required: true, capability_required: true, public_key: controlKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), issuer: "agentpass-cloud", key_id: "control-v2", organization_id: organizationId, device_id: deviceId, state_path: statePath }
  }, configDir);
  saveState({ revoked: false, generation: 0 }, configDir);

  async function issueCapability(sequence, idempotencyKey) {
    const response = await fetch(`${baseUrl}/v1/organizations/${organizationId}/capabilities`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": idempotencyKey },
      body: JSON.stringify({ agent_id: identity.id, device_id: deviceId, scope, ttl_ms: 60_000, sequence })
    });
    assert.equal(response.status, 201);
    return (await response.json()).capability;
  }

  function request(capability) {
    return signRequest({ request_id: crypto.randomUUID(), operation: "git.commit.sign", cwd: repo, sign_args: ["-Y", "sign", "-n", "git", "-f", "/tmp/untrusted"], payload_base64: payload.toString("base64"), session: null, capability, agent_id: identity.id, timestamp_ms: Date.now(), nonce: crypto.randomBytes(24).toString("base64url") }, identity.private_path);
  }

  const capability1 = await issueCapability(1, "capability-1");
  const capability2 = await issueCapability(2, "capability-2");
  const cache = { highestSequence: 0, bundle: null, capabilitySequence: {}, consumedCapabilities: new Set() };
  let signerCalls = 0;
  const signer = async () => { signerCalls += 1; return { status: 0, stdout: Buffer.from("hardware-signature"), stderr: "" }; };
  const allowed = await processRequest(request(capability1), signer, configDir, null, new Map(), cache);
  assert.equal(Buffer.from(allowed.stdout_base64, "base64").toString(), "hardware-signature");
  assert.equal(signerCalls, 1);

  const stop = await fetch(`${baseUrl}/v1/organizations/${organizationId}/emergency-stop`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": "emergency-stop" },
    body: JSON.stringify({ reason: "incident" })
  });
  assert.equal(stop.status, 201);
  assert.equal((await cloud.sync()).sequence, 2);
  await assert.rejects(processRequest(request(capability2), signer, configDir, null, new Map(), cache), /global_revoked/);
  assert.equal(signerCalls, 1);
});
