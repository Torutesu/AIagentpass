import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createCloudRuntime, loadRuntimeConfig } from "../src/runtime.mjs";
import { createCloudStore } from "../src/store.mjs";

const CURSOR_SECRET = Buffer.alloc(32, 0x42).toString("base64url");

function files() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cloud-runtime-"));
  fs.chmodSync(root, 0o700);
  const dataDir = path.join(root, "data");
  const tokenRecordsPath = path.join(root, "tokens.json");
  const bundlePrivateKeyPath = path.join(root, "bundle.pem");
  const identityPublicKeyPath = path.join(root, "identity-public.pem");
  const refreshPrivateKeyPath = path.join(root, "refresh-private.pem");
  const refreshNonceKeyringPath = path.join(root, "refresh-nonce-keyring.json");
  const agentSessionProcessPoliciesPath = path.join(root, "agent-session-process-policies.json");
  const token = generateApiToken();
  const records = [createApiTokenRecord({ token, organizationId: crypto.randomUUID(), memberId: crypto.randomUUID(), role: "owner" })];
  const keys = crypto.generateKeyPairSync("ed25519");
  const refreshKeys = crypto.generateKeyPairSync("ed25519");
  const agentSessionKeys = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(tokenRecordsPath, JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(bundlePrivateKeyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(identityPublicKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(refreshPrivateKeyPath, refreshKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(refreshNonceKeyringPath, JSON.stringify({ version: 1, active_key_id: "refresh-nonce-v1", keys: { "refresh-nonce-v1": Buffer.alloc(32, 0x35).toString("base64url") } }), { mode: 0o600 });
  fs.writeFileSync(agentSessionProcessPoliciesPath, JSON.stringify({ version: 1, policies: [{ policy_id: "claude-code-v1", release_id: "agentpass-0.18.0", agent_kind: "claude-code", adapter_id: "11111111-1111-4111-8111-111111111111", adapter_versions: ["1.0.0"], status: "enabled" }] }), { mode: 0o600 });
  return { root, identityPublicKeyPath, refreshPrivateKeyPath, refreshNonceKeyringPath, agentSessionProcessPoliciesPath, agentSessionKeys, env: { AGENTPASS_CLOUD_PROFILE: "evaluation", AGENTPASS_CLOUD_DATA_DIR: dataDir, AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: tokenRecordsPath, AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: bundlePrivateKeyPath, AGENTPASS_CLOUD_PORT: "0" } };
}

test("production runtime starts from protected files and closes idempotently", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const runtime = await createCloudRuntime({ env: value.env, logger: { info() {} } });
  const address = await runtime.listen();
  assert.equal(typeof address.port, "number");
  await runtime.close();
  await runtime.close();
});

test("runtime rejects unsafe secrets, key algorithms, and configuration", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  fs.chmodSync(value.env.AGENTPASS_CLOUD_TOKEN_RECORDS_PATH, 0o644);
  await assert.rejects(createCloudRuntime({ env: value.env }), /permissions are unsafe/);
  assert.throws(() => loadRuntimeConfig({}), /profile is required/);
  assert.throws(() => loadRuntimeConfig({ ...value.env, AGENTPASS_CLOUD_HOST: "example.com" }), /listen host/);
  assert.throws(() => loadRuntimeConfig({ ...value.env, AGENTPASS_DATABASE_URL: "postgresql://db" }), /forbids PostgreSQL/);
  const humanEnv = hostedEnv(value);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_WEBAUTHN_RP_ID: "other.test" }), /Human Auth configuration is invalid/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_CURSOR_SECRET: undefined }), /requires complete PostgreSQL/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_CURSOR_SECRET: "A".repeat(42) }), /Human Auth configuration is invalid/);
});

test("production human auth is composed from PostgreSQL and closed with the runtime", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = hostedEnv(value);
  const calls = [];
  const controlPlaneStore = await createCloudStore({ dataDir: path.join(value.root, "hosted-test-store"), auditCursorSecret: Buffer.from(CURSOR_SECRET, "base64url") });
  const hostedControlPlaneStore = new Proxy(controlPlaneStore, { get(target, property, receiver) { if (property === "pollDeviceRefresh") return async () => null; if (property === "markDeviceRefreshDelivered") return async () => {}; return Reflect.get(target, property, receiver); } });
  const postgresRuntime = { pool: {}, humanRepository: {}, controlPlaneStore: hostedControlPlaneStore, refreshHintNotifier: { async waitForRefresh() { return false; } }, sharedControlRepository: { async consumeDeviceRequestNonce() { return { accepted: true }; }, async acquireRateLimit() { return { allowed: true, limit: 120, remaining: 119, retryAfterMs: 0, retryAfterSeconds: 0, resetAt: Date.now() }; } }, capabilityAuthorityRepository: { async issueCapabilityMetadata() {}, async listRevokedCapabilityIds() { return []; } }, agentSessionIssuanceRepository: { async issueAgentSessionGrant() {} }, agentSessionAuthorityRepository: { async consumeAgentSessionGrant() {} }, async readiness() { return readyDatabaseReport(); }, async close() { calls.push("postgres-close"); await controlPlaneStore.close(); } };
  const recentAuthService = { async authorize() { return { verified: false }; } };
  const humanSession = { async authenticateRequest() { return { session: {} }; } };
  let signerHealthy = true;
  const provider = signerProvider(value);
  const publicKeyMetadata = provider.publicKeyMetadata;
  provider.publicKeyMetadata = async (input) => {
    if (!signerHealthy) throw new Error("simulated provider outage");
    return publicKeyMetadata(input);
  };
  const runtime = await createCloudRuntime({ env, logger: { info() {} }, agentSessionSignerProvider: provider, postgresFactory: async (input) => { calls.push(["postgres", input.applicationVersion, typeof input.refreshNonceCodec?.derive, typeof input.resolveProcessBindingPolicy]); return postgresRuntime; }, humanAuthFactory: (input) => { calls.push(["human", input.origin, input.rpId, input.cursorSecret, input.signedConsoleIdentity, input.agentSessionSigner]); return { api: { async handle() { return { status: 404, body: { error: { code: "not_found", message: "Resource not found" } }, headers: {} }; } }, humanSession, recentAuthService }; } });
  assert.equal(runtime.postgresRuntime, postgresRuntime);
  assert.equal(runtime.humanAuthRuntime.recentAuthService, recentAuthService);
  assert.deepEqual(calls[0], ["postgres", "0.18.0", "function", "function"]);
  assert.deepEqual(calls[1].slice(0, 4), ["human", "https://console.example.test", "example.test", CURSOR_SECRET]);
  assert.equal(calls[1][4].issuer, "agentpass-console");
  assert.equal(calls[1][4].audience, "agentpass-cloud-session");
  assert.equal(calls[1][4].keyId, "console-2026-08");
  assert.match(calls[1][4].publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(typeof calls[1][5].signAgentSessionGrant, "function");
  assert.equal(Object.hasOwn(runtime.config.humanAuth, "cursorSecret"), false);
  assert.equal(runtime.config.tokenRecordsPath, null);
  assert.equal(JSON.stringify(runtime.config).includes(CURSOR_SECRET), false);
  const address = await runtime.listen();
  const probeHeaders = { "AgentPass-Operational-Token": env.AGENTPASS_OPERATIONAL_PROBE_SECRET };
  const ready = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(ready.status, 200);
  assert.equal((await ready.json()).checks.agent_session_signer.ok, true);
  signerHealthy = false;
  const degraded = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(degraded.status, 503);
  const degradedBody = await degraded.json();
  assert.equal(degradedBody.code, "agent_session_signer_unavailable");
  assert.deepEqual(degradedBody.checks.agent_session_signer, { ok: false, purpose: "agent-session-grant", algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
  await runtime.close();
  assert.equal(calls.at(-1), "postgres-close");
});

test("production human auth fails closed without PostgreSQL capability authority", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = hostedEnv(value);
  let closed = false;
  await assert.rejects(createCloudRuntime({
    env,
    agentSessionSignerProvider: signerProvider(value),
    postgresFactory: async () => ({ pool: {}, humanRepository: {}, async close() { closed = true; } }),
    humanAuthFactory: () => { throw new Error("human auth must not be constructed"); }
  }), /capability authority is unavailable/);
  assert.equal(closed, true);
});

function hostedEnv(value) {
  return { ...value.env, AGENTPASS_CLOUD_PROFILE: "hosted", AGENTPASS_CLOUD_DATA_DIR: undefined, AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: undefined, AGENTPASS_DATABASE_URL: "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full", AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test", AGENTPASS_WEBAUTHN_RP_ID: "example.test", AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET, AGENTPASS_CAPABILITY_NONCE_SECRET: Buffer.alloc(32, 0x33).toString("base64url"), AGENTPASS_OPERATIONAL_PROBE_SECRET: Buffer.alloc(32, 0x34).toString("base64url"), AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-console", AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-cloud-session", AGENTPASS_IDENTITY_ASSERTION_KID: "console-2026-08", AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: value.identityPublicKeyPath, AGENTPASS_CLOUD_REFRESH_PRIVATE_KEY_PATH: value.refreshPrivateKeyPath, AGENTPASS_CLOUD_REFRESH_KEY_ID: "refresh-2026-08", AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH: value.refreshNonceKeyringPath, AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08", AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: value.agentSessionKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH: value.agentSessionProcessPoliciesPath };
}

function signerProvider(value) {
  const publicKey = value.agentSessionKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, value.agentSessionKeys.privateKey); }
  };
}

function readyDatabaseReport() {
  return Object.freeze({
    version: 1,
    ready: true,
    status: "ready",
    code: "ready",
    checks: Object.freeze({
      database: Object.freeze({ ok: true, probe: "ok" }),
      schema: Object.freeze({ ok: true, expected_version: 1, applied_version: 1, migration_count: 1, pending_count: 0, checksum_status: "ok", drift: false }),
      pool: Object.freeze({ ok: true, max_connections: 10, total_connections: 1, idle_connections: 1, waiting_connections: 0, utilization_percent: 10, saturated: false }),
      drain: Object.freeze({ state: "running", accepting: true, in_flight: 0 })
    })
  });
}
