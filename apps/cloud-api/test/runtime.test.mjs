import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createCloudRuntime, loadRuntimeConfig } from "../src/runtime.mjs";

const CURSOR_SECRET = Buffer.alloc(32, 0x42).toString("base64url");

function files() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cloud-runtime-"));
  fs.chmodSync(root, 0o700);
  const dataDir = path.join(root, "data");
  const tokenRecordsPath = path.join(root, "tokens.json");
  const bundlePrivateKeyPath = path.join(root, "bundle.pem");
  const identityPublicKeyPath = path.join(root, "identity-public.pem");
  const token = generateApiToken();
  const records = [createApiTokenRecord({ token, organizationId: crypto.randomUUID(), memberId: crypto.randomUUID(), role: "owner" })];
  const keys = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(tokenRecordsPath, JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(bundlePrivateKeyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(identityPublicKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  return { root, env: { AGENTPASS_CLOUD_DATA_DIR: dataDir, AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: tokenRecordsPath, AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: bundlePrivateKeyPath, AGENTPASS_CLOUD_PORT: "0", AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-console", AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-cloud-session", AGENTPASS_IDENTITY_ASSERTION_KID: "console-2026-08", AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: identityPublicKeyPath } };
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
  assert.throws(() => loadRuntimeConfig({}), /absolute path/);
  assert.throws(() => loadRuntimeConfig({ ...value.env, AGENTPASS_CLOUD_HOST: "example.com" }), /listen host/);
  assert.throws(() => loadRuntimeConfig({ ...value.env, AGENTPASS_DATABASE_URL: "postgresql://db" }), /Human auth configuration is incomplete/);
  assert.throws(() => loadRuntimeConfig({ ...value.env, AGENTPASS_DATABASE_URL: "postgresql://db", AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test", AGENTPASS_WEBAUTHN_RP_ID: "other.test" }), /RP_ID/);
  const humanEnv = { ...value.env, AGENTPASS_DATABASE_URL: "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full", AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test", AGENTPASS_WEBAUTHN_RP_ID: "example.test" };
  assert.throws(() => loadRuntimeConfig(humanEnv), /HUMAN_CURSOR_SECRET/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_CURSOR_SECRET: "A".repeat(42) }), /HUMAN_CURSOR_SECRET/);
});

test("production human auth is composed from PostgreSQL and closed with the runtime", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = { ...value.env, AGENTPASS_DATABASE_URL: "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full", AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test", AGENTPASS_WEBAUTHN_RP_ID: "example.test", AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET };
  const calls = [];
  const postgresRuntime = { pool: {}, humanRepository: {}, capabilityAuthorityRepository: { async issueCapabilityMetadata() {}, async listRevokedCapabilityIds() { return []; } }, async close() { calls.push("postgres-close"); } };
  const recentAuthService = { async authorize() { return { verified: false }; } };
  const humanSession = { async authenticateRequest() { return { session: {} }; } };
  const runtime = await createCloudRuntime({ env, logger: { info() {} }, postgresFactory: async (input) => { calls.push(["postgres", input.applicationVersion]); return postgresRuntime; }, humanAuthFactory: (input) => { calls.push(["human", input.origin, input.rpId, input.cursorSecret, input.signedConsoleIdentity]); return { api: { async handle() { return { status: 404, body: { error: { code: "not_found", message: "Resource not found" } }, headers: {} }; } }, humanSession, recentAuthService }; } });
  assert.equal(runtime.postgresRuntime, postgresRuntime);
  assert.equal(runtime.humanAuthRuntime.recentAuthService, recentAuthService);
  assert.deepEqual(calls[0], ["postgres", "0.18.0"]);
  assert.deepEqual(calls[1].slice(0, 4), ["human", "https://console.example.test", "example.test", CURSOR_SECRET]);
  assert.equal(calls[1][4].issuer, "agentpass-console");
  assert.equal(calls[1][4].audience, "agentpass-cloud-session");
  assert.equal(calls[1][4].keyId, "console-2026-08");
  assert.match(calls[1][4].publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(Object.hasOwn(runtime.config.humanAuth, "cursorSecret"), false);
  assert.equal(JSON.stringify(runtime.config).includes(CURSOR_SECRET), false);
  await runtime.close();
  assert.equal(calls.at(-1), "postgres-close");
});

test("production human auth fails closed without PostgreSQL capability authority", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = { ...value.env, AGENTPASS_DATABASE_URL: "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full", AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test", AGENTPASS_WEBAUTHN_RP_ID: "example.test", AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET };
  let closed = false;
  await assert.rejects(createCloudRuntime({
    env,
    postgresFactory: async () => ({ pool: {}, humanRepository: {}, async close() { closed = true; } }),
    humanAuthFactory: () => { throw new Error("human auth must not be constructed"); }
  }), /capability authority is unavailable/);
  assert.equal(closed, true);
});
