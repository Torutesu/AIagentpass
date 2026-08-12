import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createCloudRuntime, loadRuntimeConfig } from "../src/runtime.mjs";

function files() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cloud-runtime-"));
  fs.chmodSync(root, 0o700);
  const dataDir = path.join(root, "data");
  const tokenRecordsPath = path.join(root, "tokens.json");
  const bundlePrivateKeyPath = path.join(root, "bundle.pem");
  const token = generateApiToken();
  const records = [createApiTokenRecord({ token, organizationId: crypto.randomUUID(), memberId: crypto.randomUUID(), role: "owner" })];
  const keys = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(tokenRecordsPath, JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(bundlePrivateKeyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return { root, env: { AGENTPASS_CLOUD_DATA_DIR: dataDir, AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: tokenRecordsPath, AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: bundlePrivateKeyPath, AGENTPASS_CLOUD_PORT: "0" } };
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
});
