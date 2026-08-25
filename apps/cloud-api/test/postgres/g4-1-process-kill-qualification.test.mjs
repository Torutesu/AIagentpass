import assert from "node:assert/strict";
import crypto from "node:crypto";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import pg from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";

const { Pool } = pg;
const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const workerUrl = new URL("./g4-1-process-kill-worker.mjs", import.meta.url);
const repositoryRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const TEST_TIMEOUT_MS = 25_000;
const CHILD_MESSAGE_TIMEOUT_MS = 7_500;
const NONCE_KEY_ID = "refresh-nonce-v9";
const NONCE_KEY = Buffer.alloc(32, 0x6b);
const CURSOR_SECRET = Buffer.alloc(32, 0x63);
const CAPABILITY_SECRET = Buffer.alloc(32, 0x6d);

test("G4.1 hard-kill qualification reconstructs committed generation and nonce across Cloud processes", {
  skip: !databaseUrl,
  timeout: TEST_TIMEOUT_MS
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 3 });
  const children = new Set();
  let ids;
  try {
    await migrate(pool);
    ids = await createFixture(pool);

    const workerEnvironment = {
      ...process.env,
      AGENTPASS_TEST_POSTGRES_URL: databaseUrl,
      AGENTPASS_G41_ORGANIZATION_ID: ids.organization,
      AGENTPASS_G41_DEVICE_ID: ids.device,
      AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET.toString("base64url"),
      AGENTPASS_CAPABILITY_NONCE_SECRET: CAPABILITY_SECRET.toString("base64url")
    };

    // First prove that an armed PostgreSQL LISTEN owner can disappear at the
    // process boundary without making the later cross-instance check depend on
    // that process remaining alive.
    const deadListener = launchWorker("listener", workerEnvironment, children);
    await waitForMessage(deadListener, "listener-ready");
    const deadListenerExit = await killAndWait(deadListener);
    assert.equal(deadListenerExit.signal, "SIGKILL");

    const survivor = launchWorker("survivor", workerEnvironment, children);
    await waitForMessage(survivor, "listener-ready");

    const publisher = launchWorker("publisher", workerEnvironment, children);
    await waitForMessage(publisher, "ready");
    send(publisher, { type: "commit" });
    const committed = await waitForMessage(publisher, "committed");

    // The parent kills at the explicit post-commit/pre-publish gate. There is
    // no timer race: publisher waits for a command before calling service.poll.
    const beforeKill = await readOutbox(pool, ids);
    assert.equal(Number(beforeKill.desired_generation), committed.generation);
    assert.equal(beforeKill.status, "pending");
    assert.equal(Buffer.from(beforeKill.refresh_nonce_digest).toString("hex"), committed.nonce_digest);

    const publisherExit = await killAndWait(publisher);
    assert.equal(publisherExit.signal, "SIGKILL");

    const afterKill = await readOutbox(pool, ids);
    assert.equal(afterKill.status, "pending", "publisher was killed before in-process publication");

    send(survivor, { type: "serve" });
    const served = await waitForMessage(survivor, "served");
    const codec = createRefreshNonceCodec({ keys: { [NONCE_KEY_ID]: NONCE_KEY }, activeKeyId: NONCE_KEY_ID });
    const expectedNonce = codec.derive({
      organization_id: ids.organization,
      device_id: ids.device,
      authority_generation: committed.generation,
      outbox_id: committed.outbox_id,
      key_id: beforeKill.refresh_nonce_key_id
    }).nonce_base64url;
    assert.equal(served.hint.authority_generation, committed.generation);
    assert.equal(served.hint.nonce, committed.nonce);
    assert.equal(served.hint.nonce, expectedNonce);
    assert.equal(crypto.createHash("sha256").update(Buffer.from(served.hint.nonce, "base64url")).digest("hex"), committed.nonce_digest);
    assert.equal(served.hint.organization_id, ids.organization);
    assert.equal(served.hint.device_id, ids.device);

    const afterServe = await readOutbox(pool, ids);
    assert.equal(afterServe.status, "delivered");
    assert.equal(Number(afterServe.desired_generation), committed.generation);

    send(survivor, { type: "shutdown" });
    await waitForExit(survivor);
    t.diagnostic("G4.1 process-kill qualification passed; generation and nonce were reconstructed from PostgreSQL");
  } finally {
    await cleanupChildren(children);
    if (ids) await cleanupFixture(pool, ids.organization).catch(() => {});
    await pool.end();
  }
});

async function migrate(pool) {
  const client = await pool.connect();
  try {
    await createMigrationRunner({ client, applicationVersion: "g4-1-process-kill-qualification" }).run();
  } finally {
    client.release();
  }
}

async function createFixture(pool) {
  const organization = crypto.randomUUID();
  const device = crypto.randomUUID();
  const publicKey = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organization, "G4.1 process qualification"]);
  await pool.query(`INSERT INTO devices
    (organization_id,id,label,key_algorithm,public_key_pem,status)
    VALUES ($1,$2,'G4.1 qualification device','ed25519',$3,'active')`, [organization, device, publicKey]);
  const initial = await pool.query(`SELECT desired_generation,refresh_state
    FROM device_control_plane_state WHERE organization_id=$1 AND device_id=$2`, [organization, device]);
  assert.equal(initial.rows.length, 1);
  assert.equal(Number(initial.rows[0].desired_generation), 1);
  assert.equal(initial.rows[0].refresh_state, "pending");
  return { organization, device };
}

async function readOutbox(pool, ids) {
  const result = await pool.query(`SELECT desired_generation,status,refresh_nonce_key_id,refresh_nonce_digest
    FROM device_refresh_outbox
    WHERE organization_id=$1 AND device_id=$2
    ORDER BY desired_generation DESC LIMIT 1`, [ids.organization, ids.device]);
  assert.equal(result.rows.length, 1);
  return result.rows[0];
}

async function cleanupFixture(pool, organization) {
  const tables = [
    "device_bundle_acknowledgements", "bundle_acknowledgements", "device_refresh_delivery_attempts",
    "control_bundle_statements", "device_refresh_outbox", "device_control_plane_state", "device_key_epochs",
    "bundle_heads", "device_audit_events", "device_audit_gaps", "device_audit_heads", "device_request_nonces",
    "capabilities", "agents", "revocations", "policies", "device_enrollments", "memberships",
    "organization_invitations", "outbox_events", "admin_audit_events", "admin_audit_heads", "rate_limit_buckets",
    "idempotency_records", "webauthn_challenges", "control_plane_authority_generations", "devices"
  ];
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const table of tables) await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [organization]);
    await client.query("DELETE FROM organizations WHERE id=$1", [organization]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function launchWorker(workerRole, env, children) {
  const child = fork(fileURLToPath(workerUrl), [], {
    cwd: repositoryRoot,
    env: { ...env, AGENTPASS_G41_WORKER_ROLE: workerRole },
    execArgv: [],
    stdio: ["ignore", "ignore", "ignore", "ipc"]
  });
  children.add(child);
  return child;
}

function send(child, message) {
  if (child.connected) child.send(message);
}

function waitForMessage(child, expectedType) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`child message timeout: ${expectedType}`)), CHILD_MESSAGE_TIMEOUT_MS);
    const onMessage = (message) => {
      if (message?.type === "error") finish(new Error(`child reported ${message.code ?? "WORKER_FAILURE"}`));
      else if (message?.type === expectedType) finish(undefined, message);
    };
    const onExit = () => finish(new Error(`child exited before ${expectedType}`));
    const finish = (error, value) => {
      clearTimeout(timer);
      child.off("message", onMessage);
      child.off("exit", onExit);
      error ? reject(error) : resolve(value);
    };
    child.on("message", onMessage);
    child.once("exit", onExit);
  });
}

async function killAndWait(child) {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  return waitForExit(child);
}

function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("child exit timeout")), CHILD_MESSAGE_TIMEOUT_MS);
    const onExit = (code, signal) => finish(undefined, { code, signal });
    const finish = (error, value) => {
      clearTimeout(timer);
      child.off("exit", onExit);
      error ? reject(error) : resolve(value);
    };
    child.once("exit", onExit);
  });
}

async function cleanupChildren(children) {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
  await Promise.allSettled([...children].map((child) => waitForExit(child)));
}
