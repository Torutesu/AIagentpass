import crypto from "node:crypto";
import pg from "pg";

import { createRefreshHintService } from "../../src/refresh-hint-service.mjs";
import { createEd25519RefreshHintSigner } from "../../src/refresh-hint-signer.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createPostgresRefreshHintNotifier, REFRESH_HINT_NOTIFICATION_CHANNEL } from "../../src/postgres/refresh-hint-notifier.mjs";
import { createPostgresRuntime } from "../../src/postgres/runtime.mjs";

const role = process.env.AGENTPASS_G41_WORKER_ROLE;
const organizationId = process.env.AGENTPASS_G41_ORGANIZATION_ID;
const deviceId = process.env.AGENTPASS_G41_DEVICE_ID;
const AFTER_GENERATION = 1;
const LISTENER_WAIT_MS = 10_000;
const NONCE_KEY_ID = "refresh-nonce-v9";
const NONCE_KEY = Buffer.alloc(32, 0x6b);
const CURSOR_SECRET = Buffer.alloc(32, 0x63);
const CAPABILITY_SECRET = Buffer.alloc(32, 0x6d);
const { Pool } = pg;

class QualificationPool extends Pool {
  constructor(options) {
    // This process-kill test qualifies lifecycle reconstruction, not database
    // login roles. Its injected pool uses the disposable administrator URL,
    // while production configuration parsing still proves three distinct role
    // identities. Least-privilege login behavior has a separate qualification.
    const connection = new URL(process.env.AGENTPASS_TEST_POSTGRES_URL);
    connection.search = "";
    super({ ...options, connectionString: connection.toString(), ssl: false });
  }
}

let runtime;
let qualificationNotifier;

try {
  if (!new Set(["listener", "survivor", "publisher"]).has(role)) throw new Error("invalid worker role");
  if (!organizationId || !deviceId) throw new Error("worker identifiers are missing");
  const codec = createRefreshNonceCodec({ keys: { [NONCE_KEY_ID]: NONCE_KEY }, activeKeyId: NONCE_KEY_ID });
  runtime = await createPostgresRuntime({
    env: runtimeEnvironment(),
    PoolClass: QualificationPool,
    applicationVersion: "g4-1-process-kill-qualification",
    refreshNonceCodec: codec,
    platformPromotionVerifyEvidence: async () => false
  });

  if (role === "publisher") await runPublisher({ codec });
  else await runSurvivor({ codec });
} catch (error) {
  send({ type: "error", code: safeErrorCode(error) });
  try { await qualificationNotifier?.close?.(); } catch { /* bounded cleanup is best effort after a worker failure */ }
  try { await runtime?.close?.(); } catch { /* bounded cleanup is best effort after a worker failure */ }
  process.exitCode = 1;
}

function runtimeEnvironment() {
  const databaseUrl = process.env.AGENTPASS_TEST_POSTGRES_URL;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) throw new Error("test database is missing");
  const validatedURL = new URL(databaseUrl);
  validatedURL.protocol = "postgresql:";
  validatedURL.search = "?sslmode=verify-full";
  const roleUrl = (username) => {
    const value = new URL(validatedURL);
    value.username = username;
    return value.toString();
  };
  return {
    AGENTPASS_DATABASE_URL: roleUrl("agentpass_app"),
    AGENTPASS_MIGRATION_DATABASE_URL: roleUrl("agentpass_migrator"),
    AGENTPASS_SIGNER_DATABASE_URL: roleUrl("agentpass_signer"),
    AGENTPASS_MAINTENANCE_DATABASE_URL: roleUrl("agentpass_maintenance"),
    AGENTPASS_MAINTENANCE_DATABASE_MAX_CONNECTIONS: "2",
    AGENTPASS_DATABASE_MAX_CONNECTIONS: "3",
    AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS: "2000",
    AGENTPASS_DATABASE_IDLE_TIMEOUT_MS: "1000",
    AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS: "5000",
    AGENTPASS_DATABASE_LOCK_TIMEOUT_MS: "1500",
    AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET.toString("base64url"),
    AGENTPASS_CAPABILITY_NONCE_SECRET: CAPABILITY_SECRET.toString("base64url")
  };
}

async function runPublisher({ codec }) {
  const authority = createControlPlaneAuthorityRepository({
    client: runtime.pool,
    cursorSecret: CURSOR_SECRET,
    refreshNonceCodec: codec
  });
  const signer = createEd25519RefreshHintSigner({
    privateKey: crypto.generateKeyPairSync("ed25519").privateKey,
    keyId: "g41-process-kill"
  });
  const service = createRefreshHintService({
    source: runtime.controlPlaneStore,
    nonceDeriver: codec,
    signer,
    notifier: runtime.refreshHintNotifier
  });
  send({ type: "ready", role });
  const command = await nextCommand();
  if (command?.type !== "commit") throw new Error("publisher commit gate was not requested");

  const issuedAt = new Date().toISOString();
  const reduction = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: organizationId,
    issued_at: issuedAt,
    expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString()
  });
  const device = reduction.devices.find((item) => item.device_id === deviceId);
  if (!device) throw new Error("publisher did not enqueue the qualification device");
  const derived = codec.derive({
    organization_id: organizationId,
    device_id: deviceId,
    authority_generation: reduction.generation,
    outbox_id: device.outbox_id,
    key_id: device.refresh_nonce_key_id
  });

  // This is the hard process-kill gate. The transaction is committed, but no
  // call to service.poll() is made until the parent explicitly says publish.
  send({
    type: "committed",
    generation: reduction.generation,
    outbox_id: device.outbox_id,
    nonce: derived.nonce_base64url,
    nonce_digest: device.refresh_nonce_digest
  });
  const publicationCommand = await nextCommand();
  if (publicationCommand?.type === "publish") {
    const hint = await service.poll({ organization_id: organizationId, device_id: deviceId, after_generation: AFTER_GENERATION, wait_ms: 0 });
    send({ type: "published", hint });
  }
  await closeRuntime();
}

async function runSurvivor({ codec }) {
  const signer = createEd25519RefreshHintSigner({
    privateKey: crypto.generateKeyPairSync("ed25519").privateKey,
    keyId: "g41-process-kill"
  });
  // Use the production notifier implementation with a deterministic
  // client-factory gate. The factory reports readiness only after PostgreSQL
  // has accepted LISTEN, not when a pool client merely exists.
  qualificationNotifier = createPostgresRefreshHintNotifier({
    pool: runtime.pool,
    clientFactory: async () => {
      const client = await runtime.pool.connect();
      await client.query(`LISTEN ${REFRESH_HINT_NOTIFICATION_CHANNEL}`);
      send({ type: "listener-armed", role });
      return client;
    }
  });
  const service = createRefreshHintService({
    source: runtime.controlPlaneStore,
    nonceDeriver: codec,
    signer,
    notifier: qualificationNotifier
  });

  // waitForRefresh causes the production notifier's dedicated LISTEN
  // connection over the runtime pool to be established. The IPC message is
  // sent only after its snapshot is connected; no polling sleep is used to
  // coordinate the kill boundary.
  const listenerWait = qualificationNotifier.waitForRefresh({
    organization_id: organizationId,
    device_id: deviceId,
    after_generation: AFTER_GENERATION,
    timeout_ms: LISTENER_WAIT_MS
  });
  await waitForListenerConnection();
  send({ type: "listener-ready", role });
  void listenerWait.catch(() => {});

  while (true) {
    const command = await nextCommand();
    if (command?.type === "serve") {
      const hint = await service.poll({ organization_id: organizationId, device_id: deviceId, after_generation: AFTER_GENERATION, wait_ms: 0 });
      send({ type: "served", hint });
      continue;
    }
    if (command?.type === "shutdown") break;
    throw new Error("survivor command was not recognized");
  }
  await closeRuntime();
}

async function waitForListenerConnection() {
  const deadline = Date.now() + LISTENER_WAIT_MS;
  while (qualificationNotifier.snapshot().connected !== true) {
    if (Date.now() >= deadline) throw new Error("refresh listener did not connect");
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function nextCommand() {
  return new Promise((resolve) => {
    const onMessage = (message) => {
      process.off("message", onMessage);
      resolve(message);
    };
    process.on("message", onMessage);
  });
}

function send(message) {
  if (typeof process.send === "function" && process.connected) process.send(message);
}

async function closeRuntime() {
  await qualificationNotifier?.close?.();
  qualificationNotifier = undefined;
  await runtime.close();
  runtime = undefined;
  if (process.connected) process.disconnect();
  process.exit(0);
}

function safeErrorCode(error) {
  const code = error?.code;
  return typeof code === "string" && /^[A-Z0-9_:-]{1,64}$/u.test(code) ? code : "WORKER_FAILURE";
}
