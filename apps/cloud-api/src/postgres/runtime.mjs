import { Pool } from "pg";
import { createMigrationRunner } from "./migration-runner.mjs";
import { createCapabilityAuthorityRepository } from "./capability-authority-repository.mjs";
import { createPostgresControlPlaneStore } from "./control-plane-store.mjs";
import { createPostgresHumanRepository } from "./human-repository.mjs";
import { createPostgresOrganizationRepository } from "./organization-repository.mjs";
import { createTenantRepositoryFactory } from "./repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";
import { createPostgresRefreshHintNotifier } from "./refresh-hint-notifier.mjs";
import {
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics
} from "./operational-health.mjs";

export async function createPostgresRuntime({ env = process.env, PoolClass = Pool, applicationVersion = "unknown", refreshNonceCodec } = {}) {
  const config = loadPostgresConfig(env);
  const pool = new PoolClass({ connectionString: config.connectionString, ssl: { rejectUnauthorized: true }, max: config.maxConnections, connectionTimeoutMillis: config.connectionTimeoutMs, idleTimeoutMillis: config.idleTimeoutMs, statement_timeout: config.statementTimeoutMs, lock_timeout: config.lockTimeoutMs, query_timeout: config.statementTimeoutMs + 1_000, allowExitOnIdle: false });
  const migrationRunner = createMigrationRunner({ client: pool, applicationVersion });
  let client;
  try {
    client = await pool.connect();
    await client.query("SELECT set_config('statement_timeout', $1, false)", [`${config.statementTimeoutMs}ms`]);
    await client.query("SELECT set_config('lock_timeout', $1, false)", [`${config.lockTimeoutMs}ms`]);
    await createMigrationRunner({ client, applicationVersion }).run();
  } catch (error) {
    client?.release?.(true);
    await pool.end().catch(() => {});
    throw error;
  }
  client.release();
  let closed = false;
  const drainController = createDrainController();
  const refreshHintNotifier = createPostgresRefreshHintNotifier({ pool });
  const operationalMetrics = createOperationalMetrics();
  const operationalHealth = createOperationalHealth({
    pool,
    maxConnections: config.maxConnections,
    migrationStatus: () => migrationRunner.status(),
    metrics: operationalMetrics,
    drainController
  });
  async function closePool() {
    if (closed) return;
    closed = true;
    await refreshHintNotifier.close();
    await pool.end();
  }
  async function close() {
    return drainController.close(closePool);
  }
  async function drain(options = {}) {
    return drainController.drain({ ...options, close: closePool });
  }
  const organizationRepository = createPostgresOrganizationRepository({ client: pool });
  const capabilityAuthorityRepository = createCapabilityAuthorityRepository({ client: pool });
  const sharedControlRepository = createSharedControlRepository({ client: pool });
  const auditCursorSecret = exactSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET, "AGENTPASS_HUMAN_CURSOR_SECRET");
  const capabilityNonceSecret = exactSecret(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "AGENTPASS_CAPABILITY_NONCE_SECRET");
  const controlPlaneStore = createPostgresControlPlaneStore({
    client: pool,
    organizationRepository,
    capabilityAuthorityRepository,
    sharedControlRepository,
    auditCursorSecret,
    capabilityNonceSecret,
    refreshNonceCodec
  });
  return Object.freeze({
    pool,
    humanRepository: createPostgresHumanRepository({ client: pool }),
    organizationRepository,
    capabilityAuthorityRepository,
    sharedControlRepository,
    controlPlaneStore,
    refreshHintNotifier,
    tenants: createTenantRepositoryFactory({ client: pool }),
    operationalHealth,
    operationalMetrics,
    metrics: operationalMetrics,
    readiness: operationalHealth.readiness,
    health: operationalHealth.health,
    trackInFlight: drainController.track,
    beginDrain: drainController.beginDrain,
    drain,
    close
  });
}

export function loadPostgresConfig(env = {}) {
  const raw = env.AGENTPASS_DATABASE_URL;
  let url;
  try { url = new URL(raw); } catch { throw new TypeError("AGENTPASS_DATABASE_URL is invalid"); }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash) throw new TypeError("AGENTPASS_DATABASE_URL is invalid");
  const parameters = [...url.searchParams.entries()];
  if (parameters.length !== 1 || parameters[0][0] !== "sslmode" || parameters[0][1] !== "verify-full") {
    throw new TypeError("PostgreSQL sslmode=verify-full is required and must be the only connection parameter");
  }
  return Object.freeze({
    connectionString: url.toString(),
    maxConnections: integer(env.AGENTPASS_DATABASE_MAX_CONNECTIONS ?? "10", 2, 100),
    connectionTimeoutMs: integer(env.AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS ?? "5000", 250, 30_000),
    idleTimeoutMs: integer(env.AGENTPASS_DATABASE_IDLE_TIMEOUT_MS ?? "30000", 1_000, 300_000),
    statementTimeoutMs: integer(env.AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS ?? "8000", 250, 60_000),
    lockTimeoutMs: integer(env.AGENTPASS_DATABASE_LOCK_TIMEOUT_MS ?? "2000", 100, 30_000)
  });
}

function integer(value, min, max) { if (typeof value !== "string" || !/^\d+$/.test(value)) throw new TypeError("PostgreSQL timeout/limit is invalid"); const result=Number(value); if(!Number.isSafeInteger(result)||result<min||result>max) throw new TypeError("PostgreSQL timeout/limit is invalid"); return result; }

function exactSecret(value, name) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new TypeError(`${name} must be an exact 32-byte base64url secret`); const bytes=Buffer.from(value,"base64url"); if(bytes.length!==32||bytes.toString("base64url")!==value) throw new TypeError(`${name} must be an exact 32-byte base64url secret`); return bytes; }
