import { Pool } from "pg";
import { createMigrationRunner } from "./migration-runner.mjs";
import { createCapabilityAuthorityRepository } from "./capability-authority-repository.mjs";
import { createPostgresControlPlaneStore } from "./control-plane-store.mjs";
import { createControlPlaneAuthorityRepository } from "./control-plane-authority-repository.mjs";
import { createPostgresHumanRepository } from "./human-repository.mjs";
import { createPostgresOrganizationRepository } from "./organization-repository.mjs";
import { createTenantRepositoryFactory } from "./repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";
import { createPostgresRefreshHintNotifier } from "./refresh-hint-notifier.mjs";
import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { createAgentSessionAuthorityRepository } from "./agent-session-authority-repository.mjs";
import { createPostgresAgentSessionConsumptionRepository } from "./agent-session-consumption-repository.mjs";
import { createPostgresAgentSessionIssuanceRepository } from "./agent-session-issuance-repository.mjs";
import { createAuthorityReductionAuditAppender } from "./authority-reduction-audit.mjs";
import {
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics
} from "./operational-health.mjs";

export async function createPostgresRuntime({ env = process.env, PoolClass = Pool, applicationVersion = "unknown", refreshNonceCodec, resolveProcessBindingPolicy } = {}) {
  if (resolveProcessBindingPolicy !== undefined && typeof resolveProcessBindingPolicy !== "function") throw new TypeError("resolveProcessBindingPolicy must be a function");
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
  const operationalMetrics = createOperationalMetrics();
  const refreshHintNotifier = createPostgresRefreshHintNotifier({ pool, metrics: operationalMetrics });
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
  const auditCursorSecret = exactSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET, "AGENTPASS_HUMAN_CURSOR_SECRET");
  const capabilityNonceSecret = exactSecret(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "AGENTPASS_CAPABILITY_NONCE_SECRET");
  const adminAuditRepository = createPostgresAdminAuditRepository({ client: pool });
  const agentSessionAuthorityRepository = createAgentSessionAuthorityRepository({ client: pool });
  const sharedControlRepository = createSharedControlRepository({ client: pool });
  const agentSessionConsumptionRepository = createPostgresAgentSessionConsumptionRepository({
    client: pool,
    authorityRepository: agentSessionAuthorityRepository,
    sharedControls: sharedControlRepository
  });
  const agentSessionIssuanceRepository = resolveProcessBindingPolicy === undefined ? undefined : createPostgresAgentSessionIssuanceRepository({
    client: pool,
    authorityRepository: agentSessionAuthorityRepository,
    sharedControls: sharedControlRepository,
    auditRepository: adminAuditRepository,
    resolveProcessBindingPolicy
  });
  const authorityReductionAuditAppender = createAuthorityReductionAuditAppender({ adminAuditRepository });
  const onAuthorityReduction = async ({ tx, organization_id, occurred_at, policy, resource, member_id, actor_member_id, capabilities }) => {
    const issuedAt = occurred_at ?? policy?.updated_at;
    if (typeof issuedAt !== "string" || !Number.isFinite(Date.parse(issuedAt))) throw new TypeError("authority reduction timestamp is invalid");
    const authority = createControlPlaneAuthorityRepository({
      client: transactionBoundClient(tx),
      cursorSecret: auditCursorSecret,
      refreshNonceCodec
    });
    const reduction = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
      organization_id,
      issued_at: issuedAt,
      expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString()
    });
    const audit = authorityReductionAudit({ organization_id, resource, member_id, actor_member_id, capabilities, reduction, occurred_at: issuedAt });
    if (audit) await authorityReductionAuditAppender.appendAuthorityReductionAudit({ ...audit, tx });
    return reduction;
  };
  const organizationRepository = createPostgresOrganizationRepository({ client: pool, onAuthorityReduction });
  const capabilityAuthorityRepository = createCapabilityAuthorityRepository({ client: pool, onAuthorityReduction });
  const controlPlaneStore = createPostgresControlPlaneStore({
    client: pool,
    organizationRepository,
    capabilityAuthorityRepository,
    sharedControlRepository,
    auditCursorSecret,
    capabilityNonceSecret,
    refreshNonceCodec,
    onAuthorityReduction
  });
  return Object.freeze({
    pool,
    humanRepository: createPostgresHumanRepository({ client: pool, onAuthorityReduction }),
    organizationRepository,
    capabilityAuthorityRepository,
    agentSessionAuthorityRepository: agentSessionConsumptionRepository,
    agentSessionConsumptionRepository,
    ...(agentSessionIssuanceRepository ? { agentSessionIssuanceRepository } : {}),
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

function authorityReductionAudit({ organization_id, resource, member_id, actor_member_id, capabilities, reduction, occurred_at }) {
  if (resource === "credential" || resource === "session") {
    return Object.freeze({
      organization_id,
      actor: Object.freeze({ member_id }),
      event_type: `${resource}.revoked`,
      resource: Object.freeze({ type: "member", id: member_id }),
      metadata: Object.freeze({ generation: reduction.generation }),
      reason: "human_management",
      source: "management_api",
      mutation_key: `authority-reduction-${reduction.generation}`,
      occurred_at
    });
  }
  if (Array.isArray(capabilities) && capabilities.length > 0) {
    return Object.freeze({
      organization_id,
      actor: Object.freeze({ member_id: actor_member_id }),
      event_type: "capability.revoked",
      resource: Object.freeze({ type: "member", id: member_id }),
      metadata: Object.freeze({ revoked_count: capabilities.length, generation: reduction.generation }),
      reason: "authority_revoked",
      source: "system",
      mutation_key: `authority-reduction-${reduction.generation}`,
      occurred_at
    });
  }
  return null;
}

function transactionBoundClient(tx) {
  return Object.freeze({
    async query(text, params) {
      if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
      return tx.query(text, params);
    }
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
