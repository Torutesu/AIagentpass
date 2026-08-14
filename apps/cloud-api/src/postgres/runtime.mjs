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
import { createPostgresOwnerRecoveryRepository } from "./owner-recovery-repository.mjs";
import { createPostgresOwnerRecoveryWebAuthnRepository } from "./owner-recovery-webauthn-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "./owner-recovery-outbox-repository.mjs";
import { createPostgresOwnerRecoveryOutboxManagementRepository } from "./owner-recovery-outbox-management-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRetentionRepository } from "./owner-recovery-outbox-retention-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "./owner-recovery-outbox-worker.mjs";
import { normalizeOwnerRecoveryDeliveryBinding } from "./owner-recovery-delivery-binding.mjs";
import { createSharedControlMaintenanceWorker } from "./shared-control-maintenance-worker.mjs";
import { createAgentSessionAuthorityRepository } from "./agent-session-authority-repository.mjs";
import { createPostgresAgentSessionConsumptionRepository } from "./agent-session-consumption-repository.mjs";
import { createPostgresAgentSessionLifecycleRepository } from "./agent-session-lifecycle-repository.mjs";
import { createPostgresAgentSessionIssuanceRepository } from "./agent-session-issuance-repository.mjs";
import { createQualificationGrantBatchRepository } from "./qualification-grant-batch-repository.mjs";
import { createAuthorityReductionAuditAppender } from "./authority-reduction-audit.mjs";
import { createPostgresManagedSignerKeyLifecycleRepository } from "./managed-signer-key-lifecycle-repository.mjs";
import { createPostgresProviderOperationRepository } from "./provider-operation-repository.mjs";
import {
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics
} from "./operational-health.mjs";

export async function createPostgresRuntime({ env = process.env, PoolClass = Pool, applicationVersion = "unknown", refreshNonceCodec, resolveProcessBindingPolicy, ownerRecoveryPublisher, ownerRecoveryOutboxAutoStart = true, ownerRecoveryOutboxWorkerOptions = {}, sharedControlMaintenanceAutoStart = true, sharedControlMaintenanceWorkerOptions = {} } = {}) {
  if (resolveProcessBindingPolicy !== undefined && typeof resolveProcessBindingPolicy !== "function") throw new TypeError("resolveProcessBindingPolicy must be a function");
  if (typeof ownerRecoveryOutboxAutoStart !== "boolean" || !ownerRecoveryOutboxWorkerOptions || typeof ownerRecoveryOutboxWorkerOptions !== "object" || Array.isArray(ownerRecoveryOutboxWorkerOptions)) throw new TypeError("owner recovery outbox runtime configuration is invalid");
  if (typeof sharedControlMaintenanceAutoStart !== "boolean" || !sharedControlMaintenanceWorkerOptions || typeof sharedControlMaintenanceWorkerOptions !== "object" || Array.isArray(sharedControlMaintenanceWorkerOptions)) throw new TypeError("shared-control maintenance runtime configuration is invalid");
  let ownerRecoveryDeliveryBinding;
  if (ownerRecoveryPublisher !== undefined
    && (!ownerRecoveryPublisher || typeof ownerRecoveryPublisher.publish !== "function"
      || typeof ownerRecoveryPublisher.lookupAcceptance !== "function")) throw new TypeError("owner recovery publisher is invalid");
  try { ownerRecoveryDeliveryBinding = ownerRecoveryPublisher === undefined ? undefined : normalizeOwnerRecoveryDeliveryBinding(ownerRecoveryPublisher.binding); }
  catch { throw new TypeError("owner recovery publisher binding is invalid"); }
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
  let closePoolPromise;
  let ownerRecoveryOutboxWorker;
  let ownerRecoveryOutboxRepository;
  let sharedControlMaintenanceWorker;
  const drainController = createDrainController();
  const operationalMetrics = createOperationalMetrics();
  const refreshHintNotifier = createPostgresRefreshHintNotifier({ pool, metrics: operationalMetrics });
  const operationalHealth = createOperationalHealth({
    pool,
    maxConnections: config.maxConnections,
    migrationStatus: () => migrationRunner.status(),
    metrics: operationalMetrics,
    drainController,
    ...(ownerRecoveryPublisher === undefined ? {} : {
      outboxStatus: async () => ({
        ...(await ownerRecoveryOutboxRepository.health()),
        worker_state: ownerRecoveryOutboxWorker?.snapshot().state ?? "unavailable"
      })
    })
  });
  async function closePool() {
    if (closed) return;
    if (closePoolPromise) return closePoolPromise;
    closePoolPromise = (async () => {
      await refreshHintNotifier.close();
      await pool.end();
      closed = true;
    })();
    try { await closePoolPromise; } catch (error) { closePoolPromise = undefined; throw error; }
  }
  async function close() {
    return drain();
  }
  async function drain(options = {}) {
    const timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 60_000) throw new TypeError("runtime drain timeout is invalid");
    const workerDrain = ownerRecoveryOutboxWorker?.drain({ timeout_ms: timeoutMs });
    const maintenanceDrain = sharedControlMaintenanceWorker?.close({ timeoutMs });
    return drainController.drain({
      ...options,
      timeoutMs,
      close: async () => {
        const workerResult = await workerDrain;
        if (workerResult && workerResult.drained !== true) throw Object.assign(new Error("Owner recovery outbox worker drain timed out"), { code: "owner_recovery_outbox_worker_drain_timeout" });
        const maintenanceResult = await maintenanceDrain;
        if (maintenanceResult && maintenanceResult.drained !== true) throw Object.assign(new Error("Shared-control maintenance worker drain timed out"), { code: "shared_control_maintenance_worker_drain_timeout" });
        await closePool();
      }
    });
  }
  const auditCursorSecret = exactSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET, "AGENTPASS_HUMAN_CURSOR_SECRET");
  const capabilityNonceSecret = exactSecret(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "AGENTPASS_CAPABILITY_NONCE_SECRET");
  const adminAuditRepository = createPostgresAdminAuditRepository({ client: pool });
  const ownerRecoveryRepository = createPostgresOwnerRecoveryRepository({
    client: pool,
    auditRepository: adminAuditRepository,
    metrics: operationalMetrics,
    deliveryBinding: ownerRecoveryDeliveryBinding
  });
  const ownerRecoveryWebAuthnRepository = createPostgresOwnerRecoveryWebAuthnRepository({ client: pool });
  ownerRecoveryOutboxRepository = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: ownerRecoveryDeliveryBinding });
  const ownerRecoveryOutboxManagementRepository = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: pool,
    cursorSecret: auditCursorSecret,
    auditRepository: adminAuditRepository,
    metrics: operationalMetrics
  });
  const ownerRecoveryOutboxRetentionRepository = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: pool,
    metrics: operationalMetrics
  });
  if (ownerRecoveryPublisher !== undefined) {
    ownerRecoveryOutboxWorker = createOwnerRecoveryOutboxWorker({
      ...ownerRecoveryOutboxWorkerOptions,
      repository: ownerRecoveryOutboxRepository,
      retentionRepository: ownerRecoveryOutboxRetentionRepository,
      publisher: ownerRecoveryPublisher,
      metrics: operationalMetrics
    });
    if (ownerRecoveryOutboxAutoStart) ownerRecoveryOutboxWorker.start();
  }
  const agentSessionAuthorityRepository = createAgentSessionAuthorityRepository({ client: pool });
  const sharedControlRepository = createSharedControlRepository({ client: pool });
  sharedControlMaintenanceWorker = createSharedControlMaintenanceWorker({
    ...sharedControlMaintenanceWorkerOptions,
    repository: sharedControlRepository,
    metrics: operationalMetrics
  });
  if (sharedControlMaintenanceAutoStart) sharedControlMaintenanceWorker.start();
  const agentSessionConsumptionRepository = createPostgresAgentSessionConsumptionRepository({
    client: pool,
    authorityRepository: agentSessionAuthorityRepository,
    sharedControls: sharedControlRepository,
    metrics: operationalMetrics
  });
  const agentSessionLifecycleRepository = createPostgresAgentSessionLifecycleRepository({ client: pool, metrics: operationalMetrics });
  const agentSessionIssuanceRepository = resolveProcessBindingPolicy === undefined ? undefined : createPostgresAgentSessionIssuanceRepository({
    client: pool,
    authorityRepository: agentSessionAuthorityRepository,
    sharedControls: sharedControlRepository,
    auditRepository: adminAuditRepository,
    metrics: operationalMetrics,
    resolveProcessBindingPolicy
  });
  const qualificationGrantBatchRepository = createQualificationGrantBatchRepository({
    client: pool,
    sharedControls: sharedControlRepository,
    adminAuditRepository
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
    onRevocation: async ({ tx, revocation }) => {
      const selector = revocation.target_type === "organization"
        ? { organization_wide: true }
        : revocation.target_type === "device"
          ? { device_id: revocation.target_id }
          : revocation.target_type === "agent"
            ? { agent_id: revocation.target_id }
            : null;
      if (selector) await agentSessionLifecycleRepository.revokeAuthorityInTransaction({
        tx,
        organization_id: revocation.organization_id,
        ...selector,
        revoked_at: revocation.revoked_at
      });
    },
    onAuthorityReduction
  });
  return Object.freeze({
    pool,
    humanRepository: createPostgresHumanRepository({ client: pool, onAuthorityReduction }),
    organizationRepository,
    capabilityAuthorityRepository,
    agentSessionAuthorityRepository: agentSessionConsumptionRepository,
    agentSessionConsumptionRepository,
    agentSessionLifecycleRepository,
    ...(agentSessionIssuanceRepository ? { agentSessionIssuanceRepository } : {}),
    qualificationGrantBatchRepository,
    createManagedSignerKeyLifecycleRepository: (options = {}) => createPostgresManagedSignerKeyLifecycleRepository({ ...options, client: pool }),
    createProviderOperationRepository: (options = {}) => createPostgresProviderOperationRepository({ ...options, client: pool }),
    ownerRecoveryRepository,
    ownerRecoveryWebAuthnRepository,
    ownerRecoveryOutboxRepository,
    ownerRecoveryOutboxManagementRepository,
    ownerRecoveryOutboxRetentionRepository,
    ...(ownerRecoveryOutboxWorker ? { ownerRecoveryOutboxWorker } : {}),
    sharedControlRepository,
    sharedControlMaintenanceWorker,
    controlPlaneStore,
    refreshHintNotifier,
    tenants: createTenantRepositoryFactory({ client: pool }),
    operationalHealth,
    operationalMetrics,
    operationalReport: Object.freeze({ snapshot: operationalHealth.operationalSnapshot }),
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
