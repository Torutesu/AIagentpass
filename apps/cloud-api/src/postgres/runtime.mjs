import { Pool } from "pg";
import { createMigrationRunner, loadSqlMigrations } from "./migration-runner.mjs";
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
import { createPostgresProviderOperationMaintenanceRepository } from "./provider-operation-maintenance-repository.mjs";
import { createManagedSignerProviderOperationMaintenanceWorker } from "./managed-signer-provider-operation-maintenance-worker.mjs";
import { createPostgresAuditExportSnapshotReader } from "./audit-export-snapshot-reader.mjs";
import { createPostgresAuditExportIssuanceRepository } from "./audit-export-issuance-repository.mjs";
import { createPostgresPlatformPromotionIssuanceRepository } from "./platform-promotion-issuance-repository.mjs";
import { createPostgresPlatformAuthorizationRepository } from "./platform-authorization-repository.mjs";
import { createPostgresPlatformOperatorAssignmentRepository } from "./platform-operator-assignment-repository.mjs";
import { createPostgresPlatformSessionRepository } from "./platform-session-repository.mjs";
import { createPostgresPlatformSessionWebAuthnRepository } from "./platform-session-webauthn-repository.mjs";
import { createPostgresPlatformSessionBootstrapRepository } from "./platform-session-bootstrap-repository.mjs";
import { createPostgresHostedIdentityBootstrapRepository } from "./hosted-identity-bootstrap-repository.mjs";
import {
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics
} from "./operational-health.mjs";
import { POSTGRES_SCHEMA_HEAD } from "./schema-head.mjs";

export async function createPostgresRuntime({ env = process.env, PoolClass = Pool, MigrationPoolClass = PoolClass, SignerPoolClass = PoolClass, applicationVersion = "unknown", refreshNonceCodec, resolveProcessBindingPolicy, ownerRecoveryPublisher, platformPromotionVerifyEvidence, platformPromotionLifecycle = undefined, ownerRecoveryOutboxAutoStart = true, ownerRecoveryOutboxWorkerOptions = {}, sharedControlMaintenanceAutoStart = true, sharedControlMaintenanceWorkerOptions = {}, managedSignerProviderOperationMaintenanceAutoStart = true, managedSignerProviderOperationMaintenanceWorkerOptions = {} } = {}) {
  if (resolveProcessBindingPolicy !== undefined && typeof resolveProcessBindingPolicy !== "function") throw new TypeError("resolveProcessBindingPolicy must be a function");
  if (typeof ownerRecoveryOutboxAutoStart !== "boolean" || !ownerRecoveryOutboxWorkerOptions || typeof ownerRecoveryOutboxWorkerOptions !== "object" || Array.isArray(ownerRecoveryOutboxWorkerOptions)) throw new TypeError("owner recovery outbox runtime configuration is invalid");
  if (typeof sharedControlMaintenanceAutoStart !== "boolean" || !sharedControlMaintenanceWorkerOptions || typeof sharedControlMaintenanceWorkerOptions !== "object" || Array.isArray(sharedControlMaintenanceWorkerOptions)) throw new TypeError("shared-control maintenance runtime configuration is invalid");
  if (typeof managedSignerProviderOperationMaintenanceAutoStart !== "boolean" || !managedSignerProviderOperationMaintenanceWorkerOptions || typeof managedSignerProviderOperationMaintenanceWorkerOptions !== "object" || Array.isArray(managedSignerProviderOperationMaintenanceWorkerOptions)) throw new TypeError("managed signer provider-operation maintenance runtime configuration is invalid");
  if (typeof platformPromotionVerifyEvidence !== "function") throw new TypeError("platform promotion evidence verifier is required");
  const normalizedPlatformPromotionLifecycle = normalizePlatformPromotionLifecycle(platformPromotionLifecycle);
  createManagedSignerProviderOperationMaintenanceWorker({
    ...managedSignerProviderOperationMaintenanceWorkerOptions,
    repository: { async maintainProviderOperations() { return { quarantined: 0, reconciled: 0, pruned: 0, total: 0 }; } }
  });
  let ownerRecoveryDeliveryBinding;
  if (ownerRecoveryPublisher !== undefined
    && (!ownerRecoveryPublisher || typeof ownerRecoveryPublisher.publish !== "function"
      || typeof ownerRecoveryPublisher.lookupAcceptance !== "function")) throw new TypeError("owner recovery publisher is invalid");
  try { ownerRecoveryDeliveryBinding = ownerRecoveryPublisher === undefined ? undefined : normalizeOwnerRecoveryDeliveryBinding(ownerRecoveryPublisher.binding); }
  catch { throw new TypeError("owner recovery publisher binding is invalid"); }
  const auditCursorSecret = exactSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET, "AGENTPASS_HUMAN_CURSOR_SECRET");
  const capabilityNonceSecret = exactSecret(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "AGENTPASS_CAPABILITY_NONCE_SECRET");
  const config = loadPostgresConfig(env);
  const poolOptions = (connectionString, max) => ({ connectionString, ssl: { rejectUnauthorized: true }, max, connectionTimeoutMillis: config.connectionTimeoutMs, idleTimeoutMillis: config.idleTimeoutMs, statement_timeout: config.statementTimeoutMs, lock_timeout: config.lockTimeoutMs, query_timeout: config.statementTimeoutMs + 1_000, allowExitOnIdle: false });
  const pool = new PoolClass(poolOptions(config.connectionString, config.maxConnections));
  const migrationPool = new MigrationPoolClass(poolOptions(config.migrationConnectionString, 2));
  const signerPool = new SignerPoolClass(poolOptions(config.signerConnectionString, config.signerMaxConnections));
  let migrationRunner;
  let migrations;
  let client;
  let migrationClientReleased = false;
  let poolEndPromise;
  let migrationPoolEndPromise;
  let signerPoolEndPromise;
  let ownerRecoveryOutboxWorker;
  let ownerRecoveryOutboxRepository;
  let sharedControlMaintenanceWorker;
  let providerOperationMaintenanceWorker;
  let refreshHintNotifier;

  function releaseMigrationClient(destroy = false) {
    if (migrationClientReleased) return;
    migrationClientReleased = true;
    client?.release?.(destroy);
  }

  function endPoolOnce() {
    if (poolEndPromise === undefined) {
      poolEndPromise = Promise.resolve().then(() => pool.end());
    }
    return poolEndPromise;
  }

  function endMigrationPoolOnce() {
    if (migrationPoolEndPromise === undefined) migrationPoolEndPromise = Promise.resolve().then(() => migrationPool.end());
    return migrationPoolEndPromise;
  }

  function endSignerPoolOnce() {
    if (signerPoolEndPromise === undefined) signerPoolEndPromise = Promise.resolve().then(() => signerPool.end());
    return signerPoolEndPromise;
  }

  async function cleanupConstructionFailure() {
    // Cleanup is deliberately best effort: the construction error is the
    // stable public failure and must never be replaced by a close error.
    const closers = [
      [sharedControlMaintenanceWorker, (worker) => worker.close({ timeoutMs: 0 })],
      [ownerRecoveryOutboxWorker, (worker) => worker.close({ timeout_ms: 0 })],
      [refreshHintNotifier, (notifier) => notifier.close()],
      [providerOperationMaintenanceWorker, (worker) => worker.close({ timeoutMs: 0 })]
    ];
    for (const [resource, close] of closers) {
      if (!resource) continue;
      try { await close(resource); } catch { /* preserve the original construction error */ }
    }
    try { releaseMigrationClient(true); } catch { /* preserve the original construction error */ }
    try { await endMigrationPoolOnce(); } catch { /* preserve the original construction error */ }
    try { await endSignerPoolOnce(); } catch { /* preserve the original construction error */ }
    try { await endPoolOnce(); } catch { /* preserve the original construction error */ }
  }

  try {
    migrations = await loadSqlMigrations();
    migrationRunner = createMigrationRunner({ client: pool, applicationVersion, migrations });
    client = await migrationPool.connect();
    await client.query("SELECT set_config('statement_timeout', $1, false)", [`${config.statementTimeoutMs}ms`]);
    await client.query("SELECT set_config('lock_timeout', $1, false)", [`${config.lockTimeoutMs}ms`]);
    await createMigrationRunner({ client, applicationVersion, migrations }).run();
    releaseMigrationClient();
    await endMigrationPoolOnce();
  } catch (error) {
    await cleanupConstructionFailure();
    throw error;
  }

  try {
    releaseMigrationClient();
  let closed = false;
  let closePoolPromise;
  const drainController = createDrainController();
  const operationalMetrics = createOperationalMetrics();
  const providerOperationMaintenanceRepository = createPostgresProviderOperationMaintenanceRepository({ client: signerPool });
  providerOperationMaintenanceWorker = createManagedSignerProviderOperationMaintenanceWorker({
    firstCycleDelayMs: 5_000,
    intervalMs: 30_000,
    maintenanceLimit: 1_000,
    closeTimeoutMs: 10_000,
    ...managedSignerProviderOperationMaintenanceWorkerOptions,
    repository: providerOperationMaintenanceRepository,
    metrics: operationalMetrics
  });
  refreshHintNotifier = createPostgresRefreshHintNotifier({ pool, metrics: operationalMetrics });
  const operationalHealth = createOperationalHealth({
    pool,
    maxConnections: config.maxConnections,
    schemaHead: POSTGRES_SCHEMA_HEAD,
    migrationStatus: () => migrationRunner.status(),
    metrics: operationalMetrics,
    drainController,
    providerOperationStatus: async () => {
      const health = await providerOperationMaintenanceRepository.health();
      const worker = providerOperationMaintenanceWorker.snapshot();
      return Object.freeze({
        ...health,
        worker_state: worker.state,
        worker_cycles: worker.cycles,
        consecutive_failures: worker.consecutive_failures,
        last_success_at: worker.last_success_at
      });
    },
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
      await endSignerPoolOnce();
      await endPoolOnce();
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
    drainController.beginDrain();
    const workerDrain = ownerRecoveryOutboxWorker?.drain({ timeout_ms: timeoutMs });
    const maintenanceDrain = sharedControlMaintenanceWorker?.close({ timeoutMs });
    const providerOperationMaintenanceDrain = providerOperationMaintenanceWorker?.close({ timeoutMs });
    return drainController.drain({
      ...options,
      timeoutMs,
      close: async () => {
        const workerResult = await workerDrain;
        if (workerResult && workerResult.drained !== true) throw Object.assign(new Error("Owner recovery outbox worker drain timed out"), { code: "owner_recovery_outbox_worker_drain_timeout" });
        const maintenanceResult = await maintenanceDrain;
        if (maintenanceResult && maintenanceResult.drained !== true) throw Object.assign(new Error("Shared-control maintenance worker drain timed out"), { code: "shared_control_maintenance_worker_drain_timeout" });
        const providerOperationMaintenanceResult = await providerOperationMaintenanceDrain;
        if (providerOperationMaintenanceResult && providerOperationMaintenanceResult.drained !== true) throw Object.assign(new Error("Managed signer provider-operation maintenance worker drain timed out"), { code: "managed_signer_provider_operation_maintenance_worker_drain_timeout" });
        await closePool();
      }
    });
  }
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
  }
  const agentSessionAuthorityRepository = createAgentSessionAuthorityRepository({ client: pool });
  const sharedControlRepository = createSharedControlRepository({ client: pool });
  sharedControlMaintenanceWorker = createSharedControlMaintenanceWorker({
    ...sharedControlMaintenanceWorkerOptions,
    repository: sharedControlRepository,
    metrics: operationalMetrics
  });
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
  const auditExportSnapshotReader = createPostgresAuditExportSnapshotReader();
  const auditExportIssuanceRepository = createPostgresAuditExportIssuanceRepository({
    client: pool,
    snapshotReader: auditExportSnapshotReader
  });
  const platformPromotionIssuanceRepository = createPostgresPlatformPromotionIssuanceRepository({
    // Reservation authorization runs on the application pool through 0054,
    // while post-signature commit/uncertain transitions use the purpose-scoped
    // signer role. The application credential therefore cannot execute the
    // legacy promotion mutation functions directly.
    client: signerPool,
    verifyEvidence: platformPromotionVerifyEvidence,
    ...(normalizedPlatformPromotionLifecycle ?? {})
  });
  const createBoundPlatformAuthorizationRepository = (lifecycle) => {
    const binding = normalizePlatformPromotionLifecycle(lifecycle);
    if (binding === undefined) throw new TypeError("platform promotion lifecycle configuration is invalid");
    return createPostgresPlatformAuthorizationRepository({
      client: pool,
      promotionRepository: platformPromotionIssuanceRepository,
      verifyEvidence: platformPromotionVerifyEvidence,
      ...binding
    });
  };
  const platformAuthorizationRepository = normalizedPlatformPromotionLifecycle === undefined
    ? undefined
    : createBoundPlatformAuthorizationRepository(normalizedPlatformPromotionLifecycle);
  const platformOperatorAssignmentRepository = createPostgresPlatformOperatorAssignmentRepository({ client: pool });
  const platformSessionRepository = createPostgresPlatformSessionRepository({ client: pool });
  const platformSessionWebAuthnRepository = createPostgresPlatformSessionWebAuthnRepository({ client: pool });
  const platformSessionBootstrapRepository = createPostgresPlatformSessionBootstrapRepository({ client: pool });
  const hostedIdentityBootstrapRepository = createPostgresHostedIdentityBootstrapRepository({ client: pool });
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
  const runtime = Object.freeze({
    pool,
    humanRepository: createPostgresHumanRepository({ client: pool, onAuthorityReduction }),
    organizationRepository,
    capabilityAuthorityRepository,
    agentSessionAuthorityRepository: agentSessionConsumptionRepository,
    agentSessionConsumptionRepository,
    agentSessionLifecycleRepository,
    ...(agentSessionIssuanceRepository ? { agentSessionIssuanceRepository } : {}),
    qualificationGrantBatchRepository,
    auditExportIssuanceRepository,
    platformPromotionIssuanceRepository,
    ...(platformAuthorizationRepository ? { platformAuthorizationRepository } : {}),
    // The active managed-signer key/lifecycle is authoritative only after the
    // hosted KMS binding has loaded PostgreSQL state. Bind the authorization
    // adapter at that point without creating another pool or issuance path.
    createPlatformAuthorizationRepository: createBoundPlatformAuthorizationRepository,
    platformOperatorAssignmentRepository,
    platformSessionRepository,
    platformSessionWebAuthnRepository,
    platformSessionBootstrapRepository,
    hostedIdentityBootstrapRepository,
    createManagedSignerKeyLifecycleRepository: (options = {}) => createPostgresManagedSignerKeyLifecycleRepository({ ...options, client: signerPool }),
    createProviderOperationRepository: (options = {}) => createPostgresProviderOperationRepository({ ...options, client: signerPool }),
    providerOperationMaintenanceRepository,
    providerOperationMaintenanceWorker,
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
  if (ownerRecoveryOutboxAutoStart) ownerRecoveryOutboxWorker?.start();
  if (sharedControlMaintenanceAutoStart) sharedControlMaintenanceWorker.start();
  if (managedSignerProviderOperationMaintenanceAutoStart) {
    await providerOperationMaintenanceWorker.runOnce();
    providerOperationMaintenanceWorker.start();
  }
  return runtime;
  } catch (error) {
    await cleanupConstructionFailure();
    throw error;
  }
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
  const appConfig = loadPostgresAppConfig(env);
  const app = new URL(appConfig.connectionString);
  const migration = postgresRoleUrl(env.AGENTPASS_MIGRATION_DATABASE_URL, "AGENTPASS_MIGRATION_DATABASE_URL");
  const signer = postgresRoleUrl(env.AGENTPASS_SIGNER_DATABASE_URL, "AGENTPASS_SIGNER_DATABASE_URL");
  const appTarget = postgresTarget(app);
  if (postgresTarget(migration) !== appTarget || postgresTarget(signer) !== appTarget) throw new TypeError("PostgreSQL role databases must target the same authority database");
  if (new Set([app.username, migration.username, signer.username]).size !== 3) throw new TypeError("PostgreSQL app, migration, and signer roles must be distinct");
  return Object.freeze({
    ...appConfig,
    migrationConnectionString: migration.toString(),
    signerConnectionString: signer.toString(),
    signerMaxConnections: integer(env.AGENTPASS_SIGNER_DATABASE_MAX_CONNECTIONS ?? "4", 2, 50)
  });
}

export function loadPostgresAppConfig(env = {}) {
  const app = postgresRoleUrl(env.AGENTPASS_DATABASE_URL, "AGENTPASS_DATABASE_URL");
  return Object.freeze({
    connectionString: app.toString(),
    maxConnections: integer(env.AGENTPASS_DATABASE_MAX_CONNECTIONS ?? "10", 2, 100),
    connectionTimeoutMs: integer(env.AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS ?? "5000", 250, 30_000),
    idleTimeoutMs: integer(env.AGENTPASS_DATABASE_IDLE_TIMEOUT_MS ?? "30000", 1_000, 300_000),
    statementTimeoutMs: integer(env.AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS ?? "8000", 250, 60_000),
    lockTimeoutMs: integer(env.AGENTPASS_DATABASE_LOCK_TIMEOUT_MS ?? "2000", 100, 30_000)
  });
}

function postgresRoleUrl(raw, name) {
  let url;
  try { url = new URL(raw); } catch { throw new TypeError(`${name} is invalid`); }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash) throw new TypeError(`${name} is invalid`);
  const parameters = [...url.searchParams.entries()];
  if (parameters.length !== 1 || parameters[0][0] !== "sslmode" || parameters[0][1] !== "verify-full") {
    throw new TypeError("PostgreSQL sslmode=verify-full is required and must be the only connection parameter");
  }
  return url;
}

function postgresTarget(url) { return `${url.hostname.toLowerCase()}:${url.port || "5432"}${url.pathname}`; }

function integer(value, min, max) { if (typeof value !== "string" || !/^\d+$/.test(value)) throw new TypeError("PostgreSQL timeout/limit is invalid"); const result=Number(value); if(!Number.isSafeInteger(result)||result<min||result>max) throw new TypeError("PostgreSQL timeout/limit is invalid"); return result; }

function exactSecret(value, name) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new TypeError(`${name} must be an exact 32-byte base64url secret`); const bytes=Buffer.from(value,"base64url"); if(bytes.length!==32||bytes.toString("base64url")!==value) throw new TypeError(`${name} must be an exact 32-byte base64url secret`); return bytes; }

function normalizePlatformPromotionLifecycle(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("platform promotion lifecycle configuration is invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || keys.some((key) => typeof key !== "string")
    || !keys.every((key) => ["keyId", "keyVersion", "lifecycleVersion"].includes(key))) {
    throw new TypeError("platform promotion lifecycle configuration is invalid");
  }
  if (keys.some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return !descriptor || descriptor.enumerable !== true || !("value" in descriptor);
  })) throw new TypeError("platform promotion lifecycle configuration is invalid");
  const { keyId, keyVersion, lifecycleVersion } = value;
  if (typeof keyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/u.test(keyId)
    || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1) {
    throw new TypeError("platform promotion lifecycle configuration is invalid");
  }
  return Object.freeze({ keyId, keyVersion, lifecycleVersion });
}
