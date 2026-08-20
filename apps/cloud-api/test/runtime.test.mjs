import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createCloudRuntime, createHostedRateLimiter, loadRuntimeConfig } from "../src/runtime.mjs";
import { createCloudStore } from "../src/store.mjs";
import { createManagedSignerRepositoryFactory, createProviderOperationRepositoryFactory } from "./support/managed-signer-repository.mjs";

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
  const ownerRecoveryNotificationAuthorizationPath = path.join(root, "owner-recovery-notification-authorization");
  const token = generateApiToken();
  const records = [createApiTokenRecord({ token, organizationId: crypto.randomUUID(), memberId: crypto.randomUUID(), role: "owner" })];
  const keys = crypto.generateKeyPairSync("ed25519");
  const refreshKeys = crypto.generateKeyPairSync("ed25519");
  const agentSessionKeys = crypto.generateKeyPairSync("ed25519");
  const qualificationManifestKeys = crypto.generateKeyPairSync("ed25519");
  const possessionReceiptKeys = crypto.generateKeyPairSync("ed25519");
  const controlBundleKeys = crypto.generateKeyPairSync("ed25519");
  const capabilityKeys = crypto.generateKeyPairSync("ed25519");
  const auditAnchorKeys = crypto.generateKeyPairSync("ed25519");
  const promotionEvidenceKeys = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(tokenRecordsPath, JSON.stringify(records), { mode: 0o600 });
  fs.writeFileSync(bundlePrivateKeyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(identityPublicKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(refreshPrivateKeyPath, refreshKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(refreshNonceKeyringPath, JSON.stringify({ version: 1, active_key_id: "refresh-nonce-v1", keys: { "refresh-nonce-v1": Buffer.alloc(32, 0x35).toString("base64url") } }), { mode: 0o600 });
  fs.writeFileSync(agentSessionProcessPoliciesPath, JSON.stringify({ version: 1, policies: [{ policy_id: "claude-code-v1", release_id: "agentpass-0.18.0", agent_kind: "claude-code", adapter_id: "11111111-1111-4111-8111-111111111111", adapter_versions: ["1.0.0"], status: "enabled" }] }), { mode: 0o600 });
  fs.writeFileSync(ownerRecoveryNotificationAuthorizationPath, "notification-authorization-test-value", { mode: 0o600 });
  return { root, identityPublicKeyPath, refreshPrivateKeyPath, refreshNonceKeyringPath, agentSessionProcessPoliciesPath, ownerRecoveryNotificationAuthorizationPath, refreshKeys, agentSessionKeys, qualificationManifestKeys, possessionReceiptKeys, controlBundleKeys, capabilityKeys, auditAnchorKeys, promotionEvidenceKeys, env: { AGENTPASS_CLOUD_PROFILE: "evaluation", AGENTPASS_CLOUD_DATA_DIR: dataDir, AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: tokenRecordsPath, AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: bundlePrivateKeyPath, AGENTPASS_CLOUD_PORT: "0" } };
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
  const notification = loadRuntimeConfig(humanEnv).ownerRecoveryNotification;
  assert.deepEqual(notification, {
    webhookUrl: "https://notifications.example.test/owner-recovery",
    confirmationUrl: "https://notifications.example.test/owner-recovery/acceptance",
    authorizationSecretPath: value.ownerRecoveryNotificationAuthorizationPath,
    bindingId: "owner-recovery-primary",
    bindingKeyVersion: 1,
    bindingDigest: "a".repeat(64)
  });
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_WEBAUTHN_RP_ID: "other.test" }), /Human Auth configuration is invalid/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_CURSOR_SECRET: undefined }), /requires complete PostgreSQL/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_CURSOR_SECRET: "A".repeat(42) }), /Human Auth configuration is invalid/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_AUTH_SECRET: undefined }), /requires complete PostgreSQL/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_HUMAN_AUTH_SECRET: "A".repeat(42) }), /Human Auth configuration is invalid/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH: undefined }), /requires complete PostgreSQL/);
  assert.throws(() => loadRuntimeConfig({ ...humanEnv, AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "A".repeat(64) }), /requires complete PostgreSQL|binding is invalid/);
  const withoutNotifications = {
    ...humanEnv,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL: undefined,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL: undefined,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH: undefined,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID: undefined,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: undefined,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: undefined
  };
  await assert.rejects(createCloudRuntime({ env: withoutNotifications, agentSessionSignerProvider: signerProvider(value), qualificationManifestSignerProvider: qualificationSignerProvider(value) }), /requires complete PostgreSQL/);
});

test("production human auth is composed from PostgreSQL and closed with the runtime", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = hostedEnv(value);
  const calls = [];
  const controlPlaneStore = await createCloudStore({ dataDir: path.join(value.root, "hosted-test-store"), auditCursorSecret: Buffer.from(CURSOR_SECRET, "base64url") });
  const hostedControlPlaneStore = new Proxy(controlPlaneStore, { get(target, property, receiver) { if (property === "pollDeviceRefresh") return async () => null; if (property === "markDeviceRefreshDelivered") return async () => {}; return Reflect.get(target, property, receiver); } });
  const postgresRuntime = { pool: {}, humanRepository: {}, controlPlaneStore: hostedControlPlaneStore, refreshHintNotifier: { async waitForRefresh() { return false; } }, sharedControlRepository: { async consumeDeviceRequestNonce() { return { accepted: true }; }, async acquireRateLimit() { return { allowed: true, limit: 120, remaining: 119, retryAfterMs: 0, retryAfterSeconds: 0, resetAt: Date.now() }; }, async acquireAnonymousRateLimit() { return { allowed: true, limit: 120, remaining: 119, retryAfterMs: 0, retryAfterSeconds: 0, resetAt: Date.now() }; } }, capabilityAuthorityRepository: { async issueCapabilityMetadata() {}, async listRevokedCapabilityIds() { return []; } }, agentSessionIssuanceRepository: { async issueAgentSessionGrant() {} }, agentSessionAuthorityRepository: { async consumeAgentSessionGrant() {} }, qualificationGrantBatchRepository: { async claimQualificationGrantBatch() {} }, auditExportIssuanceRepository: { async reserveAuditExport() {}, async commitAuditExport() {}, async replayAuditExport() {}, async markAuditExportUncertain() {}, async getAuditExportPayload() {}, async getCommittedAuditExport() {} }, createManagedSignerKeyLifecycleRepository: createManagedSignerRepositoryFactory(), createProviderOperationRepository: createProviderOperationRepositoryFactory(), async readiness() { return readyDatabaseReport(); }, async close() { calls.push("postgres-close"); await controlPlaneStore.close(); } };
  const recentAuthService = { async authorize() { return { verified: false }; } };
  const humanSession = { async authenticateRequest() { return { session: {} }; } };
  let signerHealthy = true;
  let qualificationSignerHealthy = true;
  let possessionSignerHealthy = true;
  let refreshSignerHealthy = true;
  const provider = signerProvider(value);
  const publicKeyMetadata = provider.publicKeyMetadata;
  provider.publicKeyMetadata = async (input) => {
    if (!signerHealthy) throw new Error("simulated provider outage");
    return publicKeyMetadata(input);
  };
  const qualificationProvider = qualificationSignerProvider(value);
  const ownerRecoveryPublisher = { async publish() { return { accepted: true, duplicate: false }; }, async lookupAcceptance() { return { accepted: false }; } };
  const qualificationPublicKeyMetadata = qualificationProvider.publicKeyMetadata;
  qualificationProvider.publicKeyMetadata = async (input) => {
    if (!qualificationSignerHealthy) throw new Error("simulated qualification provider outage");
    return qualificationPublicKeyMetadata(input);
  };
  const possessionProvider = possessionSignerProvider(value);
  const possessionPublicKeyMetadata = possessionProvider.publicKeyMetadata;
  possessionProvider.publicKeyMetadata = async (input) => {
    if (!possessionSignerHealthy) throw new Error("simulated possession provider outage");
    return possessionPublicKeyMetadata(input);
  };
  const refreshProvider = refreshSignerProvider(value);
  const refreshPublicKeyMetadata = refreshProvider.publicKeyMetadata;
  refreshProvider.publicKeyMetadata = async (input) => {
    if (!refreshSignerHealthy) throw new Error("simulated refresh provider outage");
    return refreshPublicKeyMetadata(input);
  };
  const runtime = await createCloudRuntime({ env, logger: { info() {} }, kmsProviderFactory: async () => { calls.push("kms"); return { agentSessionSignerProvider: provider, qualificationManifestSignerProvider: qualificationProvider, possessionReceiptSignerProvider: possessionProvider, refreshHintSignerProvider: refreshProvider, controlBundleSignerProvider: purposeProvider(value.controlBundleKeys, 2), capabilitySignerProvider: purposeProvider(value.capabilityKeys, 1), auditAnchorSignerProvider: purposeProvider(value.auditAnchorKeys, 1), promotionEvidenceSignerProvider: purposeProvider(value.promotionEvidenceKeys, 3), async close() { calls.push("kms-close"); } }; }, ownerRecoveryPublisher, postgresFactory: async (input) => { calls.push(["postgres", input.applicationVersion, typeof input.refreshNonceCodec?.derive, typeof input.resolveProcessBindingPolicy, input.ownerRecoveryPublisher]); return postgresRuntime; }, humanAuthFactory: (input) => { calls.push(["human", input.origin, input.rpId, input.cursorSecret, input.securitySecret, input.signedConsoleIdentity, input.agentSessionSigner, input.qualificationManifestSigner]); return { api: { async handle() { return { status: 404, body: { error: { code: "not_found", message: "Resource not found" } }, headers: {} }; } }, humanSession, recentAuthService }; } });
  assert.equal(runtime.postgresRuntime, postgresRuntime);
  assert.equal(runtime.humanAuthRuntime.recentAuthService, recentAuthService);
  assert.deepEqual(calls[0], ["postgres", "0.18.0", "function", "function", ownerRecoveryPublisher]);
  assert.equal(calls[1], "kms");
  assert.deepEqual(calls[2].slice(0, 4), ["human", "https://console.example.test", "example.test", CURSOR_SECRET]);
  assert.equal(Buffer.from(calls[2][4]).toString("base64url"), env.AGENTPASS_HUMAN_AUTH_SECRET);
  assert.equal(calls[2][5].issuer, "agentpass-console");
  assert.equal(calls[2][5].audience, "agentpass-cloud-session");
  assert.equal(calls[2][5].keyId, "console-2026-08");
  assert.match(calls[2][5].publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(typeof calls[2][6].signAgentSessionGrant, "function");
  assert.equal(typeof calls[2][7].signQualificationGrantBatchManifest, "function");
  assert.equal(typeof runtime.auditAnchorSigner.signAuditAnchor, "function");
  assert.equal(runtime.auditAnchorSigner.key_id, env.AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID);
  assert.equal(typeof runtime.auditExportIssuanceService.issueAuditExport, "function");
  assert.equal(typeof runtime.auditExportIssuanceService.replayAuditExport, "function");
  assert.equal(typeof runtime.auditExportIssuanceService.retrieveAuditExport, "function");
  assert.equal(typeof runtime.promotionEvidenceSigner.signPromotionEvidence, "function");
  assert.equal(runtime.promotionEvidenceSigner.key_id, env.AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID);
  assert.equal(runtime.config.auditAnchorTimeoutMs, 5_000);
  assert.equal(runtime.config.promotionEvidenceTimeoutMs, 5_000);
  assert.equal(Object.hasOwn(runtime.config.humanAuth, "cursorSecret"), false);
  assert.equal(runtime.config.tokenRecordsPath, null);
  assert.equal(JSON.stringify(runtime.config).includes(CURSOR_SECRET), false);
  assert.equal(JSON.stringify(runtime.config).includes(env.AGENTPASS_HUMAN_AUTH_SECRET), false);
  const address = await runtime.listen();
  const probeHeaders = { "AgentPass-Operational-Token": env.AGENTPASS_OPERATIONAL_PROBE_SECRET };
  const ready = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(ready.status, 200);
  const readyBody = await ready.json();
  assert.equal(readyBody.checks.agent_session_signer.ok, true);
  assert.deepEqual(Object.keys(readyBody.checks).filter((key) => key.endsWith("_signer")).sort(), [
    "agent_session_signer",
    "audit_anchor_signer",
    "capability_signer",
    "control_bundle_signer",
    "possession_receipt_signer",
    "promotion_evidence_signer",
    "qualification_manifest_signer",
    "refresh_hint_signer"
  ]);
  for (const name of ["agent_session_signer", "audit_anchor_signer", "capability_signer", "control_bundle_signer", "possession_receipt_signer", "promotion_evidence_signer", "qualification_manifest_signer", "refresh_hint_signer"]) {
    assert.equal(readyBody.checks[name].ok, true);
    assert.equal(readyBody.checks[name].algorithm, "ed25519");
    assert.match(readyBody.checks[name].public_key_fingerprint, /^[0-9a-f]{64}$/u);
  }
  signerHealthy = false;
  const degraded = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(degraded.status, 503);
  const degradedBody = await degraded.json();
  assert.equal(degradedBody.code, "agent_session_signer_unavailable");
  assert.deepEqual(degradedBody.checks.agent_session_signer, { ok: false, purpose: "agentpass.agent-session-grant", algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
  signerHealthy = true;
  qualificationSignerHealthy = false;
  const qualificationDegraded = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(qualificationDegraded.status, 503);
  const qualificationDegradedBody = await qualificationDegraded.json();
  assert.equal(qualificationDegradedBody.code, "qualification_manifest_signer_unavailable");
  assert.deepEqual(qualificationDegradedBody.checks.qualification_manifest_signer, { ok: false, purpose: "agentpass.qualification-grant-batch-manifest", algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
  qualificationSignerHealthy = true;
  possessionSignerHealthy = false;
  const possessionDegraded = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(possessionDegraded.status, 503);
  const possessionDegradedBody = await possessionDegraded.json();
  assert.equal(possessionDegradedBody.code, "possession_receipt_signer_unavailable");
  assert.deepEqual(possessionDegradedBody.checks.possession_receipt_signer, { ok: false, purpose: "device-enrollment-possession-receipt", algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
  possessionSignerHealthy = true;
  refreshSignerHealthy = false;
  const refreshDegraded = await fetch(`http://127.0.0.1:${address.port}/health/ready`, { headers: probeHeaders });
  assert.equal(refreshDegraded.status, 503);
  assert.equal((await refreshDegraded.json()).code, "refresh_hint_signer_unavailable");
  await runtime.close();
  assert.equal(calls.includes("postgres-close"), true);
  assert.equal(calls.includes("kms-close"), true);
  assert.equal(calls.indexOf("postgres-close") < calls.indexOf("kms-close"), true, "KMS clients close only after tracked PostgreSQL work drains");
});

test("production human auth fails closed without PostgreSQL capability authority", async (t) => {
  const value = files();
  t.after(() => fs.rmSync(value.root, { recursive: true, force: true }));
  const env = hostedEnv(value);
  let closed = false;
  await assert.rejects(createCloudRuntime({
    env,
    ownerRecoveryPublisher: { async publish() { return { accepted: true, duplicate: false }; }, async lookupAcceptance() { return { accepted: false }; } },
    agentSessionSignerProvider: signerProvider(value),
    qualificationManifestSignerProvider: qualificationSignerProvider(value),
    possessionReceiptSignerProvider: possessionSignerProvider(value),
    refreshHintSignerProvider: refreshSignerProvider(value),
    postgresFactory: async () => ({ pool: {}, humanRepository: {}, async close() { closed = true; } }),
    humanAuthFactory: () => { throw new Error("human auth must not be constructed"); }
  }), /capability authority is unavailable/);
  assert.equal(closed, true);
});

test("hosted rate limiter uses shared tenant buckets only for authenticated UUID pairs", async () => {
  const calls = [];
  const repository = {
    async acquireRateLimit(input) { calls.push({ kind: "tenant", input }); return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterSeconds: 0, resetAt: Date.now() }; },
    async acquireAnonymousRateLimit(input) { calls.push({ kind: "anonymous", input }); return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterSeconds: 0, resetAt: Date.now() }; }
  };
  const limiter = createHostedRateLimiter(repository, { secret: Buffer.alloc(32, 0x43) });
  const organizationId = "11111111-1111-4111-8111-111111111111";
  const memberId = "22222222-2222-4222-8222-222222222222";
  await limiter.acquire({ tenantId: organizationId, principalType: "human", principalId: memberId });
  assert.equal(calls[0].kind, "tenant");
  assert.deepEqual(calls[0].input, { organizationId, principalType: "human", principalId: memberId, capacity: 120, refillPerSecond: 2, cost: 1 });
});

test("hosted rate limiter maps malformed transport scopes to fixed HMAC anonymous buckets", async () => {
  const calls = [];
  const anonymousAttempts = new Map();
  const repository = {
    async acquireRateLimit(input) { calls.push({ kind: "tenant", input }); return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterSeconds: 0, resetAt: Date.now() }; },
    async acquireAnonymousRateLimit(input) {
      calls.push({ kind: "anonymous", input });
      const attempt = (anonymousAttempts.get(input.principalId) ?? 0) + 1;
      anonymousAttempts.set(input.principalId, attempt);
      return { allowed: attempt === 1, limit: input.capacity, remaining: attempt === 1 ? input.capacity - 1 : 0, retryAfterSeconds: attempt === 1 ? 0 : 1, resetAt: Date.now() };
    }
  };
  const secret = Buffer.alloc(32, 0x43);
  const first = createHostedRateLimiter(repository, { secret });
  const second = createHostedRateLimiter(repository, { secret: Buffer.from(secret) });
  await first.acquire({ tenantId: "attacker-controlled-tenant", principalType: "human", principalId: "attacker-controlled-principal" });
  const restartedDecision = await second.acquire({ tenantId: "another-tenant", principalType: "human", principalId: "another-principal" });
  await first.acquire({ tenantId: "attacker-controlled-tenant", principalType: "device", principalId: "attacker-controlled-principal" });
  assert.equal(calls.length, 3);
  assert.equal(calls.every(({ kind }) => kind === "anonymous"), true);
  assert.equal(calls[0].input.operation, "cloud.transport.human");
  assert.equal(calls[1].input.operation, "cloud.transport.human");
  assert.equal(calls[2].input.operation, "cloud.transport.device");
  assert.equal(restartedDecision.allowed, false, "a new process must observe the shared bucket state");
  assert.equal(calls[0].input.principalId, calls[1].input.principalId);
  assert.notEqual(calls[0].input.principalId, calls[2].input.principalId);
  assert.match(calls[0].input.principalId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.notEqual(calls[0].input.principalId, "attacker-controlled-principal");
  const differentSecretCalls = [];
  const differentSecretRepository = { async acquireRateLimit() {}, async acquireAnonymousRateLimit(input) { differentSecretCalls.push(input); return { allowed: true, limit: 120, remaining: 119, retryAfterSeconds: 0, resetAt: Date.now() }; } };
  await createHostedRateLimiter(differentSecretRepository, { secret: Buffer.alloc(32, 0x44) }).acquire({ tenantId: "bad", principalType: "human", principalId: "bad" });
  assert.notEqual(calls[0].input.principalId, differentSecretCalls[0].principalId);
});

test("hosted rate limiter requires shared anonymous controls and propagates outage", async () => {
  assert.throws(() => createHostedRateLimiter({ async acquireRateLimit() {} }, { secret: Buffer.alloc(32) }), /PostgreSQL shared rate limiter is unavailable/);
  const outage = new Error("database unavailable");
  const limiter = createHostedRateLimiter({ async acquireRateLimit() {}, async acquireAnonymousRateLimit() { throw outage; } }, { secret: Buffer.alloc(32, 0x43) });
  await assert.rejects(limiter.acquire({ tenantId: "bad", principalType: "human", principalId: "bad" }), (error) => error === outage);
});

function hostedEnv(value) {
  return {
    ...value.env,
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_DATA_DIR: undefined,
    AGENTPASS_CLOUD_TOKEN_RECORDS_PATH: undefined,
    AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH: undefined,
    AGENTPASS_DATABASE_URL: "postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full",
    AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test",
    AGENTPASS_WEBAUTHN_RP_ID: "example.test",
    AGENTPASS_HUMAN_CURSOR_SECRET: CURSOR_SECRET,
    AGENTPASS_HUMAN_AUTH_SECRET: Buffer.alloc(32, 0x43).toString("base64url"),
    AGENTPASS_CAPABILITY_NONCE_SECRET: Buffer.alloc(32, 0x33).toString("base64url"),
    AGENTPASS_OPERATIONAL_PROBE_SECRET: Buffer.alloc(32, 0x34).toString("base64url"),
    AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-console",
    AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-cloud-session",
    AGENTPASS_IDENTITY_ASSERTION_KID: "console-2026-08",
    AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH: value.identityPublicKeyPath,
    AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY: value.refreshKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_REFRESH_KEY_ID: "refresh-2026-08",
    AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH: value.refreshNonceKeyringPath,
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: value.agentSessionKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH: value.agentSessionProcessPoliciesPath,
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "qualification-manifest-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: value.qualificationManifestKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "possession-receipt-2026-08",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: value.possessionReceiptKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID: "control-bundle-2026-08",
    AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY: value.controlBundleKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_CAPABILITY_KEY_ID: "capability-2026-08",
    AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY: value.capabilityKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID: "audit-anchor-2026-08",
    AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY: value.auditAnchorKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID: "promotion-evidence-2026-08",
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY: value.promotionEvidenceKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS: "5000",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL: "https://notifications.example.test/owner-recovery",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL: "https://notifications.example.test/owner-recovery/acceptance",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH: value.ownerRecoveryNotificationAuthorizationPath,
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID: "owner-recovery-primary",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION: "1",
    AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST: "a".repeat(64)
  };
}

function signerProvider(value) {
  const publicKey = value.agentSessionKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    provider_id: "test-kms-ledger-v1",
    version: 1,
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, value.agentSessionKeys.privateKey); }
  };
}

function qualificationSignerProvider(value) {
  const publicKey = value.qualificationManifestKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    provider_id: "test-kms-ledger-v1",
    version: 2,
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, value.qualificationManifestKeys.privateKey); }
  };
}

function possessionSignerProvider(value) {
  const publicKey = value.possessionReceiptKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    provider_id: "test-kms-ledger-v1",
    version: 1,
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, value.possessionReceiptKeys.privateKey); }
  };
}

function refreshSignerProvider(value) {
  const publicKey = value.refreshKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    provider_id: "test-kms-ledger-v1",
    version: 1,
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, value.refreshKeys.privateKey); }
  };
}

function purposeProvider(keys, version = 1) {
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    provider_id: "test-kms-ledger-v1",
    version,
    async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, keys.privateKey); }
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
