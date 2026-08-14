import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { createCloudApi } from "./server.mjs";
import { createCloudStore } from "./store.mjs";
import { createPersistentReplayCache, verifyDeviceRequest } from "./auth.mjs";
import { createRateLimiter } from "./rate-limit.mjs";
import { createPostgresRuntime } from "./postgres/runtime.mjs";
import { createHumanAuthRuntime } from "./human-auth/runtime.mjs";
import { parseCloudRuntimeProfile } from "./runtime-profile.mjs";
import { createRefreshHintService } from "./refresh-hint-service.mjs";
import { createEd25519RefreshHintSigner } from "./refresh-hint-signer.mjs";
import { createRefreshNonceCodec } from "./postgres/refresh-nonce-codec.mjs";
import { createHostedAgentSessionGrantSigner } from "./agent-session-signer-config.mjs";
import { createProcessBindingPolicyRegistry } from "./process-binding-policy-registry.mjs";
import { createAgentSessionDeviceApi } from "./agent-session-device-api.mjs";
import { createQualificationGrantBatchDeviceApi } from "./qualification-grant-batch-device-api.mjs";
import { createHostedQualificationManifestSigner } from "./qualification-manifest-signer-config.mjs";
import { createOwnerRecoveryNotificationPublisher } from "./postgres/owner-recovery-notification-publisher.mjs";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export async function createCloudRuntime({ env = process.env, logger = console, postgresFactory = createPostgresRuntime, humanAuthFactory = createHumanAuthRuntime, agentSessionSignerProvider, agentSessionSignerFactory = createHostedAgentSessionGrantSigner, qualificationManifestSignerProvider, qualificationManifestSignerFactory = createHostedQualificationManifestSigner, ownerRecoveryPublisher } = {}) {
  const profile = parseCloudRuntimeProfile(env);
  const config = loadRuntimeConfig(env);
  const configuredOwnerRecoveryPublisher = profile.isHosted
    ? ownerRecoveryPublisher ?? createConfiguredOwnerRecoveryPublisher(config.ownerRecoveryNotification)
    : undefined;
  const tokenRecords = profile.isHosted ? [] : readProtectedJson(config.tokenRecordsPath, "token records", 1024 * 1024);
  if (!Array.isArray(tokenRecords) || tokenRecords.length > 256 || (!config.humanAuth && tokenRecords.length < 1)) throw new Error("Cloud token records are invalid");
  const privateKeyPEM = readProtectedFile(config.bundlePrivateKeyPath, "bundle private key", 16 * 1024).toString("utf8");
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateKeyPEM); } catch { throw new Error("Cloud bundle private key is invalid"); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Cloud bundle private key must be Ed25519");
  let refreshHintSigner;
  let refreshNonceCodec;
  let agentSessionSigner;
  let qualificationManifestSigner;
  let processBindingPolicies;
  if (profile.isHosted) {
    const refreshPrivateKeyPEM = readProtectedFile(config.refreshPrivateKeyPath, "refresh private key", 16 * 1024).toString("utf8");
    let refreshPrivateKey;
    try { refreshPrivateKey = crypto.createPrivateKey(refreshPrivateKeyPEM); } catch { throw new Error("Cloud refresh private key is invalid"); }
    if (refreshPrivateKey.asymmetricKeyType !== "ed25519") throw new Error("Cloud refresh private key must be Ed25519");
    const bundlePublic = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
    const refreshPublic = crypto.createPublicKey(refreshPrivateKey).export({ type: "spki", format: "der" });
    if (bundlePublic.equals(refreshPublic)) throw new Error("Cloud refresh key must be purpose-separated from the bundle key");
    refreshHintSigner = createEd25519RefreshHintSigner({ privateKey: refreshPrivateKey, keyId: config.refreshKeyId });
    refreshNonceCodec = loadRefreshNonceCodec(config.refreshNonceKeyringPath);
    processBindingPolicies = createProcessBindingPolicyRegistry(readProtectedJson(config.agentSessionProcessPoliciesPath, "Agent Session process policies", 256 * 1024));
    agentSessionSigner = await agentSessionSignerFactory({
      provider: agentSessionSignerProvider,
      env,
      references: {
        bundle: { keyId: config.keyId, publicKey: privateKey },
        refresh: { keyId: config.refreshKeyId, publicKey: refreshPrivateKey }
      }
    });
    if (!agentSessionSigner || typeof agentSessionSigner.signAgentSessionGrant !== "function"
      || typeof agentSessionSigner.verifyAgentSessionGrant !== "function"
      || typeof agentSessionSigner.verificationKeyMetadata !== "function"
      || typeof agentSessionSigner.health !== "function" || typeof agentSessionSigner.key_id !== "string") throw new Error("Cloud Agent Session signer is unavailable");
    const signerHealth = await agentSessionSigner.health();
    if (signerHealth?.ready !== true || signerHealth.key_id !== agentSessionSigner.key_id) throw new Error("Cloud Agent Session signer is unavailable");
    const agentSessionVerificationKeys = await agentSessionSigner.verificationKeyMetadata();
    qualificationManifestSigner = await qualificationManifestSignerFactory({
      provider: qualificationManifestSignerProvider,
      env,
      references: {
        bundle: { keyId: config.keyId, publicKey: privateKey },
        refresh: { keyId: config.refreshKeyId, publicKey: refreshPrivateKey },
        agentSession: agentSessionVerificationKeys.keys.map((key) => ({ keyId: key.key_id, publicKey: key.public_key }))
      }
    });
    if (!qualificationManifestSigner || typeof qualificationManifestSigner.signQualificationGrantBatchManifest !== "function"
      || typeof qualificationManifestSigner.verifyQualificationGrantBatchManifest !== "function"
      || typeof qualificationManifestSigner.verificationKeyMetadata !== "function"
      || typeof qualificationManifestSigner.health !== "function" || typeof qualificationManifestSigner.key_id !== "string") throw new Error("Cloud qualification manifest signer is unavailable");
    const qualificationSignerHealth = await qualificationManifestSigner.health();
    if (qualificationSignerHealth?.ready !== true || qualificationSignerHealth.key_id !== qualificationManifestSigner.key_id) throw new Error("Cloud qualification manifest signer is unavailable");
  }
  const cursorSecret = config.humanAuth ? requireHumanCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET) : undefined;
  const humanAuthSecret = config.humanAuth ? exactRuntimeSecret(env.AGENTPASS_HUMAN_AUTH_SECRET, "AGENTPASS_HUMAN_AUTH_SECRET") : undefined;
  const consoleIdentityPublicKey = config.humanAuth
    ? readProtectedFile(config.humanAuth.identityAssertionPublicKeyPath, "console identity public key", 16 * 1024).toString("utf8")
    : undefined;
  // Hosted instances share the Human cursor root, while the audit codec uses
  // its own domain separator. This keeps Cloud audit cursors valid across
  // restarts/instances without exposing another secret in runtime metadata.
  let store;
  let postgresRuntime;
  let humanAuthRuntime;
  let server;
  try {
    if (profile.isHosted) {
      postgresRuntime = await postgresFactory({ env, applicationVersion: "0.18.0", refreshNonceCodec, resolveProcessBindingPolicy: processBindingPolicies.resolve, ownerRecoveryPublisher: configuredOwnerRecoveryPublisher });
      if (!postgresRuntime?.capabilityAuthorityRepository
        || typeof postgresRuntime.capabilityAuthorityRepository.issueCapabilityMetadata !== "function"
        || typeof postgresRuntime.capabilityAuthorityRepository.listRevokedCapabilityIds !== "function") {
        throw new Error("PostgreSQL capability authority is unavailable");
      }
      if (!postgresRuntime?.controlPlaneStore) throw new Error("PostgreSQL control-plane store is unavailable");
      if (!postgresRuntime?.agentSessionIssuanceRepository || !postgresRuntime?.agentSessionAuthorityRepository) throw new Error("PostgreSQL Agent Session authority is unavailable");
      if (!postgresRuntime?.sharedControlRepository || typeof postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce !== "function" || typeof postgresRuntime.sharedControlRepository.acquireRateLimit !== "function") throw new Error("PostgreSQL shared controls are unavailable");
      store = postgresRuntime.controlPlaneStore;
      if (typeof store.pollDeviceRefresh !== "function" || typeof store.markDeviceRefreshDelivered !== "function") throw new Error("PostgreSQL refresh polling is unavailable");
      if (!postgresRuntime.refreshHintNotifier || typeof postgresRuntime.refreshHintNotifier.waitForRefresh !== "function") throw new Error("PostgreSQL refresh notification is unavailable");
      humanAuthRuntime = humanAuthFactory({
        postgresRuntime,
        tokenRecords,
        origin: config.humanAuth.origin,
        rpId: config.humanAuth.rpId,
        cursorSecret,
        securitySecret: humanAuthSecret,
        identityProvider: config.humanAuth.identityProvider,
        signedConsoleIdentity: {
          issuer: config.humanAuth.identityAssertionIssuer,
          audience: config.humanAuth.identityAssertionAudience,
          keyId: config.humanAuth.identityAssertionKeyId,
          publicKey: consoleIdentityPublicKey
        },
        agentSessionSigner,
        qualificationManifestSigner
      });
    } else store = await createCloudStore({ dataDir: config.dataDir });
    const hostedRateLimiter = profile.isHosted ? createHostedRateLimiter(postgresRuntime.sharedControlRepository) : undefined;
    let agentSessionDeviceApi;
    let qualificationGrantBatchDeviceApi;
    if (profile.isHosted) {
      const deviceRequestVerifier = async (request, options) => {
        const devices = await store.listDevices({ organizationId: options.organizationId });
        const principal = verifyDeviceRequest(request, devices, { ...options, deferReplayConsumption: true });
        const nonce = request.headers?.["agentpass-nonce"] ?? request.headers?.["AgentPass-Nonce"];
        let consumed;
        try { consumed = await postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce({ organizationId: options.organizationId, deviceId: principal.device_id, nonce }); }
        catch { const unavailable = new Error("device replay authority unavailable"); unavailable.code = "ERR_REPOSITORY_UNAVAILABLE"; throw unavailable; }
        if (consumed?.accepted !== true) { const replay = new Error("device request replay denied"); replay.code = "ERR_REPLAY_DETECTED"; throw replay; }
        return principal;
      };
      agentSessionDeviceApi = createAgentSessionDeviceApi({
        deviceRequestVerifier,
        grantVerifier: async (grant, context) => {
          await agentSessionSigner.verificationKeyMetadata(grant?.statement?.key_id, { at: context.now });
          return agentSessionSigner.verifyAgentSessionGrant(grant, { at: context.now });
        },
        repository: postgresRuntime.agentSessionAuthorityRepository,
        rateLimiter: hostedRateLimiter
      });
      if (!postgresRuntime.qualificationGrantBatchRepository
        || typeof postgresRuntime.qualificationGrantBatchRepository.claimQualificationGrantBatch !== "function") {
        throw new Error("PostgreSQL qualification Grant batch authority is unavailable");
      }
      qualificationGrantBatchDeviceApi = createQualificationGrantBatchDeviceApi({
        deviceRequestVerifier,
        grantVerifier: async (grant, context) => {
          await agentSessionSigner.verificationKeyMetadata(grant?.statement?.key_id, { at: context.now });
          return agentSessionSigner.verifyAgentSessionGrant(grant, { at: context.now });
        },
        manifestVerifier: async (manifest, context) => qualificationManifestSigner.verifyQualificationGrantBatchManifest(manifest, { at: context.now }),
        repository: postgresRuntime.qualificationGrantBatchRepository,
        rateLimiter: hostedRateLimiter
      });
    }
    server = createCloudApi({
      store,
      tokenRecords,
      replayCache: profile.isHosted ? undefined : createPersistentReplayCache(path.join(config.dataDir, "device-replay-cache.json")),
      ...(profile.isHosted ? {
        deviceReplayConsumer: async ({ organizationId, deviceId, nonce }) => (await postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce({ organizationId, deviceId, nonce })).accepted,
        rateLimiter: hostedRateLimiter,
        enrollmentCredentialSecret: Buffer.from(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "base64url"),
        trackInFlight: postgresRuntime.trackInFlight,
        readiness: createHostedReadiness(postgresRuntime.readiness, [
          { name: "agent_session_signer", purpose: "agent-session-grant", unavailableCode: "agent_session_signer_unavailable", signer: agentSessionSigner },
          { name: "qualification_manifest_signer", purpose: "agentpass.qualification-grant-batch-manifest", unavailableCode: "qualification_manifest_signer_unavailable", signer: qualificationManifestSigner }
        ]),
        operationalMetrics: postgresRuntime.operationalMetrics,
        operationalProbeSecret: exactRuntimeSecret(env.AGENTPASS_OPERATIONAL_PROBE_SECRET, "AGENTPASS_OPERATIONAL_PROBE_SECRET")
      } : { rateLimiter: createRateLimiter({ persistencePath: path.join(config.dataDir, "principal-rate-limits.json") }) }),
      admissionRateLimiter: profile.isHosted ? undefined : createRateLimiter({ persistencePath: path.join(config.dataDir, "admission-rate-limits.json"), human: { capacity: 30, refillPerSecond: 1 }, device: { capacity: 60, refillPerSecond: 2 } }),
      bundleSigner: { privateKey, issuer: config.issuer, keyId: config.keyId, ttlMs: config.ttlMs, offlineTtlMs: config.offlineTtlMs },
      ...(profile.isHosted ? { refreshHintService: createRefreshHintService({ source: store, nonceDeriver: refreshNonceCodec, signer: refreshHintSigner, notifier: postgresRuntime.refreshHintNotifier, metrics: postgresRuntime.operationalMetrics }) } : {}),
      ...(humanAuthRuntime ? { humanAuthApi: humanAuthRuntime.api, humanSession: humanAuthRuntime.humanSession, recentAuthService: humanAuthRuntime.recentAuthService } : {}),
      ...(agentSessionDeviceApi ? { agentSessionDeviceApi } : {}),
      ...(qualificationGrantBatchDeviceApi ? { qualificationGrantBatchDeviceApi } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityAuthorityRepository: postgresRuntime.capabilityAuthorityRepository } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityRevocationSource: postgresRuntime.capabilityAuthorityRepository } : {})
    });
  } catch (error) { await postgresRuntime?.close?.().catch(() => {}); await store?.close?.(); throw error; }
  let closed = false;
  let closePromise;
  return Object.freeze({
    config: Object.freeze({ ...config, profile: profile.profile }),
    server,
    store,
    postgresRuntime,
    humanAuthRuntime,
    async listen() {
      if (server.listening) return server.address();
      await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, () => { server.off("error", reject); resolve(); }); });
      logger.info?.(`AgentPass Cloud API listening on ${config.host}:${server.address().port}`);
      return server.address();
    },
    async close() {
      if (closed) return;
      if (closePromise) return closePromise;
      closePromise = (async () => {
        postgresRuntime?.beginDrain?.();
        const serverClose = server.listening
          ? new Promise((resolve, reject) => {
              server.close((error) => error ? reject(error) : resolve());
              server.closeIdleConnections?.();
            })
          : Promise.resolve();
        const databaseClose = postgresRuntime?.drain ? postgresRuntime.drain() : postgresRuntime?.close?.();
        const results = await runtimeTimeout(Promise.all([serverClose, databaseClose]), 15_000);
        const drainResult = results?.[1];
        if (drainResult?.drained === false) throw new Error("Cloud runtime drain timed out");
        await store.close?.();
        closed = true;
      })();
      try { return await closePromise; }
      catch (error) { closePromise = undefined; throw error; }
    }
  });
}

export function loadRuntimeConfig(env = {}) {
  const profile = parseCloudRuntimeProfile(env);
  const dataDir = profile.isEvaluation ? absolute(env.AGENTPASS_CLOUD_DATA_DIR, "AGENTPASS_CLOUD_DATA_DIR") : null;
  const bundlePrivateKeyPath = absolute(env.AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH, "AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH");
  const issuer = env.AGENTPASS_CLOUD_ISSUER ?? "agentpass-cloud";
  const keyId = env.AGENTPASS_CLOUD_KEY_ID ?? "control-v2";
  if (!IDENTIFIER.test(issuer) || !IDENTIFIER.test(keyId)) throw new Error("Cloud signer identifiers are invalid");
  const host = env.AGENTPASS_CLOUD_HOST ?? "127.0.0.1";
  if (!new Set(["127.0.0.1", "::1", "localhost", "0.0.0.0", "::"]).has(host)) throw new Error("Cloud listen host is invalid");
  const port = integer(env.AGENTPASS_CLOUD_PORT ?? "8080", 0, 65_535, "Cloud port");
  const ttlMs = integer(env.AGENTPASS_CLOUD_BUNDLE_TTL_MS ?? "3600000", 1_000, 7 * 24 * 60 * 60 * 1000, "Bundle TTL");
  const offlineTtlMs = integer(env.AGENTPASS_CLOUD_OFFLINE_TTL_MS ?? "3600000", 0, 7 * 24 * 60 * 60 * 1000, "Offline TTL");
  const humanAuth = profile.isHosted ? humanAuthConfig(env) : null;
  const refreshPrivateKeyPath = profile.isHosted ? absolute(env.AGENTPASS_CLOUD_REFRESH_PRIVATE_KEY_PATH, "AGENTPASS_CLOUD_REFRESH_PRIVATE_KEY_PATH") : null;
  const refreshNonceKeyringPath = profile.isHosted ? absolute(env.AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH, "AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH") : null;
  const refreshKeyId = profile.isHosted ? env.AGENTPASS_CLOUD_REFRESH_KEY_ID : null;
  if (profile.isHosted && !IDENTIFIER.test(refreshKeyId ?? "")) throw new Error("Cloud refresh signer identifier is invalid");
  const agentSessionProcessPoliciesPath = profile.isHosted ? absolute(env.AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH, "AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH") : null;
  const ownerRecoveryNotification = profile.isHosted ? ownerRecoveryNotificationConfig(env) : null;
  // Hosted Human Auth never loads the legacy operator bearer database. The
  // token-record file exists only for the explicit evaluation profile.
  const tokenRecordsPath = profile.isHosted ? null : absolute(env.AGENTPASS_CLOUD_TOKEN_RECORDS_PATH, "AGENTPASS_CLOUD_TOKEN_RECORDS_PATH");
  return Object.freeze({ dataDir, tokenRecordsPath, bundlePrivateKeyPath, issuer, keyId, host, port, ttlMs, offlineTtlMs, humanAuth, refreshPrivateKeyPath, refreshNonceKeyringPath, refreshKeyId, agentSessionProcessPoliciesPath, ownerRecoveryNotification });
}

function ownerRecoveryNotificationConfig(env) {
  const webhookUrl = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL;
  const authorizationSecretPath = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH;
  if (webhookUrl === undefined && authorizationSecretPath === undefined) return null;
  if (typeof webhookUrl !== "string" || typeof authorizationSecretPath !== "string") throw new Error("Owner recovery notification configuration is incomplete");
  let parsed;
  try { parsed = new URL(webhookUrl); } catch { throw new Error("Owner recovery notification webhook URL is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || !parsed.hostname || webhookUrl.length > 2_048) throw new Error("Owner recovery notification webhook URL is invalid");
  return Object.freeze({ webhookUrl: parsed.href, authorizationSecretPath: absolute(authorizationSecretPath, "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH") });
}

function createConfiguredOwnerRecoveryPublisher(config) {
  if (!config) throw new Error("Hosted owner recovery notification publisher is required");
  const authorizationSecret = readProtectedFile(config.authorizationSecretPath, "owner recovery notification authorization", 4_096).toString("utf8");
  try { return createOwnerRecoveryNotificationPublisher({ webhookUrl: config.webhookUrl, authorizationSecret }); }
  catch { throw new Error("Hosted owner recovery notification publisher is invalid"); }
}

function loadRefreshNonceCodec(file) {
  const document = readProtectedJson(file, "refresh nonce keyring", 64 * 1024);
  if (!document || typeof document !== "object" || Array.isArray(document)
    || Object.keys(document).sort().join(",") !== "active_key_id,keys,version"
    || document.version !== 1 || !document.keys || typeof document.keys !== "object" || Array.isArray(document.keys)
    || Object.keys(document.keys).length < 1 || Object.keys(document.keys).length > 8) {
    throw new Error("Cloud refresh nonce keyring is invalid");
  }
  const keys = {};
  for (const [keyId, encoded] of Object.entries(document.keys)) {
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(encoded)) throw new Error("Cloud refresh nonce keyring is invalid");
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.length !== 32 || bytes.toString("base64url") !== encoded) throw new Error("Cloud refresh nonce keyring is invalid");
    keys[keyId] = bytes;
  }
  try { return createRefreshNonceCodec({ keys, activeKeyId: document.active_key_id }); }
  catch { throw new Error("Cloud refresh nonce keyring is invalid"); }
}

function humanAuthConfig(env) {
  const database = env.AGENTPASS_DATABASE_URL;
  const origin = env.AGENTPASS_CONSOLE_ORIGIN;
  const rpId = env.AGENTPASS_WEBAUTHN_RP_ID;
  const identityProvider = env.AGENTPASS_IDENTITY_PROVIDER ?? "chatgpt";
  const identityAssertionIssuer = env.AGENTPASS_IDENTITY_ASSERTION_ISSUER;
  const identityAssertionAudience = env.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE;
  const identityAssertionKeyId = env.AGENTPASS_IDENTITY_ASSERTION_KID;
  const identityAssertionPublicKeyPath = env.AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH;
  if (database === undefined && origin === undefined && rpId === undefined) return null;
  if (typeof database !== "string" || database.length < 1 || typeof origin !== "string" || typeof rpId !== "string") throw new Error("Human auth configuration is incomplete");
  let parsed;
  try { parsed = new URL(origin); } catch { throw new Error("AGENTPASS_CONSOLE_ORIGIN is invalid"); }
  if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.pathname !== "/" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("AGENTPASS_CONSOLE_ORIGIN is invalid");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(rpId) || (parsed.hostname !== rpId && !parsed.hostname.endsWith(`.${rpId}`))) throw new Error("AGENTPASS_WEBAUTHN_RP_ID is invalid");
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(identityProvider)) throw new Error("AGENTPASS_IDENTITY_PROVIDER is invalid");
  if (typeof identityAssertionIssuer !== "string" || identityAssertionIssuer.length < 1 || identityAssertionIssuer.length > 256
    || typeof identityAssertionAudience !== "string" || identityAssertionAudience.length < 1 || identityAssertionAudience.length > 256
    || !IDENTIFIER.test(identityAssertionKeyId ?? "")) throw new Error("Human identity assertion configuration is incomplete");
  const publicKeyPath = absolute(identityAssertionPublicKeyPath, "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH");
  requireHumanCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET);
  exactRuntimeSecret(env.AGENTPASS_HUMAN_AUTH_SECRET, "AGENTPASS_HUMAN_AUTH_SECRET");
  return Object.freeze({ origin, rpId, identityProvider, identityAssertionIssuer, identityAssertionAudience, identityAssertionKeyId, identityAssertionPublicKeyPath: publicKeyPath });
}

function requireHumanCursorSecret(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret"); }
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  return value;
}

function exactRuntimeSecret(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  return bytes;
}

function readProtectedJson(file, label, maxBytes) {
  const bytes = readProtectedFile(file, label, maxBytes);
  try { return JSON.parse(bytes); } catch { throw new Error(`Cloud ${label} JSON is invalid`); }
}

function readProtectedFile(file, label, maxBytes) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > maxBytes || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`Cloud ${label} permissions are unsafe`);
    return fs.readFileSync(descriptor);
  } finally { fs.closeSync(descriptor); }
}

function absolute(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.basename(value) === "." || path.basename(value) === "..") throw new Error(`${label} must be an absolute path`);
  return path.resolve(value);
}

function integer(value, min, max, label) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} is invalid`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < min || result > max) throw new Error(`${label} is invalid`);
  return result;
}

function runtimeTimeout(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Cloud runtime shutdown timed out")), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function createHostedRateLimiter(repository, { now = () => Date.now() } = {}) {
  if (!repository || typeof repository.acquireRateLimit !== "function") throw new Error("PostgreSQL shared rate limiter is unavailable");
  const fallback = createRateLimiter({ now });
  const policies = Object.freeze({ human: Object.freeze({ capacity: 120, refillPerSecond: 2 }), device: Object.freeze({ capacity: 240, refillPerSecond: 4 }) });
  return Object.freeze({
    policies,
    async acquire({ tenantId, principalType, principalId } = {}) {
      // Pre-authentication traffic has no trustworthy organization UUID yet;
      // it remains bounded by the transport-scoped admission limiter. Every
      // authenticated tenant request uses the shared PostgreSQL bucket.
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(tenantId ?? "")
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(principalId ?? "")) return fallback.acquire({ tenantId, principalType, principalId });
      const policy = policies[principalType];
      if (!policy) throw new Error("rate limiter principal type is invalid");
      return repository.acquireRateLimit({ organizationId: tenantId, principalType, principalId, capacity: policy.capacity, refillPerSecond: policy.refillPerSecond, cost: 1 });
    }
  });
}

function createHostedReadiness(databaseReadiness, signers) {
  if (typeof databaseReadiness !== "function" || !Array.isArray(signers) || signers.length < 1
    || signers.some(({ name, purpose, unavailableCode, signer }) => typeof name !== "string" || typeof purpose !== "string" || typeof unavailableCode !== "string"
      || typeof signer?.health !== "function" || typeof signer?.verificationKeyMetadata !== "function")) throw new Error("Hosted readiness dependencies are unavailable");
  return async function hostedReadiness() {
    const databaseReport = await databaseReadiness();
    const checks = {};
    let signerFailure;
    for (const dependency of signers) {
      let report;
      try {
        const [value, keyRing] = await Promise.all([dependency.signer.health(), dependency.signer.verificationKeyMetadata()]);
        if (!value || value.ready !== true || typeof value.purpose !== "string" || value.algorithm !== "ed25519"
          || typeof value.key_id !== "string" || !/^[0-9a-f]{64}$/u.test(value.public_key_fingerprint ?? "")) throw new Error("invalid signer health");
        if (!keyRing || keyRing.version !== 1 || keyRing.purpose !== value.purpose || keyRing.active_key_id !== value.key_id
          || !Array.isArray(keyRing.keys) || keyRing.keys.length < 1 || keyRing.keys.length > 4
          || !keyRing.keys.some((key) => key?.status === "active" && key.key_id === value.key_id)
          || keyRing.keys.some((key) => !key || key.algorithm !== "ed25519" || typeof key.key_id !== "string"
            || !/^[0-9a-f]{64}$/u.test(key.public_key_fingerprint ?? "") || !["active", "retiring"].includes(key.status))) throw new Error("invalid verification key metadata");
        report = Object.freeze({ ok: true, purpose: value.purpose, algorithm: value.algorithm, key_id: value.key_id, public_key_fingerprint: value.public_key_fingerprint });
      } catch {
        signerFailure ??= dependency.unavailableCode;
        report = Object.freeze({ ok: false, purpose: dependency.purpose, algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
      }
      checks[dependency.name] = report;
    }
    if (!databaseReport || typeof databaseReport !== "object" || Array.isArray(databaseReport)) throw new Error("invalid database readiness");
    return Object.freeze({
      ...databaseReport,
      ready: databaseReport.ready === true && signerFailure === undefined,
      status: databaseReport.ready !== true ? databaseReport.status : signerFailure === undefined ? databaseReport.status : "not_ready",
      code: databaseReport.ready !== true ? databaseReport.code : signerFailure === undefined ? databaseReport.code : signerFailure,
      checks: Object.freeze({ ...(databaseReport.checks ?? {}), ...checks })
    });
  };
}
