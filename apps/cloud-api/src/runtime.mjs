import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { createCloudApi } from "./server.mjs";
import { createCloudStore } from "./store.mjs";
import { createPersistentReplayCache } from "./auth.mjs";
import { createRateLimiter } from "./rate-limit.mjs";
import { createPostgresRuntime } from "./postgres/runtime.mjs";
import { createHumanAuthRuntime } from "./human-auth/runtime.mjs";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export async function createCloudRuntime({ env = process.env, logger = console, postgresFactory = createPostgresRuntime, humanAuthFactory = createHumanAuthRuntime } = {}) {
  const config = loadRuntimeConfig(env);
  const tokenRecords = config.humanAuth ? [] : readProtectedJson(config.tokenRecordsPath, "token records", 1024 * 1024);
  if (!Array.isArray(tokenRecords) || tokenRecords.length > 256 || (!config.humanAuth && tokenRecords.length < 1)) throw new Error("Cloud token records are invalid");
  const privateKeyPEM = readProtectedFile(config.bundlePrivateKeyPath, "bundle private key", 16 * 1024).toString("utf8");
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateKeyPEM); } catch { throw new Error("Cloud bundle private key is invalid"); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Cloud bundle private key must be Ed25519");
  const cursorSecret = config.humanAuth ? requireHumanCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET) : undefined;
  const consoleIdentityPublicKey = config.humanAuth
    ? readProtectedFile(config.humanAuth.identityAssertionPublicKeyPath, "console identity public key", 16 * 1024).toString("utf8")
    : undefined;
  // Hosted instances share the Human cursor root, while the audit codec uses
  // its own domain separator. This keeps Cloud audit cursors valid across
  // restarts/instances without exposing another secret in runtime metadata.
  const store = await createCloudStore({
    dataDir: config.dataDir,
    ...(cursorSecret ? { auditCursorSecret: Buffer.from(cursorSecret, "base64url") } : {})
  });
  let postgresRuntime;
  let humanAuthRuntime;
  let server;
  try {
    if (config.humanAuth) {
      postgresRuntime = await postgresFactory({ env, applicationVersion: "0.18.0" });
      if (!postgresRuntime?.capabilityAuthorityRepository
        || typeof postgresRuntime.capabilityAuthorityRepository.issueCapabilityMetadata !== "function"
        || typeof postgresRuntime.capabilityAuthorityRepository.listRevokedCapabilityIds !== "function") {
        throw new Error("PostgreSQL capability authority is unavailable");
      }
      humanAuthRuntime = humanAuthFactory({
        postgresRuntime,
        tokenRecords,
        origin: config.humanAuth.origin,
        rpId: config.humanAuth.rpId,
        cursorSecret,
        identityProvider: config.humanAuth.identityProvider,
        signedConsoleIdentity: {
          issuer: config.humanAuth.identityAssertionIssuer,
          audience: config.humanAuth.identityAssertionAudience,
          keyId: config.humanAuth.identityAssertionKeyId,
          publicKey: consoleIdentityPublicKey
        }
      });
    }
    server = createCloudApi({
      store,
      tokenRecords,
      replayCache: createPersistentReplayCache(path.join(config.dataDir, "device-replay-cache.json")),
      rateLimiter: createRateLimiter({ persistencePath: path.join(config.dataDir, "principal-rate-limits.json") }),
      admissionRateLimiter: createRateLimiter({ persistencePath: path.join(config.dataDir, "admission-rate-limits.json"), human: { capacity: 30, refillPerSecond: 1 }, device: { capacity: 60, refillPerSecond: 2 } }),
      bundleSigner: { privateKey, issuer: config.issuer, keyId: config.keyId, ttlMs: config.ttlMs, offlineTtlMs: config.offlineTtlMs },
      ...(humanAuthRuntime ? { humanAuthApi: humanAuthRuntime.api, humanSession: humanAuthRuntime.humanSession, recentAuthService: humanAuthRuntime.recentAuthService } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityAuthorityRepository: postgresRuntime.capabilityAuthorityRepository } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityRevocationSource: postgresRuntime.capabilityAuthorityRepository } : {})
    });
  } catch (error) { await postgresRuntime?.close?.().catch(() => {}); await store.close(); throw error; }
  let closed = false;
  return Object.freeze({
    config,
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
      closed = true;
      if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await postgresRuntime?.close?.();
      await store.close();
    }
  });
}

export function loadRuntimeConfig(env = {}) {
  const dataDir = absolute(env.AGENTPASS_CLOUD_DATA_DIR, "AGENTPASS_CLOUD_DATA_DIR");
  const bundlePrivateKeyPath = absolute(env.AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH, "AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH");
  const issuer = env.AGENTPASS_CLOUD_ISSUER ?? "agentpass-cloud";
  const keyId = env.AGENTPASS_CLOUD_KEY_ID ?? "control-v2";
  if (!IDENTIFIER.test(issuer) || !IDENTIFIER.test(keyId)) throw new Error("Cloud signer identifiers are invalid");
  const host = env.AGENTPASS_CLOUD_HOST ?? "127.0.0.1";
  if (!new Set(["127.0.0.1", "::1", "localhost", "0.0.0.0", "::"]).has(host)) throw new Error("Cloud listen host is invalid");
  const port = integer(env.AGENTPASS_CLOUD_PORT ?? "8080", 0, 65_535, "Cloud port");
  const ttlMs = integer(env.AGENTPASS_CLOUD_BUNDLE_TTL_MS ?? "3600000", 1_000, 7 * 24 * 60 * 60 * 1000, "Bundle TTL");
  const offlineTtlMs = integer(env.AGENTPASS_CLOUD_OFFLINE_TTL_MS ?? "3600000", 0, 7 * 24 * 60 * 60 * 1000, "Offline TTL");
  const humanAuth = humanAuthConfig(env);
  // Hosted Human Auth never loads the legacy operator bearer database. The
  // token-record file exists only for the explicit evaluation profile.
  const tokenRecordsPath = humanAuth ? null : absolute(env.AGENTPASS_CLOUD_TOKEN_RECORDS_PATH, "AGENTPASS_CLOUD_TOKEN_RECORDS_PATH");
  return Object.freeze({ dataDir, tokenRecordsPath, bundlePrivateKeyPath, issuer, keyId, host, port, ttlMs, offlineTtlMs, humanAuth });
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
  return Object.freeze({ origin, rpId, identityProvider, identityAssertionIssuer, identityAssertionAudience, identityAssertionKeyId, identityAssertionPublicKeyPath: publicKeyPath });
}

function requireHumanCursorSecret(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret"); }
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  return value;
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
