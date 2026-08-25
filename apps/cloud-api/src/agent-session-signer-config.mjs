import crypto from "node:crypto";
import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";

import {
  AGENT_SESSION_GRANT_ISSUER,
  AGENT_SESSION_GRANT_TYPE,
  AGENT_SESSION_GRANT_VERSION,
  agentSessionGrantSigningData,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement,
  verifyAgentSessionGrant as verifyGrant
} from "./agent-session-grant.mjs";

export const AGENT_SESSION_SIGNER_PURPOSE = AGENT_SESSION_GRANT_TYPE;
export const AGENT_SESSION_SIGNER_ALGORITHM = "ed25519";
export const AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV = "AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON";
export const AGENT_SESSION_SIGNER_MAX_RETIRING_KEYS = 3;
export const AGENT_SESSION_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;
export const AGENT_SESSION_SIGNER_ENV = Object.freeze([
  "AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID",
  "AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY",
  "AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS",
  AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV
]);

export const AGENT_SESSION_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SESSION_SIGNER_CONFIG",
  INPUT: "ERR_AGENT_SESSION_SIGNER_INPUT",
  PROVIDER: "ERR_AGENT_SESSION_SIGNER_PROVIDER",
  TIMEOUT: "ERR_AGENT_SESSION_SIGNER_TIMEOUT",
  METADATA: "ERR_AGENT_SESSION_SIGNER_METADATA",
  KEY_REUSE: "ERR_AGENT_SESSION_SIGNER_KEY_REUSE",
  DUPLICATE_KEY: "ERR_AGENT_SESSION_SIGNER_DUPLICATE_KEY",
  AMBIGUOUS_KEY: "ERR_AGENT_SESSION_SIGNER_AMBIGUOUS_KEY",
  KEY_NOT_TRUSTED: "ERR_AGENT_SESSION_SIGNER_KEY_NOT_TRUSTED",
  OUTPUT: "ERR_AGENT_SESSION_SIGNER_OUTPUT",
  VERIFICATION: "ERR_AGENT_SESSION_SIGNER_VERIFICATION"
});

const PROFILE = "hosted";
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const MAX_TIMEOUT_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_PUBLIC_KEY_BYTES = 8 * 1024;
const MAX_SIGNATURE_BYTES = 64;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const PUBLIC_METADATA_KEYS = Object.freeze(["key_id", "algorithm", "public_key"]);
const PUBLIC_KEY_HASH_ALGORITHM = "sha256";

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG]: "agent session signer configuration is invalid",
  [AGENT_SESSION_SIGNER_ERROR_CODES.INPUT]: "agent session signer input is invalid",
  [AGENT_SESSION_SIGNER_ERROR_CODES.PROVIDER]: "agent session signer provider failed",
  [AGENT_SESSION_SIGNER_ERROR_CODES.TIMEOUT]: "agent session signer provider timed out",
  [AGENT_SESSION_SIGNER_ERROR_CODES.METADATA]: "agent session signer metadata is invalid",
  [AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE]: "agent session signer key is not purpose separated",
  [AGENT_SESSION_SIGNER_ERROR_CODES.DUPLICATE_KEY]: "agent session signer verification keys contain a duplicate",
  [AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY]: "agent session signer active and retiring keys are ambiguous",
  [AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED]: "agent session signer verification key is not trusted",
  [AGENT_SESSION_SIGNER_ERROR_CODES.OUTPUT]: "agent session signer output is invalid",
  [AGENT_SESSION_SIGNER_ERROR_CODES.VERIFICATION]: "agent session signer output could not be verified"
});

export class AgentSessionSignerConfigError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG]);
    this.name = "AgentSessionSignerConfigError";
    this.code = code;
  }
}

/**
 * Parse the non-secret configuration for the hosted Agent Session signer.
 *
 * The private signing key is deliberately not a supported configuration
 * value. It remains behind the injected provider's KMS/HSM boundary. The
 * public key is an SPKI PEM pin used to detect provider/key substitution.
 */
export function parseAgentSessionSignerConfig(env = process.env, references = {}, options = {}) {
  try {
    if (!plainObject(env) || env.AGENTPASS_CLOUD_PROFILE !== PROFILE) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
    const currentNow = readNow(options?.now);
    const verification = parseVerificationConfiguration(env, currentNow);
    const timeoutMs = parseTimeout(env.AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS);
    const referenceKeys = normalizeReferenceKeys(references);
    rejectPurposeKeyReuse(verification.keys, referenceKeys);
    const result = {
      profile: PROFILE,
      purpose: AGENT_SESSION_SIGNER_PURPOSE,
      algorithm: AGENT_SESSION_SIGNER_ALGORITHM,
      keyId: verification.active.keyId,
      timeoutMs,
      publicKeyPem: verification.active.publicKeyPem,
      publicKeyFingerprint: verification.active.publicKeyFingerprint
    };
    const safeKeys = verification.keys.map(toSafeVerificationKey);
    const safeActive = safeKeys[0];
    const safeRetiring = safeKeys.slice(1);
    const safeRing = Object.freeze({
      version: verification.version,
      purpose: AGENT_SESSION_SIGNER_PURPOSE,
      active_key_id: verification.active.keyId,
      keys: Object.freeze(safeKeys)
    });
    Object.defineProperties(result, {
      activeVerificationKey: { value: safeActive, enumerable: false },
      retiringVerificationKeys: { value: Object.freeze(safeRetiring), enumerable: false },
      verificationKeys: { value: Object.freeze(safeKeys), enumerable: false },
      verificationKeyRing: { value: safeRing, enumerable: false }
    });
    return deepFreeze(result);
  } catch (error) {
    if (error instanceof AgentSessionSignerConfigError) throw error;
    throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }
}

export const parseHostedAgentSessionSignerConfig = parseAgentSessionSignerConfig;

/**
 * Build the production-only Agent Session Grant signer boundary.
 *
 * The provider is intentionally injected so this module cannot silently
 * fall back to a local private-key file. Its only public contract is a
 * purpose-bound public metadata lookup and a raw Ed25519 signature call.
 */
export function createHostedAgentSessionGrantSigner({ provider, env = process.env, references, now = () => Date.now() } = {}) {
  const config = parseAgentSessionSignerConfig(env, references, { now });
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function" || typeof now !== "function") {
    throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }

  async function loadMetadata() {
    let metadata;
    try {
      metadata = await withDeadline(
        (signal) => provider.publicKeyMetadata({
          key_id: config.keyId,
          algorithm: config.algorithm,
          purpose: config.purpose,
          version: AGENT_SESSION_GRANT_VERSION,
          signal
        }),
        config.timeoutMs
      );
    } catch (error) {
      if (error instanceof AgentSessionSignerConfigError) throw error;
      throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.PROVIDER);
    }
    validateProviderMetadata(metadata, config);
    return Object.freeze({
      version: AGENT_SESSION_GRANT_VERSION,
      purpose: config.purpose,
      key_id: config.keyId,
      algorithm: config.algorithm,
      public_key: config.publicKeyPem,
      public_key_fingerprint: config.publicKeyFingerprint
    });
  }

  async function publicKeyMetadata() {
    return loadMetadata();
  }

  /**
   * Return the current public verification set. The active key is the only
   * key the injected provider may use for signing; retiring keys are
   * verification-only and are accepted only until their configured expiry.
   */
  async function verificationKeyMetadata(keyId, { at = undefined } = {}) {
    await loadMetadata();
    const current = readNow(at === undefined ? now : at);
    if (keyId !== undefined) return resolveVerificationKey(config, keyId, current);
    return Object.freeze({
      version: AGENT_SESSION_GRANT_VERSION,
      purpose: AGENT_SESSION_SIGNER_PURPOSE,
      active_key_id: config.keyId,
      keys: Object.freeze(config.verificationKeys.filter((key) => isCurrentlyVerifiable(key, current)))
    });
  }

  async function signAgentSessionGrant(statement) {
    const normalized = normalizeStatement(statement, now);
    if (normalized.key_id !== config.keyId) throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.INPUT);
    await loadMetadata();
    const bytes = agentSessionGrantSigningData(normalized);
    let signature;
    try {
      signature = await withDeadline(
        (signal) => provider.sign({
          bytes: Buffer.from(bytes),
          key_id: config.keyId,
          algorithm: config.algorithm,
          purpose: config.purpose,
          version: AGENT_SESSION_GRANT_VERSION,
          signal
        }),
        config.timeoutMs
      );
    } catch (error) {
      if (error instanceof AgentSessionSignerConfigError) throw error;
      throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.PROVIDER);
    }
    const signatureBytes = normalizeSignature(signature);
    let publicKey;
    try { publicKey = crypto.createPublicKey(config.publicKeyPem); } catch { throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG); }
    if (!crypto.verify(null, bytes, publicKey, signatureBytes)) {
      throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.VERIFICATION);
    }
    return deepFreeze({
      version: AGENT_SESSION_GRANT_VERSION,
      type: AGENT_SESSION_GRANT_TYPE,
      statement: normalized,
      statement_hash: agentSessionGrantStatementHash(normalized),
      signature: signatureBytes.toString("base64url")
    });
  }

  async function health() {
    const metadata = await loadMetadata();
    const result = {
      ready: true,
      purpose: metadata.purpose,
      algorithm: metadata.algorithm,
      key_id: metadata.key_id,
      public_key_fingerprint: metadata.public_key_fingerprint
    };
    if (config.retiringVerificationKeys.length > 0) {
      result.verification_key_ids = config.verificationKeys
        .filter((key) => isCurrentlyVerifiable(key, readNow(now)))
        .map((key) => key.key_id);
    }
    return Object.freeze(result);
  }

  function verifyAgentSessionGrant(envelope, { at = undefined } = {}) {
    const current = readNow(at === undefined ? now : at);
    const keyId = envelope?.statement?.key_id;
    const key = resolveVerificationKey(config, keyId, current);
    try {
      return verifyGrant(envelope, {
        publicKey: key.public_key,
        keyId: key.key_id,
        now: current
      });
    } catch {
      throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.VERIFICATION);
    }
  }

  return Object.freeze({
    key_id: config.keyId,
    algorithm: config.algorithm,
    config,
    publicKeyMetadata,
    verificationKeyMetadata,
    signAgentSessionGrant,
    verifyAgentSessionGrant,
    health
  });
}

export const createHostedAgentSessionSigner = createHostedAgentSessionGrantSigner;

function normalizeStatement(statement, now) {
  try {
    const current = now();
    return normalizeAgentSessionGrantStatement(statement, { now: current, allowExpired: false, allowFuture: false });
  } catch {
    throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.INPUT);
  }
}

function parseVerificationConfiguration(env, currentNow) {
  const rawDocument = env[AGENT_SESSION_SIGNER_VERIFICATION_KEYS_ENV];
  if (rawDocument === undefined) {
    const active = parseLegacyActiveKey(env);
    return { version: AGENT_SESSION_GRANT_VERSION, active, keys: [active] };
  }
  if (typeof rawDocument !== "string" || Buffer.byteLength(rawDocument, "utf8") < 1 || Buffer.byteLength(rawDocument, "utf8") > 64 * 1024) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }
  let document;
  try { document = parseBoundedJson(Buffer.from(rawDocument, "utf8"), { maxBytes: 64 * 1024, maxDepth: 8 }); }
  catch { fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG); }
  exactKeys(document, ["active", "retiring", "version"], AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  if (document.version !== AGENT_SESSION_GRANT_VERSION || !Array.isArray(document.retiring)
    || document.retiring.length > AGENT_SESSION_SIGNER_MAX_RETIRING_KEYS) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }
  const active = parseRotationKey(document.active, "active", currentNow);
  const retiring = document.retiring.map((key) => parseRotationKey(key, "retiring", currentNow));
  const keys = [active, ...retiring];
  rejectRotationDuplicates(active, retiring);
  assertLegacyActiveMatches(env, active);
  return { version: document.version, active, keys };
}

function parseLegacyActiveKey(env) {
  const keyId = requiredKeyId(env.AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID);
  const publicKey = parseConfiguredPublicKey(env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY);
  return {
    keyId,
    algorithm: AGENT_SESSION_SIGNER_ALGORITHM,
    publicKeyPem: publicKey.pem,
    publicKeyFingerprint: publicKey.fingerprint,
    status: "active"
  };
}

function assertLegacyActiveMatches(env, active) {
  const legacyKeyId = env.AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID;
  const legacyPublicKey = env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY;
  const hasLegacyKeyId = legacyKeyId !== undefined;
  const hasLegacyPublicKey = legacyPublicKey !== undefined;
  if (!hasLegacyKeyId && !hasLegacyPublicKey) return;
  if (!hasLegacyKeyId || !hasLegacyPublicKey) fail(AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY);
  const legacy = parseLegacyActiveKey(env);
  if (legacy.keyId !== active.keyId || legacy.publicKeyFingerprint !== active.publicKeyFingerprint) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY);
  }
}

function parseRotationKey(value, status, currentNow) {
  const expectedKeys = status === "active"
    ? ["algorithm", "key_id", "public_key"]
    : ["algorithm", "expires_at", "key_id", "public_key"];
  exactKeys(value, expectedKeys, AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  const keyId = requiredKeyId(value.key_id);
  if (value.algorithm !== AGENT_SESSION_SIGNER_ALGORITHM) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  const publicKey = parseConfiguredPublicKey(value.public_key);
  let expiresAt;
  let expiresAtMs;
  if (status === "retiring") {
    ({ value: expiresAt, milliseconds: expiresAtMs } = parseRetiringExpiry(value.expires_at, currentNow));
  }
  return {
    keyId,
    algorithm: value.algorithm,
    publicKeyPem: publicKey.pem,
    publicKeyFingerprint: publicKey.fingerprint,
    status,
    ...(expiresAt === undefined ? {} : { expiresAt, expiresAtMs })
  };
}

function parseRetiringExpiry(value, currentNow) {
  if (typeof value !== "string") fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  let milliseconds;
  try { milliseconds = Date.parse(value); } catch { milliseconds = Number.NaN; }
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value
    || milliseconds <= currentNow
    || milliseconds > currentNow + AGENT_SESSION_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }
  return { value, milliseconds };
}

function rejectRotationDuplicates(active, retiring) {
  const retiringIds = new Set();
  const retiringFingerprints = new Set();
  for (const key of retiring) {
    if (key.keyId === active.keyId || key.publicKeyFingerprint === active.publicKeyFingerprint) {
      fail(AGENT_SESSION_SIGNER_ERROR_CODES.AMBIGUOUS_KEY);
    }
    if (retiringIds.has(key.keyId) || retiringFingerprints.has(key.publicKeyFingerprint)) {
      fail(AGENT_SESSION_SIGNER_ERROR_CODES.DUPLICATE_KEY);
    }
    retiringIds.add(key.keyId);
    retiringFingerprints.add(key.publicKeyFingerprint);
  }
}

function exactKeys(value, expected, errorCode) {
  if (!plainObject(value) || Object.keys(value).sort().join(",") !== expected.slice().sort().join(",")) fail(errorCode);
}

function toSafeVerificationKey(key) {
  return Object.freeze({
    key_id: key.keyId,
    algorithm: key.algorithm,
    public_key: key.publicKeyPem,
    public_key_fingerprint: key.publicKeyFingerprint,
    status: key.status,
    ...(key.expiresAt === undefined ? {} : { expires_at: key.expiresAt })
  });
}

function resolveVerificationKey(config, keyId, currentNow) {
  if (typeof keyId !== "string") fail(AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED);
  const key = config.verificationKeys.find((candidate) => candidate.key_id === keyId);
  if (!key || !isCurrentlyVerifiable(key, currentNow)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED);
  return key;
}

function isCurrentlyVerifiable(key, currentNow) {
  return key.status === "active" || (typeof key.expires_at === "string" && Date.parse(key.expires_at) > currentNow);
}

function readNow(value) {
  const observed = typeof value === "function" ? value() : value === undefined ? Date.now() : value;
  const resolved = observed instanceof Date ? observed.getTime() : observed;
  if (!Number.isSafeInteger(resolved) || resolved < 0) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  return resolved;
}

function validateProviderMetadata(value, config) {
  try {
    if (!plainObject(value) || Object.keys(value).length !== PUBLIC_METADATA_KEYS.length
      || Object.keys(value).some((key) => !PUBLIC_METADATA_KEYS.includes(key))
      || value.key_id !== config.keyId || value.algorithm !== config.algorithm) {
      fail(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
    }
    const publicKey = parseProviderPublicKey(value.public_key);
    if (publicKey.fingerprint !== config.publicKeyFingerprint) fail(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  } catch (error) {
    if (error instanceof AgentSessionSignerConfigError) throw error;
    throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  }
}

function normalizeReferenceKeys(references) {
  if (references === undefined) return [];
  if (!plainObject(references)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  const entries = [];
  for (const [purpose, value] of Object.entries(references)) {
    if (value === undefined || value === null) continue;
    if (!plainObject(value)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
    const keyId = value.keyId ?? value.key_id;
    const publicKeyValue = value.publicKey ?? value.public_key;
    if (keyId !== undefined && !KEY_ID.test(keyId)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
    let publicKey;
    if (publicKeyValue !== undefined) publicKey = parseReferencePublicKey(publicKeyValue);
    entries.push(Object.freeze({
      purpose,
      ...(keyId === undefined ? {} : { keyId }),
      ...(publicKey ? { fingerprint: publicKey.fingerprint } : {})
    }));
  }
  return entries;
}

function rejectPurposeKeyReuse(keys, references) {
  if (keys.some((key) => references.some((reference) => reference.keyId === key.keyId || reference.fingerprint === key.publicKeyFingerprint))) {
    throw new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE);
  }
}

function parseConfiguredPublicKey(value) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES || !PUBLIC_KEY_PEM.test(value)) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  }
  const parsed = parsePublicKey(value, false, AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  const canonical = parsed.key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  return { pem: canonical, fingerprint: parsed.fingerprint };
}

function parseProviderPublicKey(value) {
  if (typeof value === "string" && Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES) fail(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  const parsed = parsePublicKey(value, false, AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  if (typeof value === "string" && value !== parsed.key.export({ type: "spki", format: "pem" }).toString()) {
    fail(AGENT_SESSION_SIGNER_ERROR_CODES.METADATA);
  }
  return parsed;
}

function parseReferencePublicKey(value) {
  const parsed = parsePublicKey(value, true, AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  return parsed;
}

function parsePublicKey(value, allowPrivate, errorCode) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) {
      if (!allowPrivate) fail(errorCode);
    }
    const key = value?.type === "private" ? crypto.createPublicKey(value) : value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== AGENT_SESSION_SIGNER_ALGORITHM) fail(errorCode);
    const der = key.export({ type: "spki", format: "der" });
    if (!Buffer.isBuffer(der) || der.length < 1 || der.length > MAX_PUBLIC_KEY_BYTES) fail(errorCode);
    return {
      key,
      fingerprint: crypto.createHash(PUBLIC_KEY_HASH_ALGORITHM).update(der).digest("hex")
    };
  } catch (error) {
    if (error instanceof AgentSessionSignerConfigError) throw error;
    throw new AgentSessionSignerConfigError(errorCode);
  }
}

function normalizeSignature(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.OUTPUT);
  const signature = Buffer.from(value);
  if (signature.length !== MAX_SIGNATURE_BYTES) fail(AGENT_SESSION_SIGNER_ERROR_CODES.OUTPUT);
  return signature;
}

function requiredKeyId(value) {
  if (typeof value !== "string" || !KEY_ID.test(value)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  return value;
}

function parseTimeout(value) {
  if (value === undefined || value === "") return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TIMEOUT_MS) fail(AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  return parsed;
}

function withDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      controller.abort();
      reject(new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.TIMEOUT));
    }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then((value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    }, () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new AgentSessionSignerConfigError(AGENT_SESSION_SIGNER_ERROR_CODES.PROVIDER));
    });
  });
}

function plainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

function fail(code) {
  throw new AgentSessionSignerConfigError(code);
}
