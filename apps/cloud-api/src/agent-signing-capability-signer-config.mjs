import crypto from "node:crypto";

import {
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN,
  AGENT_SIGNING_CAPABILITY_VERSION,
  AgentSigningCapabilityError,
  agentSigningCapabilitySigningData,
  agentSigningCapabilityStatementHash,
  createAgentSigningCapabilitySigner,
  normalizeAgentSigningCapabilityStatement,
  verifyAgentSigningCapability
} from "./agent-signing-capability.mjs";

export const AGENT_SIGNING_CAPABILITY_SIGNER_PROFILE = "hosted";
export const AGENT_SIGNING_CAPABILITY_SIGNER_PURPOSE = AGENT_SIGNING_CAPABILITY_OPERATION;
export const AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM = AGENT_SIGNING_CAPABILITY_ALGORITHM;
export const AGENT_SIGNING_CAPABILITY_SIGNER_VERSION = AGENT_SIGNING_CAPABILITY_VERSION;
export const AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN = AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN;
export const AGENT_SIGNING_CAPABILITY_SIGNER_KEY_ID_ENV = "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_KEY_ID";
export const AGENT_SIGNING_CAPABILITY_SIGNER_PUBLIC_KEY_ENV = "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PUBLIC_KEY";
export const AGENT_SIGNING_CAPABILITY_SIGNER_TIMEOUT_ENV = "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_TIMEOUT_MS";
export const AGENT_SIGNING_CAPABILITY_SIGNER_ENV = Object.freeze([
  AGENT_SIGNING_CAPABILITY_SIGNER_KEY_ID_ENV,
  AGENT_SIGNING_CAPABILITY_SIGNER_PUBLIC_KEY_ENV,
  AGENT_SIGNING_CAPABILITY_SIGNER_TIMEOUT_ENV
]);

// A hosted signer may never silently become a local file/private-key signer.
// These names are rejected even when the value is undefined so deployment
// templates cannot accidentally introduce a second authority path.
export const AGENT_SIGNING_CAPABILITY_SIGNER_FORBIDDEN_ENV = Object.freeze([
  "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PRIVATE_KEY",
  "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PRIVATE_KEY_PATH",
  "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PUBLIC_KEY_PATH",
  "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_KEY_PATH",
  "AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_SIGNING_KEY"
]);

export const AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_CONFIG",
  INPUT: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_INPUT",
  PROVIDER: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_PROVIDER",
  TIMEOUT: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_TIMEOUT",
  METADATA: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_METADATA",
  KEY_REUSE: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_KEY_REUSE",
  OUTPUT: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_OUTPUT",
  VERIFICATION: "ERR_AGENT_SIGNING_CAPABILITY_SIGNER_VERIFICATION"
});

const PROFILE = AGENT_SIGNING_CAPABILITY_SIGNER_PROFILE;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const PUBLIC_KEY_HASH_ALGORITHM = "sha256";
const MAX_PUBLIC_KEY_BYTES = 8 * 1024;
const MAX_TIMEOUT_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_PROVIDER_BYTES = 64 * 1024;
const MAX_REFERENCE_DEPTH = 8;
const MAX_REFERENCE_NODES = 128;
const MAX_TTL_MS = 15 * 60_000;
const PUBLIC_METADATA_KEYS = Object.freeze(["algorithm", "key_id", "public_key"]);
const CORE_METADATA_KEYS = Object.freeze(["key_id", "purpose"]);
const CORE_SIGN_KEYS = Object.freeze(["algorithm", "bytes", "key_id", "purpose"]);

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.CONFIG]: "agent signing capability hosted signer configuration is invalid",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.INPUT]: "agent signing capability signing input is invalid",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.PROVIDER]: "agent signing capability hosted signer is unavailable",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.TIMEOUT]: "agent signing capability hosted signer timed out",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.METADATA]: "agent signing capability provider metadata is invalid",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.KEY_REUSE]: "agent signing capability key is not purpose separated",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.OUTPUT]: "agent signing capability provider output is invalid",
  [AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.VERIFICATION]: "agent signing capability output could not be verified"
});

export class AgentSigningCapabilitySignerConfigError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.CONFIG]);
    this.name = "AgentSigningCapabilitySignerConfigError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES.CONFIG;
  }
}

export const AgentSigningCapabilitySignerError = AgentSigningCapabilitySignerConfigError;

/**
 * Parse only public, non-secret configuration for the hosted capability
 * signer. The signing key exists exclusively behind the injected managed
 * provider (KMS/HSM); this parser has no private-key or file fallback.
 */
export function parseAgentSigningCapabilitySignerConfig(env = process.env, references = {}, options = {}) {
  try {
    if (!plainObject(env) || env.AGENTPASS_CLOUD_PROFILE !== PROFILE) fail(CODES.CONFIG);
    if (!plainObject(options) || !onlyKeys(options, ["now"])) fail(CODES.CONFIG);
    if (Object.keys(env).some((name) => name.startsWith("AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_")
      && !AGENT_SIGNING_CAPABILITY_SIGNER_ENV.includes(name))) {
      fail(CODES.CONFIG);
    }
    if (AGENT_SIGNING_CAPABILITY_SIGNER_FORBIDDEN_ENV.some((name) => Object.hasOwn(env, name))) {
      fail(CODES.CONFIG);
    }

    const now = options.now ?? (() => Date.now());
    readNow(now);
    const keyId = requiredKeyId(env[AGENT_SIGNING_CAPABILITY_SIGNER_KEY_ID_ENV]);
    const publicKey = parseConfiguredPublicKey(env[AGENT_SIGNING_CAPABILITY_SIGNER_PUBLIC_KEY_ENV]);
    const timeoutMs = parseTimeout(env[AGENT_SIGNING_CAPABILITY_SIGNER_TIMEOUT_ENV]);
    const referenceKeys = normalizeReferenceKeys(references);
    if (referenceKeys.some((reference) => reference.keyId === keyId || reference.fingerprint === publicKey.fingerprint)) {
      fail(CODES.KEY_REUSE);
    }

    return deepFreeze({
      profile: PROFILE,
      purpose: AGENT_SIGNING_CAPABILITY_SIGNER_PURPOSE,
      algorithm: AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM,
      version: AGENT_SIGNING_CAPABILITY_SIGNER_VERSION,
      signatureDomain: AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN,
      keyId,
      timeoutMs,
      publicKeyPem: publicKey.pem,
      publicKeyFingerprint: publicKey.fingerprint
    });
  } catch (error) {
    if (error instanceof AgentSigningCapabilitySignerConfigError) throw error;
    throw new AgentSigningCapabilitySignerConfigError(CODES.CONFIG);
  }
}

export const parseHostedAgentSigningCapabilitySignerConfig = parseAgentSigningCapabilitySignerConfig;

/**
 * Create the production hosted boundary. The managed provider is the only
 * signing authority. This factory deliberately does not accept a private key,
 * key path, credential blob, or local signing fallback.
 */
export function createHostedAgentSigningCapabilitySigner(options = {}) {
  if (!plainObject(options) || !onlyKeys(options, ["provider", "env", "references", "now"])) {
    fail(CODES.CONFIG);
  }
  const {
    provider,
    env = process.env,
    references = {},
    now = () => Date.now()
  } = options;
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !isSafeProviderId(provider.provider_id) || typeof now !== "function") {
    fail(CODES.CONFIG);
  }

  const config = parseAgentSigningCapabilitySignerConfig(env, references, { now });
  const providerBoundary = createBoundProvider(provider, config);
  let primitive;
  try {
    primitive = createAgentSigningCapabilitySigner({
      provider: providerBoundary,
      keyId: config.keyId,
      timeoutMs: config.timeoutMs,
      now
    });
  } catch {
    fail(CODES.CONFIG);
  }

  async function assertProviderMetadata() {
    let metadata;
    try {
      metadata = await callWithDeadline(
        (signal) => provider.publicKeyMetadata({
          algorithm: config.algorithm,
          key_id: config.keyId,
          purpose: config.purpose,
          version: config.version,
          signal
        }),
        config.timeoutMs
      );
    } catch (error) {
      throw mapProviderError(error, CODES.METADATA);
    }
    validateProviderMetadata(metadata, config);
    return makeMetadata(config);
  }

  async function publicKeyMetadata() {
    return assertProviderMetadata();
  }

  async function signAgentSigningCapability(statement) {
    let normalized;
    let currentNow;
    try {
      currentNow = readNow(now);
      normalized = normalizeAgentSigningCapabilityStatement(statement, {
        now: currentNow,
        allowExpired: false,
        allowFuture: false,
        maxTtlMs: MAX_TTL_MS
      });
    } catch (error) {
      if (error instanceof AgentSigningCapabilityError && error.code === "ERR_AGENT_SIGNING_CAPABILITY_NOT_YET_VALID") {
        throw new AgentSigningCapabilitySignerConfigError(CODES.INPUT);
      }
      throw new AgentSigningCapabilitySignerConfigError(CODES.INPUT);
    }
    if (normalized.key_id !== config.keyId) fail(CODES.INPUT);

    await assertProviderMetadata();
    let envelope;
    try {
      envelope = await primitive.signAgentSigningCapability(normalized);
    } catch (error) {
      throw mapPrimitiveError(error);
    }
    // Verify metadata after signing too. A provider/key substitution racing
    // the call is an outage, not a reason to return a possibly foreign key.
    await assertProviderMetadata();
    return verifyExactEnvelope(envelope, normalized, config, currentNow);
  }

  async function health() {
    const metadata = await assertProviderMetadata();
    return Object.freeze({
      ready: true,
      version: metadata.version,
      purpose: metadata.purpose,
      algorithm: metadata.algorithm,
      key_id: metadata.key_id,
      public_key_fingerprint: metadata.public_key_fingerprint
    });
  }

  return Object.freeze({
    key_id: config.keyId,
    purpose: config.purpose,
    algorithm: config.algorithm,
    version: config.version,
    config,
    publicKeyMetadata,
    signAgentSigningCapability,
    sign: signAgentSigningCapability,
    health,
    readiness: health
  });
}

export const createAgentSigningCapabilitySignerConfig = createHostedAgentSigningCapabilitySigner;
export const createHostedAgentSigningCapabilitySignerConfig = createHostedAgentSigningCapabilitySigner;

function createBoundProvider(provider, config) {
  return Object.freeze({
    async publicKeyMetadata(input) {
      if (!plainObject(input) || !sameKeys(input, CORE_METADATA_KEYS)
        || input.key_id !== config.keyId || input.purpose !== config.purpose) {
        throw coreError("ERR_AGENT_SIGNING_CAPABILITY_INPUT");
      }
      let metadata;
      try {
        metadata = await callWithDeadline(
          (signal) => provider.publicKeyMetadata({
            algorithm: config.algorithm,
            key_id: config.keyId,
            purpose: config.purpose,
            version: config.version,
            signal
          }),
          config.timeoutMs
        );
      } catch (error) {
        throw coreError("ERR_AGENT_SIGNING_CAPABILITY_PROVIDER", error);
      }
      validateProviderMetadata(metadata, config, true);
      return {
        key_id: config.keyId,
        algorithm: config.algorithm,
        public_key: config.publicKeyPem
      };
    },
    async sign(input) {
      if (!plainObject(input) || !sameKeys(input, CORE_SIGN_KEYS)
        || input.key_id !== config.keyId
        || input.purpose !== config.purpose
        || input.algorithm !== config.algorithm
        || !(Buffer.isBuffer(input.bytes) || input.bytes instanceof Uint8Array)) {
        throw coreError("ERR_AGENT_SIGNING_CAPABILITY_INPUT");
      }
      const bytes = Buffer.from(input.bytes);
      assertDomainSeparatedBytes(bytes);
      try {
        return await callWithDeadline(
          (signal) => provider.sign({
            algorithm: config.algorithm,
            bytes,
            key_id: config.keyId,
            purpose: config.purpose,
            version: config.version,
            signal
          }),
          config.timeoutMs
        );
      } catch (error) {
        throw coreError("ERR_AGENT_SIGNING_CAPABILITY_PROVIDER", error);
      }
    }
  });
}

function verifyExactEnvelope(envelope, normalized, config, currentNow) {
  try {
    const verified = verifyAgentSigningCapability(envelope, {
      publicKey: config.publicKeyPem,
      keyId: config.keyId,
      organizationId: normalized.organization_id,
      sessionId: normalized.session_id,
      deviceId: normalized.device_id,
      agentId: normalized.agent_id,
      sequence: normalized.sequence,
      controlSequence: normalized.control_sequence,
      authorityGeneration: normalized.authority_generation,
      now: currentNow,
      maxTtlMs: MAX_TTL_MS
    });
    if (canonicalStatement(verified.statement) !== canonicalStatement(normalized)
      || verified.statement_hash !== agentSigningCapabilityStatementHash(normalized)) {
      fail(CODES.VERIFICATION);
    }
    // verifyAgentSigningCapability verifies this exact preimage, including
    // AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN, but keep the explicit check
    // here as a local invariant for future primitive changes.
    const signature = Buffer.from(verified.signature, "base64url");
    if (!crypto.verify(null, agentSigningCapabilitySigningData(normalized), crypto.createPublicKey(config.publicKeyPem), signature)) {
      fail(CODES.VERIFICATION);
    }
    return deepFreeze(verified);
  } catch (error) {
    if (error instanceof AgentSigningCapabilitySignerConfigError) throw error;
    throw new AgentSigningCapabilitySignerConfigError(CODES.VERIFICATION);
  }
}

function validateProviderMetadata(value, config, throwCore = false) {
  try {
    if (!plainObject(value) || !sameKeys(value, PUBLIC_METADATA_KEYS)
      || value.key_id !== config.keyId || value.algorithm !== config.algorithm) {
      fail(CODES.METADATA);
    }
    const publicKey = parseProviderPublicKey(value.public_key);
    if (publicKey.fingerprint !== config.publicKeyFingerprint) fail(CODES.METADATA);
  } catch (error) {
    if (throwCore) {
      if (error instanceof AgentSigningCapabilitySignerConfigError && error.code === CODES.METADATA) {
        throw coreError("ERR_AGENT_SIGNING_CAPABILITY_OUTPUT", error);
      }
      throw coreError("ERR_AGENT_SIGNING_CAPABILITY_OUTPUT", error);
    }
    if (error instanceof AgentSigningCapabilitySignerConfigError) throw error;
    throw new AgentSigningCapabilitySignerConfigError(CODES.METADATA);
  }
}

function parseConfiguredPublicKey(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 1
    || Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES
    || !PUBLIC_KEY_PEM.test(value) || /PRIVATE\s+KEY/iu.test(value)) {
    fail(CODES.CONFIG);
  }
  const parsed = parsePublicKey(value, CODES.CONFIG);
  const canonical = parsed.key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(CODES.CONFIG);
  return { pem: canonical, fingerprint: parsed.fingerprint };
}

function parseProviderPublicKey(value) {
  if (typeof value === "string" && Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES) fail(CODES.METADATA);
  if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(CODES.METADATA);
  return parsePublicKey(value, CODES.METADATA);
}

function parseReferencePublicKey(value) {
  try {
    const key = value?.type === "private" ? crypto.createPublicKey(value) : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM) fail(CODES.CONFIG);
    const der = key.export({ type: "spki", format: "der" });
    return { fingerprint: crypto.createHash(PUBLIC_KEY_HASH_ALGORITHM).update(der).digest("hex") };
  } catch (error) {
    if (error instanceof AgentSigningCapabilitySignerConfigError) throw error;
    fail(CODES.CONFIG);
  }
}

function parsePublicKey(value, code) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM) fail(code);
    const der = key.export({ type: "spki", format: "der" });
    if (!Buffer.isBuffer(der) || der.length < 1 || der.length > MAX_PUBLIC_KEY_BYTES) fail(code);
    return {
      key,
      fingerprint: crypto.createHash(PUBLIC_KEY_HASH_ALGORITHM).update(der).digest("hex")
    };
  } catch (error) {
    if (error instanceof AgentSigningCapabilitySignerConfigError) throw error;
    throw new AgentSigningCapabilitySignerConfigError(code);
  }
}

function normalizeReferenceKeys(references) {
  if (references === undefined || references === null) return [];
  if (!plainObject(references)) fail(CODES.CONFIG);
  const output = [];
  const visited = new Set();
  let nodes = 0;

  function visit(value, depth) {
    if (value === undefined || value === null) return;
    if (depth > MAX_REFERENCE_DEPTH || ++nodes > MAX_REFERENCE_NODES) fail(CODES.CONFIG);
    if (value?.type === "public" || value?.type === "private") {
      output.push({ fingerprint: parseReferencePublicKey(value).fingerprint });
      return;
    }
    if (Array.isArray(value)) {
      if (visited.has(value)) fail(CODES.CONFIG);
      visited.add(value);
      for (const item of value) visit(item, depth + 1);
      return;
    }
    if (!plainObject(value)) fail(CODES.CONFIG);
    if (visited.has(value)) fail(CODES.CONFIG);
    visited.add(value);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") fail(CODES.CONFIG);
      if (/^(?:private[_-]?key|signing[_-]?key|secret|credential|key[_-]?path|file)$/iu.test(key)) {
        fail(CODES.CONFIG);
      }
    }
    const keyId = value.keyId ?? value.key_id;
    const publicKeyValue = value.publicKey ?? value.public_key;
    if (keyId !== undefined) {
      if (typeof keyId !== "string" || !KEY_ID.test(keyId)) fail(CODES.CONFIG);
      output.push({ keyId });
    }
    if (publicKeyValue !== undefined) output.push({ fingerprint: parseReferencePublicKey(publicKeyValue).fingerprint });
    for (const [name, child] of Object.entries(value)) {
      if (!["keyId", "key_id", "publicKey", "public_key"].includes(name)) visit(child, depth + 1);
    }
  }

  visit(references, 0);
  return output;
}

function makeMetadata(config) {
  return Object.freeze({
    version: config.version,
    purpose: config.purpose,
    key_id: config.keyId,
    algorithm: config.algorithm,
    public_key: config.publicKeyPem,
    public_key_fingerprint: config.publicKeyFingerprint
  });
}

function assertDomainSeparatedBytes(bytes) {
  const domain = Buffer.from(AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN, "utf8");
  if (bytes.length <= domain.length || !bytes.subarray(0, domain.length).equals(domain)
    || bytes.length > MAX_PROVIDER_BYTES) {
    throw coreError("ERR_AGENT_SIGNING_CAPABILITY_INPUT");
  }
}

function canonicalStatement(value) {
  return Buffer.from(agentSigningCapabilitySigningData(value)).subarray(Buffer.byteLength(AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN)).toString("utf8");
}

function mapPrimitiveError(error) {
  const causeCode = error?.cause?.code;
  if (causeCode === CODES.TIMEOUT) return new AgentSigningCapabilitySignerConfigError(CODES.TIMEOUT);
  if (causeCode === CODES.PROVIDER) return new AgentSigningCapabilitySignerConfigError(CODES.PROVIDER);
  switch (error?.code) {
    case "ERR_AGENT_SIGNING_CAPABILITY_PROVIDER": return new AgentSigningCapabilitySignerConfigError(CODES.PROVIDER);
    case "ERR_AGENT_SIGNING_CAPABILITY_OUTPUT": return new AgentSigningCapabilitySignerConfigError(CODES.OUTPUT);
    case "ERR_AGENT_SIGNING_CAPABILITY_SIGNATURE": return new AgentSigningCapabilitySignerConfigError(CODES.VERIFICATION);
    case "ERR_AGENT_SIGNING_CAPABILITY_INPUT":
    case "ERR_AGENT_SIGNING_CAPABILITY_EXPIRED":
    case "ERR_AGENT_SIGNING_CAPABILITY_NOT_YET_VALID":
      return new AgentSigningCapabilitySignerConfigError(CODES.INPUT);
    default: return new AgentSigningCapabilitySignerConfigError(CODES.PROVIDER);
  }
}

function mapProviderError(error, fallbackCode) {
  if (error instanceof AgentSigningCapabilitySignerConfigError) return error;
  if (error?.code === CODES.TIMEOUT) return error;
  return new AgentSigningCapabilitySignerConfigError(CODES.PROVIDER);
}

function coreError(code, cause = undefined) {
  return new AgentSigningCapabilityError(code, cause === undefined ? {} : { cause });
}

function callWithDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    timer = setTimeout(() => {
      controller.abort();
      finish(reject, new AgentSigningCapabilitySignerConfigError(CODES.TIMEOUT));
    }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error)
    );
  });
}

function requiredKeyId(value) {
  if (typeof value !== "string" || !KEY_ID.test(value)) fail(CODES.CONFIG);
  return value;
}

function parseTimeout(value) {
  if (value === undefined || value === "") return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) fail(CODES.CONFIG);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TIMEOUT_MS) fail(CODES.CONFIG);
  return parsed;
}

function readNow(value) {
  let observed;
  try { observed = typeof value === "function" ? value() : value; } catch { fail(CODES.CONFIG); }
  const resolved = observed instanceof Date ? observed.getTime() : observed;
  if (!Number.isSafeInteger(resolved) || resolved < 0) fail(CODES.CONFIG);
  return resolved;
}

function isSafeProviderId(value) {
  return value === undefined || (typeof value === "string" && PROVIDER_ID.test(value)
    && !/(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(value));
}

function sameKeys(value, expected) {
  const actual = Reflect.ownKeys(value);
  return actual.length === expected.length && actual.every((key) => typeof key === "string"
    && expected.includes(key) && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

function onlyKeys(value, allowed) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string" && allowed.includes(key)
    && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) {
  throw new AgentSigningCapabilitySignerConfigError(code);
}

const CODES = AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES;
