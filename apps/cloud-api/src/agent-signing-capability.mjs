import crypto from "node:crypto";

import { canonicalJson, normalizeScope } from "../../../packages/protocol/src/index.mjs";

export const AGENT_SIGNING_CAPABILITY_VERSION = 1;
export const AGENT_SIGNING_CAPABILITY_TYPE = "agentpass.agent-signing-capability";
export const AGENT_SIGNING_CAPABILITY_ISSUER = "agentpass-cloud";
export const AGENT_SIGNING_CAPABILITY_OPERATION = "git.commit.sign";
export const AGENT_SIGNING_CAPABILITY_ALGORITHM = "ed25519";
export const AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES = 1;
export const AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN = "AgentPass-Agent-Signing-Capability-v1\0";

export const AGENT_SIGNING_CAPABILITY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SIGNING_CAPABILITY_CONFIG",
  INPUT: "ERR_AGENT_SIGNING_CAPABILITY_INPUT",
  PROVIDER: "ERR_AGENT_SIGNING_CAPABILITY_PROVIDER",
  OUTPUT: "ERR_AGENT_SIGNING_CAPABILITY_OUTPUT",
  SIGNATURE: "ERR_AGENT_SIGNING_CAPABILITY_SIGNATURE",
  AUTHORITY: "ERR_AGENT_SIGNING_CAPABILITY_AUTHORITY",
  EXPIRED: "ERR_AGENT_SIGNING_CAPABILITY_EXPIRED",
  NOT_YET_VALID: "ERR_AGENT_SIGNING_CAPABILITY_NOT_YET_VALID"
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATEMENT_KEYS = Object.freeze([
  "version", "type", "capability_id", "organization_id", "session_id", "device_id", "agent_id",
  "one_use", "operation", "scope", "key_purpose", "key_id", "algorithm", "max_signatures",
  "issued_at", "not_before", "expires_at", "sequence", "control_sequence", "authority_generation", "issuer"
]);
const ENVELOPE_KEYS = Object.freeze(["version", "type", "statement", "statement_hash", "signature"]);
// Shape/canonical helpers accept the protocol ceiling. Issuance and runtime
// verification pass their tighter policy limit explicitly.
const DEFAULT_MAX_TTL_MS = 15 * 60_000;
const MAX_STATEMENT_BYTES = 32 * 1024;
const DOMAIN = Buffer.from(AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN, "utf8");

export class AgentSigningCapabilityError extends Error {
  constructor(code, { cause } = {}) {
    super(message(code), cause === undefined ? undefined : { cause });
    this.name = "AgentSigningCapabilityError";
    this.code = code;
  }
}

export function normalizeAgentSigningCapabilityStatement(input, {
  now,
  allowExpired = true,
  allowFuture = true,
  maxTtlMs = DEFAULT_MAX_TTL_MS
} = {}) {
  try {
    exactObject(input, STATEMENT_KEYS);
    const statement = {
      version: exact(input.version, AGENT_SIGNING_CAPABILITY_VERSION),
      type: exact(input.type, AGENT_SIGNING_CAPABILITY_TYPE),
      capability_id: pattern(input.capability_id, UUID),
      organization_id: pattern(input.organization_id, UUID),
      session_id: pattern(input.session_id, UUID),
      device_id: pattern(input.device_id, UUID),
      agent_id: pattern(input.agent_id, UUID),
      one_use: exact(input.one_use, true),
      operation: exact(input.operation, AGENT_SIGNING_CAPABILITY_OPERATION),
      scope: normalizedSigningScope(input.scope),
      key_purpose: exact(input.key_purpose, AGENT_SIGNING_CAPABILITY_OPERATION),
      key_id: pattern(input.key_id, IDENTIFIER),
      algorithm: exact(input.algorithm, AGENT_SIGNING_CAPABILITY_ALGORITHM),
      max_signatures: exact(input.max_signatures, AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES),
      issued_at: timestamp(input.issued_at),
      not_before: timestamp(input.not_before),
      expires_at: timestamp(input.expires_at),
      sequence: integer(input.sequence),
      control_sequence: integer(input.control_sequence),
      authority_generation: integer(input.authority_generation),
      issuer: exact(input.issuer, AGENT_SIGNING_CAPABILITY_ISSUER)
    };
    const issuedAt = Date.parse(statement.issued_at);
    const notBefore = Date.parse(statement.not_before);
    const expiresAt = Date.parse(statement.expires_at);
    if (issuedAt > notBefore || notBefore >= expiresAt || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || expiresAt - issuedAt > maxTtlMs) {
      fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
    }
    const nowMs = now === undefined ? undefined : exactNow(now);
    if (!allowFuture && nowMs < notBefore) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.NOT_YET_VALID);
    if (!allowExpired && nowMs >= expiresAt) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.EXPIRED);
    if (Buffer.byteLength(canonicalJson(statement), "utf8") > MAX_STATEMENT_BYTES) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
    return deepFreeze(statement);
  } catch (error) {
    if (error instanceof AgentSigningCapabilityError) throw error;
    throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT, { cause: error });
  }
}

export function agentSigningCapabilitySigningData(statement) {
  const normalized = normalizeAgentSigningCapabilityStatement(statement);
  return Buffer.concat([DOMAIN, Buffer.from(canonicalJson(normalized), "utf8")]);
}

export function agentSigningCapabilityStatementHash(statement) {
  const normalized = normalizeAgentSigningCapabilityStatement(statement);
  return crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex");
}

export function createAgentSigningCapabilitySigner({ provider, keyId, timeoutMs = 5_000, now = () => Date.now() } = {}) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !IDENTIFIER.test(keyId ?? "") || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 || typeof now !== "function") {
    throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG);
  }
  let pinnedPublicKey;

  async function publicKey() {
    if (pinnedPublicKey) return pinnedPublicKey;
    let metadata;
    try {
      metadata = await deadline(provider.publicKeyMetadata({ key_id: keyId, purpose: AGENT_SIGNING_CAPABILITY_OPERATION }), timeoutMs);
    } catch (error) {
      if (error instanceof AgentSigningCapabilityError) throw error;
      throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.PROVIDER, { cause: error });
    }
    try {
      exactObject(metadata, ["key_id", "algorithm", "public_key"]);
      if (metadata.key_id !== keyId || metadata.algorithm !== AGENT_SIGNING_CAPABILITY_ALGORITHM || metadata.public_key?.type === "private" || /PRIVATE\s+KEY/iu.test(String(metadata.public_key))) {
        fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.OUTPUT);
      }
      pinnedPublicKey = parsePublicKey(metadata.public_key);
      return pinnedPublicKey;
    } catch (error) {
      if (error instanceof AgentSigningCapabilityError) throw error;
      throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.OUTPUT, { cause: error });
    }
  }

  async function signAgentSigningCapability(statement) {
    let signingNow;
    try { signingNow = exactNow(now()); }
    catch { throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG); }
    const normalized = normalizeAgentSigningCapabilityStatement(statement, { now: signingNow, allowExpired: false, allowFuture: false });
    if (normalized.key_id !== keyId) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
    const key = await publicKey();
    const bytes = agentSigningCapabilitySigningData(normalized);
    let output;
    try {
      output = await deadline(provider.sign({ bytes: Buffer.from(bytes), key_id: keyId, algorithm: AGENT_SIGNING_CAPABILITY_ALGORITHM, purpose: AGENT_SIGNING_CAPABILITY_OPERATION }), timeoutMs);
    } catch (error) {
      if (error instanceof AgentSigningCapabilityError) throw error;
      throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.PROVIDER, { cause: error });
    }
    const signature = canonicalSignature(output, AGENT_SIGNING_CAPABILITY_ERROR_CODES.OUTPUT);
    if (!crypto.verify(null, bytes, key, signature)) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE);
    return deepFreeze({
      version: AGENT_SIGNING_CAPABILITY_VERSION,
      type: AGENT_SIGNING_CAPABILITY_TYPE,
      statement: normalized,
      statement_hash: agentSigningCapabilityStatementHash(normalized),
      signature: signature.toString("base64url")
    });
  }

  return Object.freeze({ signAgentSigningCapability });
}

export function createLocalAgentSigningCapabilitySigner({ privateKey, keyId, timeoutMs, now } = {}) {
  let key;
  try { key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG); }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG);
  const publicKey = crypto.createPublicKey(key);
  return createAgentSigningCapabilitySigner({
    keyId,
    timeoutMs,
    now,
    provider: {
      async publicKeyMetadata() { return { key_id: keyId, algorithm: "ed25519", public_key: publicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, key); }
    }
  });
}

export function verifyAgentSigningCapability(envelope, {
  publicKey,
  keyId,
  organizationId,
  sessionId,
  deviceId,
  agentId,
  sequence,
  controlSequence,
  authorityGeneration,
  now = Date.now(),
  maxTtlMs = DEFAULT_MAX_TTL_MS
} = {}) {
  try {
    exactObject(envelope, ENVELOPE_KEYS);
    if (envelope.version !== AGENT_SIGNING_CAPABILITY_VERSION || envelope.type !== AGENT_SIGNING_CAPABILITY_TYPE) {
      fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
    }
    const statement = normalizeAgentSigningCapabilityStatement(envelope.statement, { now, allowExpired: false, allowFuture: false, maxTtlMs });
    const expected = { organization_id: organizationId, session_id: sessionId, device_id: deviceId, agent_id: agentId, key_id: keyId,
      sequence, control_sequence: controlSequence, authority_generation: authorityGeneration };
    if (Object.values(expected).some((value) => value === undefined)
      || Object.entries(expected).some(([field, value]) => statement[field] !== value)) {
      fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.AUTHORITY);
    }
    const expectedHash = agentSigningCapabilityStatementHash(statement);
    if (!SHA256.test(envelope.statement_hash ?? "") || !timingSafeText(envelope.statement_hash, expectedHash)) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE);
    const signature = canonicalSignature(envelope.signature, AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
    if (!crypto.verify(null, agentSigningCapabilitySigningData(statement), parsePublicKey(publicKey), signature)) {
      fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE);
    }
    return deepFreeze({ ...envelope, statement });
  } catch (error) {
    if (error instanceof AgentSigningCapabilityError) throw error;
    throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT, { cause: error });
  }
}

function normalizedSigningScope(value) {
  const scope = normalizeScope(value);
  if (scope.operations.length !== 1 || scope.operations[0] !== AGENT_SIGNING_CAPABILITY_OPERATION) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
  for (const list of [scope.operations, scope.repositories, scope.branches.allow, scope.branches.deny, scope.remotes.allow, scope.remotes.deny, scope.tags?.allow ?? [], scope.tags?.deny ?? []]) {
    if (new Set(list).size !== list.length) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
  }
  return scope;
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Reflect.ownKeys(value).some((key) => typeof key !== "string")
    || Object.keys(value).length !== keys.length || Object.keys(value).some((key) => !keys.includes(key))) {
    fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);
  }
}
function exact(value, expected) { if (value !== expected) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT); return expected; }
function pattern(value, expression) { if (typeof value !== "string" || !expression.test(value)) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT); return value; }
function integer(value) { if (!Number.isSafeInteger(value) || value < 1) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT); return value; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value || Date.parse(value) <= 0) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT); return value; }
function exactNow(value) { const result = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(result) || result <= 0) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT); return result; }
function parsePublicKey(value) { try { if (value?.type === "private" || /PRIVATE\s+KEY/iu.test(String(value))) fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG); const key = value?.type === "public" ? value : crypto.createPublicKey(value); if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG); return key; } catch (error) { if (error instanceof AgentSigningCapabilityError) throw error; throw new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG, { cause: error }); } }
function canonicalSignature(value, code) {
  if (value && typeof value === "object" && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    try { exactObject(value, ["signature"]); }
    catch { throw new AgentSigningCapabilityError(code); }
  }
  const candidate = value?.signature ?? value;
  const bytes = typeof candidate === "string" ? Buffer.from(candidate, "base64url") : Buffer.from(candidate ?? []);
  if (bytes.length !== 64 || (typeof candidate === "string" && (!/^[A-Za-z0-9_-]{86}$/u.test(candidate) || bytes.toString("base64url") !== candidate))) {
    throw new AgentSigningCapabilityError(code);
  }
  return bytes;
}
function timingSafeText(left, right) { const a = Buffer.from(left, "utf8"); const b = Buffer.from(right, "utf8"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function deadline(value, timeoutMs) { let timer; return Promise.race([Promise.resolve(value), new Promise((_, reject) => { timer = setTimeout(() => reject(new AgentSigningCapabilityError(AGENT_SIGNING_CAPABILITY_ERROR_CODES.PROVIDER)), timeoutMs); })]).finally(() => clearTimeout(timer)); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const nested of Object.values(value)) deepFreeze(nested); } return value; }
function fail(code) { throw new AgentSigningCapabilityError(code); }
function message(code) { return code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.CONFIG ? "agent signing capability configuration is invalid" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.PROVIDER ? "agent signing capability signer is unavailable" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.OUTPUT ? "agent signing capability signer output is invalid" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE ? "agent signing capability signature is invalid" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.AUTHORITY ? "agent signing capability authority does not match" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.EXPIRED ? "agent signing capability is expired" : code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.NOT_YET_VALID ? "agent signing capability is not yet valid" : "agent signing capability input is invalid"; }
