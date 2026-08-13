import crypto from "node:crypto";

import { canonicalJson, normalizeScope } from "../../../packages/protocol/src/index.mjs";

export const AGENT_SESSION_GRANT_VERSION = 1;
export const AGENT_SESSION_GRANT_TYPE = "agentpass.agent-session-grant";
export const AGENT_SESSION_GRANT_ISSUER = "agentpass-cloud";
export const AGENT_SESSION_GRANT_SIGNATURE_DOMAIN = "AgentPass-Agent-Session-Grant-v1\0";

export const AGENT_SESSION_GRANT_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SESSION_GRANT_CONFIG",
  INPUT: "ERR_AGENT_SESSION_GRANT_INPUT",
  PROVIDER: "ERR_AGENT_SESSION_GRANT_PROVIDER",
  OUTPUT: "ERR_AGENT_SESSION_GRANT_OUTPUT",
  SIGNATURE: "ERR_AGENT_SESSION_GRANT_SIGNATURE",
  EXPIRED: "ERR_AGENT_SESSION_GRANT_EXPIRED",
  NOT_YET_VALID: "ERR_AGENT_SESSION_GRANT_NOT_YET_VALID"
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const SEMVER = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const AGENT_KINDS = Object.freeze(["claude-code", "cursor"]);
const STATEMENT_KEYS = Object.freeze([
  "version", "grant_id", "organization_id", "device_id", "agent_id", "agent_kind",
  "adapter_id", "adapter_version", "worktree_binding_sha256", "process_binding_policy_id",
  "scope", "max_signatures", "not_before", "expires_at", "control_sequence", "issuer", "key_id"
]);
const ENVELOPE_KEYS = Object.freeze(["version", "type", "statement", "statement_hash", "signature"]);
const MAX_STATEMENT_BYTES = 32 * 1024;
const MAX_TTL_MS = 60 * 60 * 1000;
const DOMAIN = Buffer.from(AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, "utf8");

export class AgentSessionGrantError extends Error {
  constructor(code) {
    super(message(code));
    this.name = "AgentSessionGrantError";
    this.code = code;
  }
}

export function normalizeAgentSessionGrantStatement(input, { now, allowExpired = true, allowFuture = true, maxTtlMs = MAX_TTL_MS } = {}) {
  try {
    exactObject(input, STATEMENT_KEYS);
    const statement = {
      version: exact(input.version, AGENT_SESSION_GRANT_VERSION),
      grant_id: pattern(input.grant_id, UUID),
      organization_id: pattern(input.organization_id, UUID),
      device_id: pattern(input.device_id, UUID),
      agent_id: pattern(input.agent_id, UUID),
      agent_kind: enumeration(input.agent_kind, AGENT_KINDS),
      adapter_id: pattern(input.adapter_id, UUID),
      adapter_version: pattern(input.adapter_version, SEMVER),
      worktree_binding_sha256: pattern(input.worktree_binding_sha256, SHA256),
      process_binding_policy_id: pattern(input.process_binding_policy_id, IDENTIFIER),
      scope: normalizeAndValidateScope(input.scope),
      max_signatures: integer(input.max_signatures, 1, 64),
      not_before: timestamp(input.not_before),
      expires_at: timestamp(input.expires_at),
      control_sequence: integer(input.control_sequence, 1, Number.MAX_SAFE_INTEGER),
      issuer: exact(input.issuer, AGENT_SESSION_GRANT_ISSUER),
      key_id: pattern(input.key_id, IDENTIFIER)
    };
    const notBeforeMs = Date.parse(statement.not_before);
    const expiresAtMs = Date.parse(statement.expires_at);
    if (expiresAtMs <= notBeforeMs || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || expiresAtMs - notBeforeMs > maxTtlMs) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
    const nowMs = now === undefined ? undefined : exactNow(now);
    if (!allowFuture && nowMs < notBeforeMs) fail(AGENT_SESSION_GRANT_ERROR_CODES.NOT_YET_VALID);
    if (!allowExpired && nowMs >= expiresAtMs) fail(AGENT_SESSION_GRANT_ERROR_CODES.EXPIRED);
    if (Buffer.byteLength(canonicalJson(statement), "utf8") > MAX_STATEMENT_BYTES) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
    return deepFreeze(statement);
  } catch (error) {
    if (error instanceof AgentSessionGrantError) throw error;
    throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
  }
}

export function agentSessionGrantSigningData(statement) {
  const normalized = normalizeAgentSessionGrantStatement(statement);
  return Buffer.concat([DOMAIN, Buffer.from(canonicalJson(normalized), "utf8")]);
}

export function agentSessionGrantStatementHash(statement) {
  const normalized = normalizeAgentSessionGrantStatement(statement);
  return crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex");
}

export function createAgentSessionGrantSigner({ provider, keyId, timeoutMs = 5_000, now = () => Date.now() } = {}) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !IDENTIFIER.test(keyId ?? "") || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 || typeof now !== "function") {
    throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG);
  }
  let pinnedPublicKey;

  async function publicKey() {
    if (pinnedPublicKey) return pinnedPublicKey;
    let metadata;
    try { metadata = await deadline(provider.publicKeyMetadata({ key_id: keyId, purpose: AGENT_SESSION_GRANT_TYPE }), timeoutMs); }
    catch (error) { if (error instanceof AgentSessionGrantError) throw error; throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.PROVIDER); }
    try {
      exactObject(metadata, ["key_id", "algorithm", "public_key"]);
      if (metadata.key_id !== keyId || metadata.algorithm !== "ed25519" || metadata.public_key?.type === "private" || /PRIVATE\s+KEY/iu.test(String(metadata.public_key))) fail(AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT);
      const key = metadata.public_key?.type === "public" ? metadata.public_key : crypto.createPublicKey(metadata.public_key);
      if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT);
      pinnedPublicKey = key;
      return key;
    } catch (error) { if (error instanceof AgentSessionGrantError) throw error; throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT); }
  }

  async function signAgentSessionGrant(statement) {
    let signingNow;
    try { signingNow = exactNow(now()); } catch { throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG); }
    const normalized = normalizeAgentSessionGrantStatement(statement, { allowExpired: false, allowFuture: false, now: signingNow });
    if (normalized.key_id !== keyId) throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
    const key = await publicKey();
    const bytes = agentSessionGrantSigningData(normalized);
    let output;
    try { output = await deadline(provider.sign({ bytes: Buffer.from(bytes), key_id: keyId, algorithm: "ed25519", purpose: AGENT_SESSION_GRANT_TYPE }), timeoutMs); }
    catch (error) { if (error instanceof AgentSessionGrantError) throw error; throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.PROVIDER); }
    const signature = canonicalSignature(output, AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT);
    if (!crypto.verify(null, bytes, key, signature)) throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.SIGNATURE);
    return deepFreeze({
      version: AGENT_SESSION_GRANT_VERSION,
      type: AGENT_SESSION_GRANT_TYPE,
      statement: normalized,
      statement_hash: agentSessionGrantStatementHash(normalized),
      signature: signature.toString("base64url")
    });
  }

  return Object.freeze({ signAgentSessionGrant });
}

export function createLocalAgentSessionGrantSigner({ privateKey, keyId, timeoutMs, now } = {}) {
  let key;
  try { key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG); }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG);
  const publicKey = crypto.createPublicKey(key);
  return createAgentSessionGrantSigner({
    keyId,
    timeoutMs,
    now,
    provider: {
      async publicKeyMetadata() { return { key_id: keyId, algorithm: "ed25519", public_key: publicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, key); }
    }
  });
}

export function verifyAgentSessionGrant(envelope, { publicKey, issuer = AGENT_SESSION_GRANT_ISSUER, keyId, now = Date.now(), maxTtlMs = MAX_TTL_MS } = {}) {
  try {
    exactObject(envelope, ENVELOPE_KEYS);
    if (envelope.version !== AGENT_SESSION_GRANT_VERSION || envelope.type !== AGENT_SESSION_GRANT_TYPE) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
    const statement = normalizeAgentSessionGrantStatement(envelope.statement, { now, allowExpired: false, allowFuture: false, maxTtlMs });
    if (statement.issuer !== issuer || (keyId !== undefined && statement.key_id !== keyId)) fail(AGENT_SESSION_GRANT_ERROR_CODES.SIGNATURE);
    const expectedHash = agentSessionGrantStatementHash(statement);
    if (!SHA256.test(envelope.statement_hash ?? "") || !timingSafeText(envelope.statement_hash, expectedHash)) fail(AGENT_SESSION_GRANT_ERROR_CODES.SIGNATURE);
    const key = parsePublicKey(publicKey);
    const signature = canonicalSignature(envelope.signature, AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
    if (!crypto.verify(null, agentSessionGrantSigningData(statement), key, signature)) fail(AGENT_SESSION_GRANT_ERROR_CODES.SIGNATURE);
    return deepFreeze({ ...envelope, statement });
  } catch (error) {
    if (error instanceof AgentSessionGrantError) throw error;
    throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
  }
}

function normalizeAndValidateScope(value) {
  const scope = normalizeScope(value);
  for (const list of [scope.operations, scope.repositories, scope.branches.allow, scope.branches.deny, scope.remotes.allow, scope.remotes.deny, scope.tags?.allow ?? [], scope.tags?.deny ?? []]) {
    if (new Set(list).size !== list.length) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
  }
  return scope;
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Reflect.ownKeys(value).some((key) => typeof key !== "string") || Object.keys(value).length !== keys.length || Object.keys(value).some((key) => !keys.includes(key))) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
}
function exact(value, expected) { if (value !== expected) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return expected; }
function pattern(value, expression) { if (typeof value !== "string" || !expression.test(value)) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return value; }
function enumeration(value, values) { if (!values.includes(value)) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return value; }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return value; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return value; }
function exactNow(value) { const result = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(result) || result < 0) fail(AGENT_SESSION_GRANT_ERROR_CODES.INPUT); return result; }
function parsePublicKey(value) { try { if (value?.type === "private" || /PRIVATE\s+KEY/iu.test(String(value))) fail(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG); const key = value?.type === "public" ? value : crypto.createPublicKey(value); if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG); return key; } catch (error) { if (error instanceof AgentSessionGrantError) throw error; throw new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.CONFIG); } }
function canonicalSignature(value, code) { const bytes = typeof value === "string" ? Buffer.from(value, "base64url") : Buffer.from(value ?? []); if (bytes.length !== 64 || (typeof value === "string" && (!/^[A-Za-z0-9_-]{86}$/u.test(value) || bytes.toString("base64url") !== value))) throw new AgentSessionGrantError(code); return bytes; }
function timingSafeText(left, right) { const a = Buffer.from(left, "utf8"); const b = Buffer.from(right, "utf8"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function deadline(value, timeoutMs) { let timer; return Promise.race([Promise.resolve(value), new Promise((_, reject) => { timer = setTimeout(() => reject(new AgentSessionGrantError(AGENT_SESSION_GRANT_ERROR_CODES.PROVIDER)), timeoutMs); })]).finally(() => clearTimeout(timer)); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const nested of Object.values(value)) deepFreeze(nested); } return value; }
function fail(code) { throw new AgentSessionGrantError(code); }
function message(code) { return code === AGENT_SESSION_GRANT_ERROR_CODES.CONFIG ? "agent session grant configuration is invalid" : code === AGENT_SESSION_GRANT_ERROR_CODES.PROVIDER ? "agent session grant signer is unavailable" : code === AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT ? "agent session grant signer output is invalid" : code === AGENT_SESSION_GRANT_ERROR_CODES.SIGNATURE ? "agent session grant signature is invalid" : code === AGENT_SESSION_GRANT_ERROR_CODES.EXPIRED ? "agent session grant is expired" : code === AGENT_SESSION_GRANT_ERROR_CODES.NOT_YET_VALID ? "agent session grant is not yet valid" : "agent session grant input is invalid"; }
