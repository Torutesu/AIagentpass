import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_GRANT_ISSUER,
  verifyAgentSessionGrant
} from "./agent-session-grant.mjs";

// Version 2 is intentionally incompatible with the first draft: the signed
// statement contains only Grant identity/digests. The response batch remains
// the transport for the seven full Grant envelopes.
export const QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION = 2;
export const QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE = "agentpass.qualification-grant-batch-manifest";
export const QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER = AGENT_SESSION_GRANT_ISSUER;
export const QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE = QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE;
export const QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN = "AgentPass-Qualification-Grant-Batch-v2\0";
export const QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM = "ed25519";

export const QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES = Object.freeze([
  Object.freeze({ index: 0, kind: "unarmed-control", scenario: null, phase: null }),
  Object.freeze({ index: 1, kind: "scenario", scenario: "pre-cloud-kill", phase: "pre-cloud" }),
  Object.freeze({ index: 2, kind: "scenario", scenario: "post-cloud-pre-local-kill", phase: "post-cloud-pre-local" }),
  Object.freeze({ index: 3, kind: "scenario", scenario: "post-activation-pre-audit-kill", phase: "post-activation-pre-audit" }),
  Object.freeze({ index: 4, kind: "scenario", scenario: "post-audit-pre-reply-loss", phase: "post-audit-pre-reply" }),
  Object.freeze({ index: 5, kind: "scenario", scenario: "audit-fsync-failure", phase: "audit-fsync" }),
  Object.freeze({ index: 6, kind: "scenario", scenario: "transport-reply-loss", phase: "transport-reply" })
]);

export const QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_CONFIG",
  INPUT: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_INPUT",
  PROVIDER: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_PROVIDER",
  OUTPUT: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_OUTPUT",
  SIGNATURE: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE",
  EXPIRED: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_EXPIRED",
  NOT_YET_VALID: "ERR_QUALIFICATION_GRANT_BATCH_MANIFEST_NOT_YET_VALID"
});

const DOMAIN = Buffer.from(QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN, "utf8");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
// A run binding is an opaque per-step nonce, not a user payload. Keeping its
// maximum at 64 bytes preserves ample uniqueness while making the maximum
// valid seven-step statement fit KMS RAW's 4 KiB ceiling.
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MANIFEST_STATEMENT_KEYS = Object.freeze([
  "version", "type", "batch_id", "organization_id", "device_id", "agent_id", "agent_kind",
  "requested_ttl_seconds", "candidate_sha256", "artifact_sha256", "source_commit", "team_id",
  "release_trust_sha256", "candidate_checkpoint_sha256", "issued_at", "expires_at", "steps", "issuer", "key_id"
]);
const MANIFEST_ENVELOPE_KEYS = Object.freeze(["version", "type", "statement", "statement_hash", "signature"]);
const STEP_KEYS = Object.freeze(["index", "kind", "scenario", "phase", "run_binding", "grant_id", "grant_hash", "statement_hash"]);
const MAX_TTL_SECONDS = 3_600;
const MIN_TTL_SECONDS = 60;
const MAX_STATEMENT_BYTES = 128 * 1024;
export const QUALIFICATION_GRANT_BATCH_MANIFEST_MAX_SIGNING_BYTES = 4_096;
const MAX_SIGNATURE_TIMEOUT_MS = 30_000;
const DEFAULT_SIGNATURE_TIMEOUT_MS = 5_000;

export class QualificationGrantBatchManifestError extends Error {
  constructor(code) {
    super(message(code));
    this.name = "QualificationGrantBatchManifestError";
    this.code = code;
  }
}

/**
 * Normalize the signed qualification statement. A step contains only the
 * exact identity and digests of the corresponding existing
 * agent-session-grant-v1 envelope. The full Grant is transported separately
 * in the Device API batch and is independently verified there.
 */
export function normalizeQualificationGrantBatchManifestStatement(input, {
  allowExpired = true,
  allowFuture = true,
  now,
  maxTtlSeconds = MAX_TTL_SECONDS
} = {}) {
  try {
    assertDataTree(input);
    exactObject(input, MANIFEST_STATEMENT_KEYS);
    const value = {
      version: exact(input.version, QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION),
      type: exact(input.type, QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE),
      batch_id: pattern(input.batch_id, UUID),
      organization_id: pattern(input.organization_id, UUID),
      device_id: pattern(input.device_id, UUID),
      agent_id: pattern(input.agent_id, UUID),
      agent_kind: enumeration(input.agent_kind, ["claude-code", "cursor"]),
      requested_ttl_seconds: integer(input.requested_ttl_seconds, MIN_TTL_SECONDS, maxTtlSeconds),
      candidate_sha256: pattern(input.candidate_sha256, SHA256),
      artifact_sha256: pattern(input.artifact_sha256, SHA256),
      source_commit: pattern(input.source_commit, SOURCE_COMMIT),
      team_id: pattern(input.team_id, TEAM_ID),
      release_trust_sha256: pattern(input.release_trust_sha256, SHA256),
      candidate_checkpoint_sha256: pattern(input.candidate_checkpoint_sha256, SHA256),
      issued_at: timestamp(input.issued_at),
      expires_at: timestamp(input.expires_at),
      steps: normalizeSteps(input.steps),
      issuer: exact(input.issuer, QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER),
      key_id: pattern(input.key_id, KEY_ID)
    };

    const issuedAtMs = Date.parse(value.issued_at);
    const expiresAtMs = Date.parse(value.expires_at);
    if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs !== value.requested_ttl_seconds * 1_000) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    const nowMs = now === undefined ? undefined : exactNow(now);
    if (!allowFuture && nowMs < issuedAtMs) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.NOT_YET_VALID);
    if (!allowExpired && nowMs >= expiresAtMs) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.EXPIRED);
    if (Buffer.byteLength(canonicalJson(value), "utf8") > MAX_STATEMENT_BYTES) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    return deepFreeze(value);
  } catch (error) {
    if (error instanceof QualificationGrantBatchManifestError) throw error;
    throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  }
}

export function qualificationGrantBatchManifestSigningData(statement) {
  const normalized = normalizeQualificationGrantBatchManifestStatement(statement);
  const bytes = Buffer.concat([DOMAIN, Buffer.from(canonicalJson(normalized), "utf8")]);
  if (bytes.length > QUALIFICATION_GRANT_BATCH_MANIFEST_MAX_SIGNING_BYTES) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  return bytes;
}

export function qualificationGrantBatchManifestStatementHash(statement) {
  const normalized = normalizeQualificationGrantBatchManifestStatement(statement);
  return sha256Text(canonicalJson(normalized));
}

/** Normalize a complete manifest without verifying its detached signature. */
export function normalizeQualificationGrantBatchManifest(input, options = {}) {
  try {
    assertDataTree(input);
    exactObject(input, MANIFEST_ENVELOPE_KEYS);
    if (input.version !== QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION || input.type !== QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    const statement = normalizeQualificationGrantBatchManifestStatement(input.statement, options);
    if (input.statement_hash !== qualificationGrantBatchManifestStatementHash(statement)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
    canonicalSignature(input.signature, QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    return deepFreeze({ version: input.version, type: input.type, statement, statement_hash: input.statement_hash, signature: input.signature });
  } catch (error) {
    if (error instanceof QualificationGrantBatchManifestError) throw error;
    throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  }
}

export function createQualificationGrantBatchManifestSigner({
  provider,
  keyId,
  timeoutMs = DEFAULT_SIGNATURE_TIMEOUT_MS,
  now = () => Date.now()
} = {}) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !KEY_ID.test(keyId ?? "") || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SIGNATURE_TIMEOUT_MS || typeof now !== "function") {
    throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG);
  }
  let pinnedPublicKey;

  async function publicKeyMetadata() {
    if (pinnedPublicKey) return Object.freeze({ key_id: keyId, algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM, public_key: pinnedPublicKey });
    let metadata;
    try {
      metadata = await deadline(provider.publicKeyMetadata({ key_id: keyId, purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE }), timeoutMs);
    } catch (error) {
      if (error instanceof QualificationGrantBatchManifestError) throw error;
      throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.PROVIDER);
    }
    try {
      exactObject(metadata, ["key_id", "algorithm", "public_key"]);
      if (metadata.key_id !== keyId || metadata.algorithm !== QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT);
      pinnedPublicKey = parsePublicKey(metadata.public_key, QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT);
      return Object.freeze({ key_id: keyId, algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM, public_key: pinnedPublicKey });
    } catch (error) {
      if (error instanceof QualificationGrantBatchManifestError) throw error;
      throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT);
    }
  }

  async function signQualificationGrantBatchManifest(statement) {
    let signingNow;
    try { signingNow = exactNow(now()); } catch { throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG); }
    const normalized = normalizeQualificationGrantBatchManifestStatement(statement, { now: signingNow, allowExpired: false, allowFuture: false });
    if (normalized.key_id !== keyId) throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    const metadata = await publicKeyMetadata();
    const bytes = qualificationGrantBatchManifestSigningData(normalized);
    let output;
    try {
      output = await deadline(provider.sign({
        bytes: Buffer.from(bytes),
        key_id: keyId,
        algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM,
        purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE
      }), timeoutMs);
    } catch (error) {
      if (error instanceof QualificationGrantBatchManifestError) throw error;
      throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.PROVIDER);
    }
    const signature = canonicalSignature(output, QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT);
    if (!crypto.verify(null, bytes, metadata.public_key, signature)) throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
    return deepFreeze({
      version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
      type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
      statement: normalized,
      statement_hash: qualificationGrantBatchManifestStatementHash(normalized),
      signature: signature.toString("base64url")
    });
  }

  return Object.freeze({ publicKeyMetadata, signQualificationGrantBatchManifest, signManifest: signQualificationGrantBatchManifest });
}

export function createLocalQualificationGrantBatchManifestSigner({ privateKey, keyId, timeoutMs, now } = {}) {
  let key;
  try { key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG); }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG);
  const publicKey = crypto.createPublicKey(key);
  return createQualificationGrantBatchManifestSigner({
    keyId,
    timeoutMs,
    now,
    provider: {
      async publicKeyMetadata() { return { key_id: keyId, algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM, public_key: publicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, key); }
    }
  });
}

export function verifyQualificationGrantBatchManifest(input, {
  publicKey,
  keyId,
  issuer = QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER,
  now = Date.now(),
  maxTtlSeconds = MAX_TTL_SECONDS,
  grants,
  grantPublicKey,
  grantKeyId
} = {}) {
  try {
    const manifest = normalizeQualificationGrantBatchManifest(input, { now, allowExpired: false, allowFuture: false, maxTtlSeconds });
    if (manifest.statement.issuer !== issuer || (keyId !== undefined && manifest.statement.key_id !== keyId)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
    const key = parsePublicKey(publicKey, QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG);
    if (!crypto.verify(null, qualificationGrantBatchManifestSigningData(manifest.statement), key, canonicalSignature(manifest.signature, QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT))) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
    const hasGrantVerificationOption = grants !== undefined || grantPublicKey !== undefined || grantKeyId !== undefined;
    if (hasGrantVerificationOption && (grants === undefined || grantPublicKey === undefined || typeof grantKeyId !== "string" || grantKeyId.length === 0)) {
      fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    }
    if (hasGrantVerificationOption) {
      if (!Array.isArray(grants) || grants.length !== manifest.statement.steps.length) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
      for (const [index, grant] of grants.entries()) {
        const verifiedGrant = verifyAgentSessionGrant(grant, { publicKey: grantPublicKey, keyId: grantKeyId, now });
        const step = manifest.statement.steps[index];
        if (verifiedGrant.statement.grant_id !== step.grant_id
          || verifiedGrant.statement_hash !== step.statement_hash
          || grantHash(verifiedGrant) !== step.grant_hash) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE);
      }
    }
    return manifest;
  } catch (error) {
    if (error instanceof QualificationGrantBatchManifestError) throw error;
    throw new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  }
}

export const verifyQualificationGrantBatchManifestSignature = verifyQualificationGrantBatchManifest;

function normalizeSteps(input) {
  if (!Array.isArray(input) || input.length !== QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES.length) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  const grantIds = new Set();
  const grantHashes = new Set();
  const statementHashes = new Set();
  const runBindings = new Set();
  return Object.freeze(input.map((step, index) => {
    assertDataTree(step);
    exactObject(step, STEP_KEYS);
    const expected = QUALIFICATION_GRANT_BATCH_MANIFEST_STEP_IDENTITIES[index];
    if (step.index !== expected.index || step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    const runBinding = pattern(step.run_binding, IDENTIFIER);
    const grantId = pattern(step.grant_id, UUID);
    const grantHashValue = pattern(step.grant_hash, SHA256);
    const statementHash = pattern(step.statement_hash, SHA256);
    for (const [set, value] of [[grantIds, grantId], [grantHashes, grantHashValue], [statementHashes, statementHash], [runBindings, runBinding]]) {
      if (set.has(value)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
      set.add(value);
    }
    return Object.freeze({ index: expected.index, kind: expected.kind, scenario: expected.scenario, phase: expected.phase, run_binding: runBinding, grant_id: grantId, grant_hash: grantHashValue, statement_hash: statementHash });
  }));
}

function grantHash(grant) { return sha256Text(canonicalJson(grant)); }
function sha256Text(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function exactObject(value, keys) {
  if (!plainObject(value) || Reflect.ownKeys(value).length !== keys.length || Object.keys(value).length !== keys.length || Object.keys(value).some((key) => !keys.includes(key))) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  }
}
function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  if (!plainObject(value) && !Array.isArray(value)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT);
    assertDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}
function plainObject(value) { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const prototype = Object.getPrototypeOf(value); return prototype === Object.prototype || prototype === null; }
function exact(value, expected) { if (value !== expected) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return expected; }
function pattern(value, expression) { if (typeof value !== "string" || !expression.test(value)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return value; }
function enumeration(value, values) { if (!values.includes(value)) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return value; }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return value; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return value; }
function exactNow(value) { const result = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(result) || result < 0) fail(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.INPUT); return result; }
function parsePublicKey(value, code) { try { if (value?.type === "private" || /PRIVATE\s+KEY/iu.test(String(value))) fail(code); const key = value?.type === "public" ? value : crypto.createPublicKey(value); if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(code); return key; } catch (error) { if (error instanceof QualificationGrantBatchManifestError) throw error; throw new QualificationGrantBatchManifestError(code); } }
function canonicalSignature(value, code) { const bytes = typeof value === "string" ? Buffer.from(value, "base64url") : Buffer.from(value ?? []); if (bytes.length !== 64 || (typeof value === "string" && (!SIGNATURE.test(value) || bytes.toString("base64url") !== value))) throw new QualificationGrantBatchManifestError(code); return bytes; }
function deadline(value, timeoutMs) { let timer; return Promise.race([Promise.resolve(value), new Promise((_, reject) => { timer = setTimeout(() => reject(new QualificationGrantBatchManifestError(QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.PROVIDER)), timeoutMs); })]).finally(() => clearTimeout(timer)); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const nested of Object.values(value)) deepFreeze(nested); } return value; }
function fail(code) { throw new QualificationGrantBatchManifestError(code); }
function message(code) { return code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.CONFIG ? "qualification grant batch manifest configuration is invalid" : code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.PROVIDER ? "qualification grant batch manifest signer is unavailable" : code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.OUTPUT ? "qualification grant batch manifest signer output is invalid" : code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.SIGNATURE ? "qualification grant batch manifest signature is invalid" : code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.EXPIRED ? "qualification grant batch manifest is expired" : code === QUALIFICATION_GRANT_BATCH_MANIFEST_ERROR_CODES.NOT_YET_VALID ? "qualification grant batch manifest is not yet valid" : "qualification grant batch manifest input is invalid"; }
