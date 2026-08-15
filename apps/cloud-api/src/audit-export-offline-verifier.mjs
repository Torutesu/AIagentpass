import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_ERROR_CODES,
  AUDIT_ANCHOR_MAX_TTL_MS,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorPublicKeyFingerprint,
  normalizeAuditAnchor,
  parseAuditAnchorPublicKey
} from "./audit-anchor-statement.mjs";
import { verifyAuditAnchor } from "./audit-anchor-verifier.mjs";
import {
  AUDIT_EXPORT_MAX_ENTRY_BYTES,
  AUDIT_EXPORT_MAX_PAYLOAD_BYTES,
  AUDIT_EXPORT_MAX_ROWS,
  AUDIT_EXPORT_SNAPSHOT_TYPE,
  AUDIT_EXPORT_SNAPSHOT_VERSION,
  canonicalAuditExportEntry,
  foldAuditExportRoot
} from "./postgres/audit-export-snapshot-reader.mjs";

export const AUDIT_EXPORT_OFFLINE_VERIFIER_VERSION = 1;

export const AUDIT_EXPORT_OFFLINE_REASONS = Object.freeze([
  "valid",
  "payload_digest_mismatch",
  "root_mismatch",
  "anchor_invalid",
  "historical_key_unavailable",
  "invalid_export"
]);

const INTERNAL_RESULT_KEYS = Object.freeze([
  "valid",
  "input_valid",
  "payload_digest_valid",
  "positions_valid",
  "root_valid",
  "anchor_binding_valid",
  "signature_valid",
  "lifecycle_valid",
  "reason"
]);
const DTO_KEYS = Object.freeze([
  "organization_id", "export_id", "environment", "chain", "range", "payload_digest", "payload", "audit_anchor", "validity"
]);
const RANGE_KEYS = Object.freeze([
  "from_audit_position", "to_audit_position", "previous_root_digest", "root_digest", "record_count"
]);
const PAYLOAD_KEYS = Object.freeze([
  "version", "type", "organization_id", "environment", "chain", "range", "entries"
]);
const ENTRY_KEYS = Object.freeze([
  "version", "organization_id", "environment", "chain", "export_position", "source_id", "source_device_id",
  "source_previous_hash", "source_hash", "source_gap", "event"
]);
const ADMIN_EVENT_KEYS = Object.freeze([
  "version", "audit_event_id", "organization_id", "actor_id", "action", "target_type", "target_id", "details",
  "previous_hash", "sequence", "event_hash", "recorded_at"
]);
const CLOUD_EVENT_KEYS = Object.freeze([
  "organization_id", "sequence", "event_id", "event_type", "grant_id", "session_id", "device_id", "agent_id",
  "grant_hash", "statement_hash", "signer_key_id", "process_binding_sha256", "ancestry_binding_sha256",
  "worktree_binding_sha256", "control_sequence", "authority_generation", "consumed_at", "recorded_at",
  "previous_hash", "event_hash"
]);
const DEVICE_EVENT_KEYS = Object.freeze([
  "version", "event_id", "request_id", "agent_id", "operation", "decision", "reason", "policy_sequence",
  "capability_sequence", "repository", "branch", "remote", "payload_digest", "device_timestamp", "previous_hash",
  "event_hash", "received_at"
]);
const METADATA_KEYS = Object.freeze([
  "version", "type", "purpose", "domain", "protocol_version", "signing_version", "algorithm", "key_id",
  "key_version", "lifecycle_version", "public_key", "public_key_fingerprint"
]);
const OPTIONS_KEYS = Object.freeze(["publicKeyResolver", "now", "maxTtlMs"]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const CHAINS = new Set(["admin", "cloud_agent", "device"]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const CLOUD_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SIGNATURE_DOMAIN = AUDIT_ANCHOR_SIGNATURE_DOMAIN;
const PRIVATE_FIELD = /(?:private(?:[_ -]?key|[_ -]?material)?|secret|password|credential|authorization|bearer|cookie|claim[_ -]?token|raw[_ -]?signature|provider[_ -]?diagnostic)/iu;
const PRIVATE_PEM = /-----BEGIN [^-]*PRIVATE KEY-----/iu;
const MAX_TREE_DEPTH = 16;
const MAX_TREE_ITEMS = 4096;
const MAX_STRING_BYTES = 16 * 1024;
const MAX_DTO_BYTES = 256 * 1024;

/**
 * Verify the immutable public audit-export DTO without a signer or private key.
 * The only external boundary is a resolver for historical public-key metadata.
 * All failures are converted to a frozen, redacted public result.
 */
export async function verifyOfflineAuditExport(input, options = {}) {
  return mapPublicResult(await verifyOfflineAuditExportInternal(input, options));
}

async function verifyOfflineAuditExportInternal(input, options = {}) {
  const failed = resultTemplate();
  let config;
  try {
    config = normalizeOptions(options);
  } catch {
    return freezeResult({ ...failed, reason: "invalid_input" });
  }

  let dto;
  try {
    dto = normalizeDto(input);
  } catch {
    return freezeResult({ ...failed, reason: "invalid_input" });
  }

  const state = {
    ...failed,
    input_valid: true
  };
  let payloadState;
  try {
    payloadState = validatePayload(dto);
    state.positions_valid = payloadState.positionsValid;
    state.root_valid = payloadState.rootValid;
    state.payload_digest_valid = sha256(canonicalJson(dto.payload)) === dto.payload_digest;
    if (!state.positions_valid) return finish(state, "positions_invalid");
    if (!state.root_valid) return finish(state, "root_mismatch");
    if (!state.payload_digest_valid) return finish(state, "payload_digest_mismatch");
  } catch (error) {
    if (error instanceof OfflineVerificationFailure && error.code === "positions_invalid") {
      return finish(state, "positions_invalid");
    }
    return finish(state, "payload_invalid");
  }

  let normalizedAnchor;
  try {
    normalizedAnchor = normalizeAuditAnchor(dto.audit_anchor, { allowExpired: true, allowFuture: true, maxTtlMs: config.maxTtlMs });
  } catch {
    return finish(state, "anchor_binding_invalid");
  }

  const statement = normalizedAnchor.statement;
  state.anchor_binding_valid = anchorBindsDto(statement, dto);
  if (!state.anchor_binding_valid) return finish(state, "anchor_binding_invalid");

  let metadata;
  try {
    metadata = await resolveHistoricalMetadata(config.publicKeyResolver, statement);
  } catch {
    return finish(state, "historical_key_unavailable");
  }
  state.lifecycle_valid = metadata.key_id === statement.key_id
    && metadata.key_version === statement.key_version
    && metadata.lifecycle_version === statement.lifecycle_version;
  if (!state.lifecycle_valid) return finish(state, "lifecycle_mismatch");

  const nowMs = config.now;
  const issuedAtMs = Date.parse(statement.issued_at);
  const expiresAtMs = Date.parse(statement.expires_at);
  const expectedValidity = nowMs < issuedAtMs ? "active" : nowMs < expiresAtMs ? "active" : "expired";
  if (dto.validity !== expectedValidity) return finish(state, "validity_mismatch");

  try {
    verifyAuditAnchor(dto.audit_anchor, {
      publicKey: metadata.public_key,
      organizationId: dto.organization_id,
      environment: dto.environment,
      chain: dto.chain,
      exportId: dto.export_id,
      auditPosition: dto.range.to_audit_position,
      rootDigest: dto.range.root_digest,
      exportDigest: dto.payload_digest,
      recordCount: dto.range.record_count,
      keyId: statement.key_id,
      keyVersion: statement.key_version,
      lifecycleVersion: statement.lifecycle_version,
      previousAuditPosition: dto.range.from_audit_position - 1,
      previousRootDigest: dto.range.previous_root_digest,
      now: nowMs,
      maxTtlMs: config.maxTtlMs
    });
    state.signature_valid = true;
  } catch (error) {
    if (error?.code === AUDIT_ANCHOR_ERROR_CODES.EXPIRED) return finish(state, "expired");
    if (error?.code === AUDIT_ANCHOR_ERROR_CODES.NOT_YET_VALID) return finish(state, "not_yet_valid");
    return finish(state, "signature_invalid");
  }
  return finish(state, "valid");
}

export const verifyAuditExportOffline = verifyOfflineAuditExport;

export function createOfflineAuditExportVerifier(options = {}) {
  const config = normalizeOptions(options);
  return Object.freeze({
    verify: (input) => verifyOfflineAuditExport(input, config),
    verifyAuditExport: (input) => verifyOfflineAuditExport(input, config)
  });
}

function normalizeOptions(value) {
  if (!plainObject(value)) throw new Error("options");
  exactKeys(value, OPTIONS_KEYS, true);
  const resolver = value.publicKeyResolver;
  if (typeof resolver !== "function") throw new Error("resolver");
  const now = value.now === undefined ? Date.now() : value.now instanceof Date ? value.now.getTime() : value.now;
  const maxTtlMs = value.maxTtlMs === undefined ? AUDIT_ANCHOR_MAX_TTL_MS : value.maxTtlMs;
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > AUDIT_ANCHOR_MAX_TTL_MS) {
    throw new Error("options");
  }
  return Object.freeze({ publicKeyResolver: resolver, now, maxTtlMs });
}

function normalizeDto(value) {
  assertDataTree(value);
  exactKeys(value, DTO_KEYS);
  const dto = {
    organization_id: uuid(value.organization_id),
    export_id: uuid(value.export_id),
    environment: enumeration(value.environment, ENVIRONMENTS),
    chain: enumeration(value.chain, CHAINS),
    range: normalizeRange(value.range),
    payload_digest: digest(value.payload_digest, false),
    payload: normalizePayload(value.payload, value),
    audit_anchor: value.audit_anchor,
    validity: enumeration(value.validity, new Set(["active", "expired"]))
  };
  const encodedBytes = Buffer.byteLength(canonicalJson(dto), "utf8");
  if (encodedBytes > MAX_DTO_BYTES) throw new Error("size");
  return dto;
}

function normalizePayload(value, dto) {
  assertDataTree(value);
  exactKeys(value, PAYLOAD_KEYS);
  if (value.version !== AUDIT_EXPORT_SNAPSHOT_VERSION || value.type !== AUDIT_EXPORT_SNAPSHOT_TYPE
    || value.organization_id !== dto.organization_id || value.environment !== dto.environment || value.chain !== dto.chain) {
    throw new Error("payload");
  }
  const range = normalizeRange(value.range);
  if (canonicalJson(range) !== canonicalJson(dto.range) || !Array.isArray(value.entries)
    || value.entries.length !== range.record_count || value.entries.length > AUDIT_EXPORT_MAX_ROWS) throw new Error("payload");
  const payloadBytes = Buffer.byteLength(canonicalJson(value), "utf8");
  if (payloadBytes > AUDIT_EXPORT_MAX_PAYLOAD_BYTES) throw new Error("size");
  return value;
}

function validatePayload(dto) {
  const range = dto.range;
  const positionsValid = range.to_audit_position - range.from_audit_position + 1 === range.record_count;
  if (!positionsValid) return { positionsValid: false, rootValid: false };
  let root = range.previous_root_digest;
  const lastByDevice = new Map();
  for (let index = 0; index < dto.payload.entries.length; index += 1) {
    const entry = validateEntry(dto.payload.entries[index], dto.chain, dto.organization_id, dto.environment, range.from_audit_position + index, lastByDevice);
    if (Buffer.byteLength(canonicalJson(entry), "utf8") > AUDIT_EXPORT_MAX_ENTRY_BYTES) throw new Error("size");
    root = foldAuditExportRoot(root, entry);
  }
  return { positionsValid: true, rootValid: root === range.root_digest };
}

function validateEntry(value, chain, organizationId, environment, position, lastByDevice) {
  const entry = canonicalAuditExportEntry(value);
  if (entry.version !== AUDIT_EXPORT_OFFLINE_VERIFIER_VERSION || entry.organization_id !== organizationId
    || entry.environment !== environment || entry.chain !== chain
    || entry.source_gap !== null || !isDigest(entry.source_previous_hash, true) || !isDigest(entry.source_hash, false)) {
    throw new Error("entry");
  }
  if (entry.export_position !== position) throw new OfflineVerificationFailure("positions_invalid");
  const expectedDeviceId = chain === "device" ? uuid(entry.source_device_id) : null;
  if (chain !== "device" && entry.source_device_id !== null) throw new Error("entry");
  const event = entry.event;
  if (chain === "admin") validateAdminEvent(event, entry, position, organizationId);
  else if (chain === "cloud_agent") validateCloudEvent(event, entry, position, organizationId);
  else validateDeviceEvent(event, entry, position, organizationId, expectedDeviceId, lastByDevice);
  if (chain !== "device" && entry.source_id !== eventIdFor(event, chain)) throw new Error("entry");
  if (entry.source_previous_hash !== event.previous_hash || entry.source_hash !== event.event_hash) throw new Error("entry");
  return entry;
}

function validateAdminEvent(event, entry, position, organizationId) {
  exactKeys(event, ADMIN_EVENT_KEYS);
  if (event.version !== 2 || event.organization_id !== organizationId || event.audit_event_id !== uuid(event.audit_event_id)
    || event.actor_id !== uuid(event.actor_id) || !text(event.action, 128) || !text(event.target_type, 64)
    || (event.target_id !== null && event.target_id !== uuid(event.target_id)) || !plainObject(event.details)
    || !isDigest(event.previous_hash, true) || event.sequence !== position || !isDigest(event.event_hash, false)
    || !timestamp(event.recorded_at)) throw new Error("admin");
  const { event_hash: _eventHash, recorded_at: _recordedAt, ...preimage } = event;
  if (sha256(canonicalJson(preimage)) !== event.event_hash || entry.source_id !== event.audit_event_id) throw new Error("admin");
}

function validateCloudEvent(event, entry, position, organizationId) {
  exactKeys(event, CLOUD_EVENT_KEYS);
  if (event.organization_id !== organizationId || event.sequence !== position || event.event_type !== "agent_session_grant.consumed"
    || event.event_id !== uuid(event.event_id) || event.grant_id !== uuid(event.grant_id) || event.session_id !== uuid(event.session_id)
    || event.device_id !== uuid(event.device_id) || event.agent_id !== uuid(event.agent_id) || !isDigest(event.grant_hash, false)
    || !isDigest(event.statement_hash, false) || !cloudKeyId(event.signer_key_id) || !isDigest(event.process_binding_sha256, false)
    || !isDigest(event.ancestry_binding_sha256, false) || !isDigest(event.worktree_binding_sha256, false)
    || !positiveInteger(event.control_sequence) || !positiveInteger(event.authority_generation)
    || !timestamp(event.consumed_at) || !timestamp(event.recorded_at) || !isDigest(event.previous_hash, true)
    || !isDigest(event.event_hash, false)) throw new Error("cloud");
  const { event_hash: _eventHash, ...preimage } = event;
  if (sha256(canonicalJson(preimage)) !== event.event_hash || entry.source_id !== event.event_id) throw new Error("cloud");
}

function validateDeviceEvent(event, entry, position, organizationId, deviceId, lastByDevice) {
  exactKeys(event, DEVICE_EVENT_KEYS);
  if (event.version !== 1 || event.event_id !== uuid(event.event_id) || event.request_id !== uuid(event.request_id)
    || event.agent_id !== uuid(event.agent_id) || event.operation !== "git.commit.sign"
    || !new Set(["allow", "deny", "error"]).has(event.decision) || !text(event.reason, 128)
    || !nonNegativeInteger(event.policy_sequence) || !nonNegativeInteger(event.capability_sequence)
    || !text(event.repository, 4096) || !text(event.branch, 2048) || !text(event.remote, 2048)
    || !isDigest(event.payload_digest, false) || !timestamp(event.device_timestamp) || !isDigest(event.previous_hash, true)
    || !isDigest(event.event_hash, false) || !timestamp(event.received_at) || entry.source_id !== event.event_id) throw new Error("device");
  const prior = lastByDevice.get(deviceId);
  if (prior !== undefined && event.previous_hash !== prior) throw new OfflineVerificationFailure("positions_invalid");
  lastByDevice.set(deviceId, event.event_hash);
  const { event_hash: _eventHash, received_at: _receivedAt, ...preimage } = event;
  if (sha256(canonicalJson(preimage)) !== event.event_hash) throw new Error("device");
}

function eventIdFor(event, chain) {
  return chain === "admin" ? event.audit_event_id : event.event_id;
}

async function resolveHistoricalMetadata(resolver, statement) {
  const request = {
    purpose: AUDIT_ANCHOR_PURPOSE,
    algorithm: AUDIT_ANCHOR_ALGORITHM,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    key_id: statement.key_id,
    key_version: statement.key_version,
    lifecycle_version: statement.lifecycle_version
  };
  const value = await resolver(Object.freeze(request));
  assertDataTree(value);
  exactKeys(value, METADATA_KEYS);
  if (value.version !== AUDIT_ANCHOR_VERSION || value.type !== AUDIT_ANCHOR_TYPE || value.purpose !== AUDIT_ANCHOR_PURPOSE
    || value.domain !== SIGNATURE_DOMAIN || value.protocol_version !== AUDIT_ANCHOR_PROTOCOL_VERSION
    || value.signing_version !== AUDIT_ANCHOR_SIGNING_VERSION || value.algorithm !== AUDIT_ANCHOR_ALGORITHM
    || !IDENTIFIER.test(value.key_id) || !positiveInteger(value.key_version) || !positiveInteger(value.lifecycle_version)
    || typeof value.public_key !== "string" || typeof value.public_key_fingerprint !== "string") throw new Error("metadata");
  const publicKey = parseAuditAnchorPublicKey(value.public_key, AUDIT_ANCHOR_ERROR_CODES.CONFIG);
  if (auditAnchorPublicKeyFingerprint(publicKey) !== value.public_key_fingerprint) throw new Error("metadata");
  if (value.public_key_fingerprint !== value.public_key_fingerprint.trim()) throw new Error("metadata");
  return Object.freeze({ ...value, public_key: value.public_key, publicKey });
}

function anchorBindsDto(statement, dto) {
  return statement.organization_id === dto.organization_id && statement.environment === dto.environment
    && statement.chain === dto.chain && statement.export_id === dto.export_id
    && statement.audit_position === dto.range.to_audit_position
    && statement.previous_audit_position === dto.range.from_audit_position - 1
    && statement.root_digest === dto.range.root_digest
    && statement.previous_root_digest === dto.range.previous_root_digest
    && statement.export_digest === dto.payload_digest
    && statement.record_count === dto.range.record_count;
}

function normalizeRange(value) {
  assertDataTree(value);
  exactKeys(value, RANGE_KEYS);
  const range = {
    from_audit_position: positiveInteger(value.from_audit_position),
    to_audit_position: positiveInteger(value.to_audit_position),
    previous_root_digest: digest(value.previous_root_digest, true),
    root_digest: digest(value.root_digest, false),
    record_count: positiveInteger(value.record_count)
  };
  if (range.to_audit_position < range.from_audit_position || range.record_count > AUDIT_EXPORT_MAX_ROWS
    || range.to_audit_position - range.from_audit_position + 1 !== range.record_count
    || (range.from_audit_position === 1 && range.previous_root_digest !== AUDIT_ANCHOR_ZERO_DIGEST)
    || (range.from_audit_position > 1 && range.previous_root_digest === AUDIT_ANCHOR_ZERO_DIGEST)) throw new Error("range");
  return range;
}

function assertDataTree(value, seen = new Set(), depth = 0, counter = { value: 0 }) {
  if (value === null) return;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES || PRIVATE_PEM.test(value)) throw new Error("private");
    return;
  }
  if (typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error("number");
    return;
  }
  if (typeof value !== "object" || depth > MAX_TREE_DEPTH || seen.has(value)) throw new Error("tree");
  if (counter.value++ > MAX_TREE_ITEMS) throw new Error("items");
  const isArray = Array.isArray(value);
  if (isArray ? Object.getPrototypeOf(value) !== Array.prototype : Object.getPrototypeOf(value) !== Object.prototype) throw new Error("prototype");
  seen.add(value);
  const keys = Reflect.ownKeys(value);
  if (isArray) {
    if (keys.length !== value.length + 1 || !keys.includes("length")) throw new Error("array");
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new Error("descriptor");
      assertDataTree(descriptor.value, seen, depth + 1, counter);
    }
  } else {
    for (const key of keys) {
      if (typeof key !== "string" || PRIVATE_FIELD.test(key) || key === "__proto__" || key === "constructor" || key === "prototype") throw new Error("field");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new Error("descriptor");
      assertDataTree(descriptor.value, seen, depth + 1, counter);
    }
  }
  seen.delete(value);
}

function exactKeys(value, keys, allowMissing = false) {
  if (!plainObject(value)) throw new Error("object");
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key)) || (!allowMissing && actual.length !== keys.length) || (allowMissing && actual.length > keys.length)) throw new Error("keys");
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) throw new Error("descriptor");
  }
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new Error("uuid"); return value; }
function digest(value, allowZero) { if (!isDigest(value, allowZero)) throw new Error("digest"); return value; }
function isDigest(value, allowZero) { return typeof value === "string" && DIGEST.test(value) && (allowZero || value !== AUDIT_ANCHOR_ZERO_DIGEST); }
function enumeration(value, allowed) { if (typeof value !== "string" || !allowed.has(value)) throw new Error("enum"); return value; }
function positiveInteger(value) { if (!Number.isSafeInteger(value) || value < 1) throw new Error("integer"); return value; }
function nonNegativeInteger(value) { if (!Number.isSafeInteger(value) || value < 0) throw new Error("integer"); return value; }
function text(value, maxBytes) { if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("text"); return value; }
function cloudKeyId(value) { if (typeof value !== "string" || !CLOUD_KEY_ID.test(value)) throw new Error("key"); return value; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) throw new Error("timestamp"); return value; }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }

function resultTemplate() {
  return { valid: false, input_valid: false, payload_digest_valid: false, positions_valid: false, root_valid: false, anchor_binding_valid: false, signature_valid: false, lifecycle_valid: false, reason: "invalid_input" };
}

function finish(state, reason) {
  const output = { ...state, reason };
  output.valid = reason === "valid" && output.input_valid && output.payload_digest_valid && output.positions_valid
    && output.root_valid && output.anchor_binding_valid && output.signature_valid && output.lifecycle_valid;
  return freezeResult(output);
}

function freezeResult(value) {
  const output = {};
  for (const key of INTERNAL_RESULT_KEYS) output[key] = value[key];
  return Object.freeze(output);
}

function mapPublicResult(internal) {
  const reason = internal.reason === "valid"
    ? "valid"
    : internal.reason === "payload_digest_mismatch"
      ? "payload_digest_mismatch"
      : internal.reason === "root_mismatch"
        ? "root_mismatch"
        : internal.reason === "historical_key_unavailable" || internal.reason === "lifecycle_mismatch"
          ? "historical_key_unavailable"
          : internal.reason === "anchor_binding_invalid" || internal.reason === "signature_invalid"
            || internal.reason === "expired" || internal.reason === "not_yet_valid"
              ? "anchor_invalid"
              : "invalid_export";
  return Object.freeze({
    payload_digest: internal.payload_digest_valid,
    root: internal.positions_valid && internal.root_valid,
    anchor: internal.anchor_binding_valid && internal.signature_valid,
    historical_key: internal.lifecycle_valid,
    valid: internal.valid,
    reason
  });
}

class OfflineVerificationFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
