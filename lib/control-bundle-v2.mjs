import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson, intersectScopes, scopeAllows, validateScope } from "../packages/capability/src/index.mjs";

export const FORMAT_EPOCH = 2;
export const LEGACY_FORMAT_EPOCH = 1;
export const CONTROL_BUNDLE_FORMAT_EPOCH = FORMAT_EPOCH;
export const BUNDLE_VERSION = FORMAT_EPOCH;
export const DEFAULT_BUNDLE_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_OFFLINE_TTL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;
export const CONTROL_BUNDLE_MAX_BYTES = 256 * 1024;
export const MAX_BUNDLE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_OFFLINE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const CLOCK_SKEW_MS = 60 * 1000;
export const MAX_REVOCATIONS = 256;
export const MAX_IDENTIFIER_BYTES = 128;
export const MAX_JSON_DEPTH = 32;
export const MAX_REVOCATION_ITEMS = MAX_REVOCATIONS;
export const MAX_REVOCATION_ID_LENGTH = MAX_IDENTIFIER_BYTES;

export const CONTROL_BUNDLE_KEYS = Object.freeze([
  "format_epoch", "issuer", "organization_id", "device_id", "audience", "issued_at", "expires_at",
  "sequence", "policy_scope", "global_revoked", "revoked_devices", "revoked_agents", "revoked_capabilities", "offline_ttl_ms",
  "key_id", "signature"
]);

export const CONTROL_BUNDLE_REASONS = Object.freeze({
  INVALID_BUNDLE: "invalid_bundle",
  INVALID_JSON: "invalid_json",
  JSON_TOO_LARGE: "json_too_large",
  JSON_TOO_DEEP: "json_too_deep",
  DUPLICATE_FIELD: "duplicate_field",
  UNKNOWN_FIELD: "unknown_field",
  INVALID_FORMAT_EPOCH: "invalid_format_epoch",
  LEGACY_MODE_REQUIRED: "legacy_mode_required",
  LEGACY_PERMANENTLY_REJECTED: "legacy_permanently_rejected",
  INVALID_IDENTIFIER: "invalid_identifier",
  INVALID_ORGANIZATION_ID: "invalid_organization_id",
  INVALID_DEVICE_ID: "invalid_device_id",
  INVALID_AGENT_ID: "invalid_agent_id",
  INVALID_CAPABILITY_ID: "invalid_capability_id",
  INVALID_AUDIENCE: "invalid_audience",
  AUDIENCE_MISMATCH: "audience_mismatch",
  INVALID_SCOPE: "invalid_scope",
  INVALID_TIMESTAMP: "invalid_timestamp",
  ISSUED_IN_FUTURE: "issued_in_future",
  EXPIRED: "expired",
  TTL_EXCEEDED: "ttl_exceeded",
  INVALID_OFFLINE_TTL: "invalid_offline_ttl",
  OFFLINE_TTL_EXPIRED: "offline_ttl_expired",
  INVALID_SEQUENCE: "invalid_sequence",
  SEQUENCE_ROLLBACK: "sequence_rollback",
  SEQUENCE_CONFLICT: "sequence_conflict",
  SEQUENCE_EVIDENCE_REQUIRED: "sequence_evidence_required",
  INVALID_REVOCATION: "invalid_revocation",
  DUPLICATE_REVOCATION: "duplicate_revocation",
  REVOCATION_LIST_TOO_LARGE: "revocation_list_too_large",
  INVALID_KEY: "invalid_key",
  KEY_ID_NOT_TRUSTED: "key_id_not_trusted",
  ISSUER_NOT_TRUSTED: "issuer_not_trusted",
  ISSUER_KEY_MISMATCH: "issuer_key_mismatch",
  INVALID_SIGNATURE_ENCODING: "invalid_signature_encoding",
  INVALID_SIGNATURE: "invalid_signature",
  STATE_INVALID: "state_invalid",
  STATE_SYMLINK: "state_symlink",
  STATE_PERSISTENCE_FAILED: "state_persistence_failed",
  GLOBAL_REVOKED: "global_revoked",
  DEVICE_REVOKED: "device_revoked",
  AGENT_REVOKED: "agent_revoked",
  CAPABILITY_REVOKED: "capability_revoked",
  ORGANIZATION_MISMATCH: "organization_mismatch"
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TOP_LEVEL_KEYS = new Set(CONTROL_BUNDLE_KEYS);
const AUDIENCE_KEYS = new Set(["organization_id", "device_id"]);
const STATE_KEYS = new Set(["minimum_format_epoch", "highest_sequence", "statement_hash", "active_bundle"]);
const LEGACY_KEYS = new Set(["version", "sequence", "issued_at", "expires_at", "global_revoked", "revoked_agents", "key_fingerprint", "signature"]);

export class ControlBundleError extends Error {
  constructor(reason, message = reason) {
    super(message);
    this.name = "ControlBundleError";
    this.reason = reason;
    this.code = reason;
  }
}

export const BundleError = ControlBundleError;
export const BundleValidationError = ControlBundleError;
export const BUNDLE_REASONS = CONTROL_BUNDLE_REASONS;

/** Create the initial durable head. The epoch is deliberately not inferred from a bundle. */
export function createControlBundleState() {
  return { minimum_format_epoch: LEGACY_FORMAT_EPOCH, highest_sequence: 0, statement_hash: null, active_bundle: null };
}

/** Issue a v2 bundle. The returned signature covers the exact canonical unsigned statement. */
export function issueControlBundle(input, privateKey, options = {}) {
  if (!isPlainObject(input)) fail(CONTROL_BUNDLE_REASONS.INVALID_BUNDLE, "Control bundle must be an object");
  rejectUnknown(input, new Set([...CONTROL_BUNDLE_KEYS].filter((key) => key !== "signature")), "bundle");
  if (privateKey === undefined || privateKey === null) fail(CONTROL_BUNDLE_REASONS.INVALID_KEY, "An Ed25519 private key is required");
  const now = toNow(options.now ?? Date.now());
  const statement = { ...input, format_epoch: input.format_epoch ?? FORMAT_EPOCH };
  const normalized = validateControlBundle(statement, {
    now,
    allowExpired: false,
    allowFuture: false,
    maxTtlMs: options.maxTtlMs ?? MAX_BUNDLE_TTL_MS,
    maxOfflineTtlMs: options.maxOfflineTtlMs ?? MAX_OFFLINE_TTL_MS
  });
  const key = toPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "ed25519") fail(CONTROL_BUNDLE_REASONS.INVALID_KEY, "Control bundle signing key must be Ed25519");
  return { ...normalized, signature: crypto.sign(null, canonicalBytes(normalized), key).toString("base64") };
}

export const signControlBundleV2 = issueControlBundle;
export const signBundle = issueControlBundle;
export const issueBundle = issueControlBundle;
export const issuePolicyBundle = issueControlBundle;
export const issueRevocationBundle = issueControlBundle;

/** Validate and normalize a bundle. Signature validity is checked by verifyControlBundle. */
export function validateControlBundle(bundle, options = {}) {
  if (!isPlainObject(bundle)) fail(CONTROL_BUNDLE_REASONS.INVALID_BUNDLE, "Control bundle must be an object");
  rejectUnknown(bundle, TOP_LEVEL_KEYS, "bundle");
  if (bundle.signature !== undefined && typeof bundle.signature !== "string") {
    fail(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Control bundle signature must be a string");
  }
  const maxTtlMs = positiveLimit(options.maxTtlMs ?? MAX_BUNDLE_TTL_MS, CONTROL_BUNDLE_REASONS.TTL_EXCEEDED);
  const maxOfflineTtlMs = positiveLimit(options.maxOfflineTtlMs ?? MAX_OFFLINE_TTL_MS, CONTROL_BUNDLE_REASONS.INVALID_OFFLINE_TTL);
  const now = toNow(options.now ?? Date.now());
  if (bundle.format_epoch !== FORMAT_EPOCH) fail(CONTROL_BUNDLE_REASONS.INVALID_FORMAT_EPOCH, "Control bundle format epoch must be 2");
  if (!isIdentifier(bundle.issuer)) fail(CONTROL_BUNDLE_REASONS.INVALID_IDENTIFIER, "Control bundle issuer is invalid");
  assertUuid(bundle.organization_id, CONTROL_BUNDLE_REASONS.INVALID_ORGANIZATION_ID, "Control bundle organization ID is invalid");
  assertUuid(bundle.device_id, CONTROL_BUNDLE_REASONS.INVALID_DEVICE_ID, "Control bundle device ID is invalid");
  const audience = validateAudience(bundle.audience);
  if (audience.organization_id !== bundle.organization_id || audience.device_id !== bundle.device_id) {
    fail(CONTROL_BUNDLE_REASONS.AUDIENCE_MISMATCH, "Control bundle audience does not match its subject");
  }
  const issued = parseTimestamp(bundle.issued_at);
  const expires = parseTimestamp(bundle.expires_at);
  if (expires <= issued) fail(CONTROL_BUNDLE_REASONS.INVALID_TIMESTAMP, "Control bundle expiry must be after issuance");
  if (expires - issued > maxTtlMs) fail(CONTROL_BUNDLE_REASONS.TTL_EXCEEDED, "Control bundle lifetime exceeds the maximum TTL");
  if (!options.allowFuture && issued > now + (options.clockSkewMs ?? CLOCK_SKEW_MS)) {
    fail(CONTROL_BUNDLE_REASONS.ISSUED_IN_FUTURE, "Control bundle was issued in the future");
  }
  if (!options.allowExpired && expires <= now) fail(CONTROL_BUNDLE_REASONS.EXPIRED, "Control bundle has expired");
  if (!Number.isSafeInteger(bundle.sequence) || bundle.sequence < 1) fail(CONTROL_BUNDLE_REASONS.INVALID_SEQUENCE, "Control bundle sequence is invalid");
  const policyScope = validatePolicyScope(bundle.policy_scope);
  if (typeof bundle.global_revoked !== "boolean") fail(CONTROL_BUNDLE_REASONS.INVALID_REVOCATION, "Global revocation must be boolean");
  const revokedDevices = validateRevocations(bundle.revoked_devices, CONTROL_BUNDLE_REASONS.INVALID_DEVICE_ID, "device");
  const revokedAgents = validateRevocations(bundle.revoked_agents, CONTROL_BUNDLE_REASONS.INVALID_AGENT_ID, "agent");
  const revokedCapabilities = validateRevocations(bundle.revoked_capabilities, CONTROL_BUNDLE_REASONS.INVALID_CAPABILITY_ID, "capability");
  if (!Number.isSafeInteger(bundle.offline_ttl_ms) || bundle.offline_ttl_ms <= 0 || bundle.offline_ttl_ms > maxOfflineTtlMs) {
    fail(CONTROL_BUNDLE_REASONS.INVALID_OFFLINE_TTL, "Control bundle offline TTL is invalid");
  }
  if (!isIdentifier(bundle.key_id)) fail(CONTROL_BUNDLE_REASONS.INVALID_IDENTIFIER, "Control bundle key ID is invalid");
  const normalized = {
    format_epoch: FORMAT_EPOCH,
    issuer: bundle.issuer,
    organization_id: bundle.organization_id,
    device_id: bundle.device_id,
    audience,
    issued_at: new Date(issued).toISOString(),
    expires_at: new Date(expires).toISOString(),
    sequence: bundle.sequence,
    policy_scope: policyScope,
    global_revoked: bundle.global_revoked,
    revoked_devices: revokedDevices,
    revoked_agents: revokedAgents,
    revoked_capabilities: revokedCapabilities,
    offline_ttl_ms: bundle.offline_ttl_ms,
    key_id: bundle.key_id
  };
  assertDocumentSize(normalized);
  return normalized;
}

export const validateBundle = validateControlBundle;

export function canonicalControlBundle(bundle) {
  return canonicalJsonSafe(validateControlBundle(bundle, { allowExpired: true, allowFuture: true }));
}

export const canonicalBundle = canonicalControlBundle;

export function controlBundleStatementHash(bundle) {
  return crypto.createHash("sha256").update(canonicalControlBundle(bundle), "utf8").digest("hex");
}

export const bundleHash = controlBundleStatementHash;

/** Verify a bundle against a pinned Ed25519 key and the device audience. */
export function verifyControlBundle(bundle, trust, options = {}) {
  const now = toNow(options.now ?? Date.now());
  const normalized = validateControlBundle(bundle, { ...options, now, allowExpired: options.allowOffline === true });
  const publicKey = resolvePublicKey(trust, normalized, options);
  const signature = decodeSignature(bundle.signature);
  let valid = false;
  try { valid = crypto.verify(null, canonicalBytes(normalized), publicKey, signature); } catch { valid = false; }
  if (!valid) fail(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE, "Control bundle signature is invalid");
  const expectedAudience = options.audience ?? options.expectedAudience ?? trust?.audience;
  if (expectedAudience === undefined) fail(CONTROL_BUNDLE_REASONS.INVALID_AUDIENCE, "Expected organization and device audience is required");
  checkAudience(normalized, expectedAudience);
  if (options.allowOffline === true && expiresAt(normalized) <= now && now >= expiresAt(normalized) + normalized.offline_ttl_ms) {
    fail(CONTROL_BUNDLE_REASONS.OFFLINE_TTL_EXPIRED, "Control bundle offline TTL has expired");
  }
  enforceHead(normalized, options.sequenceState ?? trust?.sequenceState, options);
  return { ...normalized, signature: bundle.signature };
}

export const verifyControlBundleV2 = verifyControlBundle;
export const verifyBundle = verifyControlBundle;
export const verifyDeviceBundle = verifyControlBundle;

/** Issuer verification is useful before a bundle is assigned to a device. */
export function verifyIssuerControlBundle(bundle, trust, options = {}) {
  const verified = verifyControlBundle(bundle, trust, {
    ...options,
    audience: options.audience ?? {
      organization_id: bundle?.organization_id,
      device_id: bundle?.device_id
    }
  });
  return verified;
}

export function verifyCachedControlBundle(bundle, trust, options = {}) {
  return verifyControlBundle(bundle, trust, { ...options, allowOffline: true });
}

export const verifyCachedBundle = verifyCachedControlBundle;

export const verifyIssuerBundle = verifyIssuerControlBundle;

/** Remote policy can only narrow a local scope. */
export function narrowPolicyScope(localScope, bundleOrScope) {
  const remoteScope = bundleOrScope?.policy_scope ?? bundleOrScope;
  try { return intersectScopes(validatePolicyScope(localScope), validatePolicyScope(remoteScope)); }
  catch (error) { fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "Policy scope intersection is invalid"); }
}

export function narrowPolicyBundle(localScope, verifiedBundle) {
  return narrowPolicyScope(localScope, verifiedBundle);
}

export function consumePolicyBundle(bundle, localScope, trust, options = {}) {
  const verified = verifyControlBundle(bundle, trust, options);
  return { bundle: verified, effective_scope: narrowPolicyScope(localScope, verified) };
}

export function policyScopeAllows(bundleOrScope, request) {
  try { return scopeAllows(bundleOrScope?.policy_scope ?? bundleOrScope, request); }
  catch { return false; }
}

export function evaluateControlBundle(bundle, { organization_id, device_id, agent_id, capability_id } = {}) {
  let normalized;
  try { normalized = validateControlBundle(bundle, { allowExpired: true, allowFuture: true }); }
  catch (error) { return { allowed: false, reason: error.reason ?? CONTROL_BUNDLE_REASONS.INVALID_BUNDLE }; }
  if (organization_id !== undefined && organization_id !== normalized.organization_id) return denied(CONTROL_BUNDLE_REASONS.ORGANIZATION_MISMATCH, normalized);
  if (device_id !== undefined && device_id !== normalized.device_id) return denied(CONTROL_BUNDLE_REASONS.AUDIENCE_MISMATCH, normalized);
  if (normalized.global_revoked) return denied(CONTROL_BUNDLE_REASONS.GLOBAL_REVOKED, normalized);
  if (device_id !== undefined && normalized.revoked_devices.includes(device_id)) return denied(CONTROL_BUNDLE_REASONS.DEVICE_REVOKED, normalized);
  if (agent_id !== undefined && normalized.revoked_agents.includes(agent_id)) return denied(CONTROL_BUNDLE_REASONS.AGENT_REVOKED, normalized);
  if (capability_id !== undefined && normalized.revoked_capabilities.includes(capability_id)) return denied(CONTROL_BUNDLE_REASONS.CAPABILITY_REVOKED, normalized);
  return { allowed: true, reason: "allowed", sequence: normalized.sequence };
}

export const evaluateRevocations = evaluateControlBundle;

/**
 * Apply a verified head and persist the epoch floor and head as one state update.
 * `statePath` may be supplied as the third argument or as options.statePath.
 */
export function applyControlBundle(bundle, trust, statePathOrOptions, maybeOptions = {}) {
  const options = typeof statePathOrOptions === "string"
    ? { ...maybeOptions, statePath: statePathOrOptions }
    : { ...(statePathOrOptions ?? {}) };
  const statePath = options.statePath;
  if (typeof statePath !== "string") fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "A state path is required");
  const state = loadControlBundleState(statePath, options);
  if (bundle?.format_epoch !== FORMAT_EPOCH) {
    if (!options.legacyMode) fail(CONTROL_BUNDLE_REASONS.LEGACY_MODE_REQUIRED, "Legacy control bundles require explicit legacy mode");
    if (state.minimum_format_epoch >= FORMAT_EPOCH) fail(CONTROL_BUNDLE_REASONS.LEGACY_PERMANENTLY_REJECTED, "Legacy control bundles are permanently disabled");
    const legacy = verifyLegacyControlBundle(bundle, trust, options);
    enforceLegacyHead(legacy, state);
    saveControlBundleState(statePath, {
      ...state,
      highest_sequence: legacy.sequence,
      statement_hash: legacy.statement_hash,
      active_bundle: legacy.bundle
    }, options);
    return legacy.bundle;
  }
  const verified = verifyControlBundle(bundle, trust, { ...options, sequenceState: state });
  const next = {
    minimum_format_epoch: FORMAT_EPOCH,
    highest_sequence: verified.sequence,
    statement_hash: controlBundleStatementHash(verified),
    active_bundle: verified
  };
  // The marker is separate and monotonic. If the head file is rolled back, this
  // marker still prevents a legacy bundle from being accepted.
  persistMinimumFormatEpoch(minimumEpochPath(statePath, options), FORMAT_EPOCH, options);
  saveControlBundleState(statePath, next, options);
  return verified;
}

export const applyControlBundleV2 = applyControlBundle;

export function loadControlBundleState(statePath, options = {}) {
  assertStatePath(statePath);
  const markerPath = minimumEpochPath(statePath, options);
  let state = createControlBundleState();
  if (fs.existsSync(statePath)) {
    const parsed = readStrictJsonFile(statePath, CONTROL_BUNDLE_MAX_BYTES);
    state = validateControlBundleState(parsed);
  }
  const marker = loadMinimumFormatEpoch(markerPath, options);
  if (marker > state.minimum_format_epoch) state.minimum_format_epoch = marker;
  if (state.minimum_format_epoch >= FORMAT_EPOCH && state.active_bundle?.format_epoch !== FORMAT_EPOCH && state.active_bundle !== null) {
    // A rolled-back or manually edited head is never usable after migration.
    state.active_bundle = null;
  }
  return state;
}

export function saveControlBundleState(statePath, state, options = {}) {
  assertStatePath(statePath);
  const normalized = validateControlBundleState(state);
  try { atomicWriteJson(statePath, normalized, options); }
  catch (error) { if (error instanceof ControlBundleError) throw error; fail(CONTROL_BUNDLE_REASONS.STATE_PERSISTENCE_FAILED, "Control bundle state could not be persisted"); }
  return normalized;
}

export const persistControlBundleState = saveControlBundleState;

export function loadMinimumFormatEpoch(markerPath, options = {}) {
  assertStatePath(markerPath);
  if (!fs.existsSync(markerPath)) return LEGACY_FORMAT_EPOCH;
  const value = readStrictJsonFile(markerPath, 1024);
  if (!isPlainObject(value) || !sameKeys(value, ["minimum_format_epoch"]) || ![1, 2].includes(value.minimum_format_epoch)) {
    fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Minimum format epoch state is invalid");
  }
  return value.minimum_format_epoch;
}

export function persistMinimumFormatEpoch(markerPath, epoch, options = {}) {
  assertStatePath(markerPath);
  if (epoch !== FORMAT_EPOCH) fail(CONTROL_BUNDLE_REASONS.INVALID_FORMAT_EPOCH, "Only format epoch 2 may be persisted");
  const existing = loadMinimumFormatEpoch(markerPath, options);
  if (existing > epoch) fail(CONTROL_BUNDLE_REASONS.LEGACY_PERMANENTLY_REJECTED, "Minimum format epoch cannot move backwards");
  if (existing === epoch) return epoch;
  try { atomicWriteJson(markerPath, { minimum_format_epoch: epoch }, options); }
  catch (error) { if (error instanceof ControlBundleError) throw error; fail(CONTROL_BUNDLE_REASONS.STATE_PERSISTENCE_FAILED, "Minimum format epoch could not be persisted"); }
  return epoch;
}

export const minimumFormatEpochPath = minimumEpochPath;

export function parseControlBundleJson(input, options = {}) {
  if (typeof input !== "string" && !Buffer.isBuffer(input)) fail(CONTROL_BUNDLE_REASONS.INVALID_JSON, "Control bundle JSON must be UTF-8 text");
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  const maxBytes = options.maxBytes ?? CONTROL_BUNDLE_MAX_BYTES;
  if (bytes.length === 0 || bytes.length > maxBytes) fail(CONTROL_BUNDLE_REASONS.JSON_TOO_LARGE, "Control bundle JSON size is invalid");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { fail(CONTROL_BUNDLE_REASONS.INVALID_JSON, "Control bundle JSON is not valid UTF-8"); }
  try { return new JsonReader(text, options.maxDepth ?? MAX_JSON_DEPTH).read(); }
  catch (error) {
    if (error instanceof ControlBundleError) throw error;
    fail(error?.reason ?? CONTROL_BUNDLE_REASONS.INVALID_JSON, "Control bundle JSON is invalid");
  }
}

export const parseBoundedJson = parseControlBundleJson;

function verifyLegacyControlBundle(bundle, trust, options) {
  if (!isPlainObject(bundle)) fail(CONTROL_BUNDLE_REASONS.INVALID_BUNDLE, "Legacy control bundle must be an object");
  rejectUnknown(bundle, LEGACY_KEYS, "legacy bundle");
  if (bundle.version !== 1) fail(CONTROL_BUNDLE_REASONS.INVALID_FORMAT_EPOCH, "Legacy control bundle version is invalid");
  if (!Number.isSafeInteger(bundle.sequence) || bundle.sequence < 1) fail(CONTROL_BUNDLE_REASONS.INVALID_SEQUENCE, "Legacy control bundle sequence is invalid");
  const issued = parseTimestamp(bundle.issued_at);
  const expires = parseTimestamp(bundle.expires_at);
  const now = toNow(options.now ?? Date.now());
  if (expires <= issued || expires - issued > MAX_BUNDLE_TTL_MS) fail(CONTROL_BUNDLE_REASONS.TTL_EXCEEDED, "Legacy control bundle lifetime is invalid");
  if (issued > now + CLOCK_SKEW_MS) fail(CONTROL_BUNDLE_REASONS.ISSUED_IN_FUTURE, "Legacy control bundle was issued in the future");
  if (expires <= now) fail(CONTROL_BUNDLE_REASONS.EXPIRED, "Legacy control bundle has expired");
  if (typeof bundle.global_revoked !== "boolean" || !Array.isArray(bundle.revoked_agents)) fail(CONTROL_BUNDLE_REASONS.INVALID_REVOCATION, "Legacy revocation state is invalid");
  validateRevocations(bundle.revoked_agents, CONTROL_BUNDLE_REASONS.INVALID_AGENT_ID, "agent");
  const publicKey = resolvePublicKey(trust, { key_id: undefined, issuer: undefined }, options);
  const expectedFingerprint = `SHA256:${crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  if (bundle.key_fingerprint !== expectedFingerprint) fail(CONTROL_BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Legacy control key fingerprint is not trusted");
  const signature = decodeSignature(bundle.signature);
  const statement = { version: 1, sequence: bundle.sequence, issued_at: new Date(issued).toISOString(), expires_at: new Date(expires).toISOString(), global_revoked: bundle.global_revoked, revoked_agents: [...bundle.revoked_agents].sort() };
  if (!crypto.verify(null, canonicalBytes(statement), publicKey, signature)) fail(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE, "Legacy control bundle signature is invalid");
  return { bundle: { ...statement, key_fingerprint: bundle.key_fingerprint, signature: bundle.signature }, sequence: statement.sequence, statement_hash: crypto.createHash("sha256").update(canonicalBytes(statement)).digest("hex") };
}

function enforceLegacyHead(legacy, state) {
  if (legacy.sequence < state.highest_sequence) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Legacy control bundle sequence rolled back");
  if (legacy.sequence === state.highest_sequence && state.statement_hash !== null && state.statement_hash !== legacy.statement_hash) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_CONFLICT, "Legacy control bundle sequence conflicts with durable evidence");
}

function enforceHead(bundle, state, options) {
  if (state === undefined || state === null) return;
  const normalized = validateControlBundleState(state);
  const hash = controlBundleStatementHash(bundle);
  if (bundle.sequence < normalized.highest_sequence) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Control bundle sequence rolled back");
  if (bundle.sequence === normalized.highest_sequence) {
    if (normalized.statement_hash === null) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_EVIDENCE_REQUIRED, "Same-sequence bundle requires durable hash evidence");
    if (normalized.statement_hash !== hash) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_CONFLICT, "Control bundle sequence conflicts with durable evidence");
  }
  if (options.highestSequence !== undefined) {
    if (!Number.isSafeInteger(options.highestSequence) || bundle.sequence < options.highestSequence) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Control bundle sequence rolled back");
    if (bundle.sequence === options.highestSequence && options.statementHash !== hash) fail(CONTROL_BUNDLE_REASONS.SEQUENCE_EVIDENCE_REQUIRED, "Same-sequence bundle requires matching hash evidence");
  }
  if (bundle.sequence >= normalized.highest_sequence) {
    state.highest_sequence = bundle.sequence;
    state.statement_hash = hash;
    state.active_bundle = { ...bundle };
  }
}

function validateControlBundleState(state) {
  if (!isPlainObject(state)) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state is invalid");
  try { rejectUnknown(state, STATE_KEYS, "control bundle state"); }
  catch { fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state has an unknown field"); }
  if (!Number.isSafeInteger(state.minimum_format_epoch) || ![1, 2].includes(state.minimum_format_epoch)) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state epoch is invalid");
  if (!Number.isSafeInteger(state.highest_sequence) || state.highest_sequence < 0) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state sequence is invalid");
  if (state.statement_hash !== null && (typeof state.statement_hash !== "string" || !/^[0-9a-f]{64}$/.test(state.statement_hash))) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state hash is invalid");
  if (state.highest_sequence === 0 && state.statement_hash !== null) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Empty control bundle state cannot contain a hash");
  if (state.active_bundle !== null && !isPlainObject(state.active_bundle)) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state head is invalid");
  if (state.active_bundle?.format_epoch === FORMAT_EPOCH) {
    const normalized = validateControlBundle(state.active_bundle, { allowExpired: true, allowFuture: true });
    if (normalized.sequence !== state.highest_sequence || controlBundleStatementHash(normalized) !== state.statement_hash) fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "Control bundle state head evidence is invalid");
  }
  return { minimum_format_epoch: state.minimum_format_epoch, highest_sequence: state.highest_sequence, statement_hash: state.statement_hash, active_bundle: state.active_bundle === null ? null : { ...state.active_bundle } };
}

function validatePolicyScope(scope) {
  try {
    if (!isPlainObject(scope)) fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "Control bundle policy scope is invalid");
    const withoutTags = { ...scope };
    delete withoutTags.tags;
    const normalized = validateScope(withoutTags);
    if (normalized.operations.some((operation) => operation !== "git.commit.sign")) fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "Only git.commit.sign is permitted");
    if (scope.tags === undefined) return normalized;
    if (!isPlainObject(scope.tags)) fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "scope.tags is invalid");
    rejectUnknown(scope.tags, new Set(["allow", "deny"]), "scope.tags");
    const tags = { allow: validatePatternList(scope.tags.allow, true), deny: validatePatternList(scope.tags.deny ?? [], true) };
    if (new Set(tags.allow).size !== tags.allow.length || new Set(tags.deny).size !== tags.deny.length) fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "scope.tags contains duplicates");
    return { ...normalized, tags };
  } catch (error) {
    if (error instanceof ControlBundleError) throw error;
    if (error?.reason === "unknown_field") fail(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD, "Policy scope has an unknown field");
    fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "Control bundle policy scope is invalid");
  }
}

function validatePatternList(value, allowEmpty) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > 256 || value.some((item) => typeof item !== "string" || item.length === 0 || Buffer.byteLength(item) > 2048)) {
    fail(CONTROL_BUNDLE_REASONS.INVALID_SCOPE, "Policy pattern list is invalid");
  }
  return [...value];
}

function validateAudience(audience) {
  if (!isPlainObject(audience)) fail(CONTROL_BUNDLE_REASONS.INVALID_AUDIENCE, "Control bundle audience is invalid");
  rejectUnknown(audience, AUDIENCE_KEYS, "audience");
  assertUuid(audience.organization_id, CONTROL_BUNDLE_REASONS.INVALID_ORGANIZATION_ID, "Audience organization ID is invalid");
  assertUuid(audience.device_id, CONTROL_BUNDLE_REASONS.INVALID_DEVICE_ID, "Audience device ID is invalid");
  return { organization_id: audience.organization_id, device_id: audience.device_id };
}

function checkAudience(bundle, expected) {
  const audience = validateAudience(expected);
  if (audience.organization_id !== bundle.organization_id || audience.device_id !== bundle.device_id) fail(CONTROL_BUNDLE_REASONS.AUDIENCE_MISMATCH, "Control bundle audience does not match the device");
}

function validateRevocations(value, idReason, kind) {
  if (!Array.isArray(value)) fail(CONTROL_BUNDLE_REASONS.INVALID_REVOCATION, `Revoked ${kind} list is invalid`);
  if (value.length > MAX_REVOCATIONS) fail(CONTROL_BUNDLE_REASONS.REVOCATION_LIST_TOO_LARGE, `Revoked ${kind} list is too large`);
  const seen = new Set();
  for (const id of value) {
    if (typeof id !== "string" || Buffer.byteLength(id) > MAX_IDENTIFIER_BYTES || !UUID.test(id)) fail(idReason, `Revoked ${kind} ID is invalid`);
    if (seen.has(id)) fail(CONTROL_BUNDLE_REASONS.DUPLICATE_REVOCATION, `Revoked ${kind} list contains a duplicate`);
    seen.add(id);
  }
  const sorted = [...value].sort();
  if (sorted.some((id, index) => id !== value[index])) fail(CONTROL_BUNDLE_REASONS.INVALID_REVOCATION, `Revoked ${kind} list is not canonical`);
  return [...value];
}

function resolvePublicKey(trust, bundle, options) {
  const direct = isKeyLike(trust) ? trust : trust?.public_key ?? trust?.publicKey ?? options.public_key ?? options.publicKey;
  if (direct === undefined) fail(CONTROL_BUNDLE_REASONS.INVALID_KEY, "A pinned Ed25519 public key is required");
  const trustKeyId = (isPlainObject(trust) && !isKeyLike(trust) ? trust.key_id : undefined) ?? options.key_id;
  if (trustKeyId !== undefined && trustKeyId !== bundle.key_id) fail(CONTROL_BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Control bundle key ID is not trusted");
  const trustIssuer = (isPlainObject(trust) && !isKeyLike(trust) ? trust.issuer : undefined) ?? options.issuer;
  if (trustIssuer !== undefined && bundle.issuer !== undefined && trustIssuer !== bundle.issuer) fail(CONTROL_BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Control bundle issuer is not trusted");
  try {
    const key = direct?.type === "public" ? direct : crypto.createPublicKey(direct);
    if (key.asymmetricKeyType !== "ed25519") throw new Error();
    return key;
  } catch { fail(CONTROL_BUNDLE_REASONS.INVALID_KEY, "Pinned control bundle key is invalid"); }
}

function toPrivateKey(value) {
  try { return value?.type === "private" ? value : crypto.createPrivateKey(value); }
  catch { fail(CONTROL_BUNDLE_REASONS.INVALID_KEY, "Control bundle private key is invalid"); }
}

function decodeSignature(value) {
  if (typeof value !== "string" || !BASE64.test(value)) fail(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Control bundle signature encoding is invalid");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== value) fail(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Control bundle signature encoding is invalid");
  return bytes;
}

function canonicalBytes(value) { return Buffer.from(canonicalJsonSafe(value), "utf8"); }
function canonicalJsonSafe(value) {
  try { return canonicalJson(value); }
  catch { fail(CONTROL_BUNDLE_REASONS.INVALID_BUNDLE, "Control bundle is not canonical JSON"); }
}
function assertDocumentSize(value) {
  const bytes = Buffer.byteLength(canonicalJsonSafe(value), "utf8");
  if (bytes > CONTROL_BUNDLE_MAX_BYTES) fail(CONTROL_BUNDLE_REASONS.JSON_TOO_LARGE, "Control bundle exceeds the maximum JSON size");
}
function parseTimestamp(value) {
  if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) fail(CONTROL_BUNDLE_REASONS.INVALID_TIMESTAMP, "Timestamps must be canonical RFC 3339 UTC strings");
  return Date.parse(value);
}
function toNow(value) { const now = value instanceof Date ? value.getTime() : Number(value); if (!Number.isFinite(now)) fail(CONTROL_BUNDLE_REASONS.INVALID_TIMESTAMP, "Verification clock is invalid"); return now; }
function expiresAt(bundle) { return Date.parse(bundle.expires_at); }
function positiveLimit(value, reason) { if (!Number.isSafeInteger(value) || value <= 0) fail(reason, "Configured limit is invalid"); return value; }
function assertUuid(value, reason, message) { if (typeof value !== "string" || !UUID.test(value)) fail(reason, message); }
function isIdentifier(value) { return typeof value === "string" && Buffer.byteLength(value) <= MAX_IDENTIFIER_BYTES && IDENTIFIER.test(value); }
function isKeyLike(value) { return typeof value === "string" || Buffer.isBuffer(value) || value?.type === "public" || value?.type === "private"; }
function isPlainObject(value) { const prototype = value && typeof value === "object" && !Array.isArray(value) ? Object.getPrototypeOf(value) : undefined; return prototype === Object.prototype || prototype === null; }
function sameKeys(value, keys) { const expected = new Set(keys); return Object.keys(value).length === expected.size && Object.keys(value).every((key) => expected.has(key)); }
function rejectUnknown(value, allowed, label) { for (const key of Reflect.ownKeys(value)) if (typeof key !== "string" || !allowed.has(key)) fail(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD, `${label} contains an unknown field`); }
function denied(reason, bundle) { return { allowed: false, reason, sequence: bundle.sequence }; }
function fail(reason, message) { throw new ControlBundleError(reason, message); }

function minimumEpochPath(statePath, options) { return options.minimumFormatEpochPath ?? `${statePath}.minimum-format-epoch`; }
function assertStatePath(file) {
  if (typeof file !== "string" || !path.isAbsolute(file) || path.basename(file) === "." || path.basename(file) === "..") fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "State path must be an absolute file path");
  const parent = path.dirname(file);
  try {
    // The immediate parent is the replace boundary. System paths such as /tmp
    // may themselves be symlinks, but an application-controlled parent may not.
    if (fs.existsSync(parent) && fs.lstatSync(parent).isSymbolicLink()) fail(CONTROL_BUNDLE_REASONS.STATE_SYMLINK, "State parent cannot be a symlink");
    if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) fail(CONTROL_BUNDLE_REASONS.STATE_SYMLINK, "State file cannot be a symlink");
  } catch (error) { if (error instanceof ControlBundleError) throw error; fail(CONTROL_BUNDLE_REASONS.STATE_PERSISTENCE_FAILED, "State path cannot be inspected"); }
}
function readStrictJsonFile(file, maxBytes) {
  assertStatePath(file);
  let bytes;
  try { bytes = fs.readFileSync(file); } catch { fail(CONTROL_BUNDLE_REASONS.STATE_INVALID, "State file cannot be read"); }
  return parseControlBundleJson(bytes, { maxBytes });
}
function atomicWriteJson(file, value, options) {
  const parent = path.dirname(file);
  let temporary;
  try {
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
    assertStatePath(file);
    const content = `${canonicalJsonSafe(value)}\n`;
    if (Buffer.byteLength(content) > (options.maxBytes ?? CONTROL_BUNDLE_MAX_BYTES)) fail(CONTROL_BUNDLE_REASONS.JSON_TOO_LARGE, "State JSON is too large");
    temporary = path.join(parent, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try { fs.writeFileSync(fd, content, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    assertStatePath(file);
    fs.renameSync(temporary, file);
    try { const directory = fs.openSync(parent, fs.constants.O_RDONLY); try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); } } catch {}
  } catch (error) {
    try { if (typeof temporary === "string" && fs.existsSync(temporary)) fs.unlinkSync(temporary); } catch {}
    if (error instanceof ControlBundleError) throw error;
    fail(CONTROL_BUNDLE_REASONS.STATE_PERSISTENCE_FAILED, "State JSON could not be written atomically");
  }
}

class JsonReader {
  constructor(text, maxDepth) { this.text = text; this.index = 0; this.maxDepth = maxDepth; }
  read() { this.ws(); const value = this.value(0); this.ws(); if (this.index !== this.text.length) throw new Error(); return value; }
  value(depth) {
    if (depth > this.maxDepth) fail(CONTROL_BUNDLE_REASONS.JSON_TOO_DEEP, "JSON nesting exceeds the maximum depth");
    this.ws(); const char = this.text[this.index];
    if (char === "{") return this.object(depth + 1);
    if (char === "[") return this.array(depth + 1);
    if (char === '"') return this.string();
    if (this.text.startsWith("true", this.index)) { this.index += 4; return true; }
    if (this.text.startsWith("false", this.index)) { this.index += 5; return false; }
    if (this.text.startsWith("null", this.index)) { this.index += 4; return null; }
    const match = this.text.slice(this.index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (match) { this.index += match[0].length; const number = Number(match[0]); if (!Number.isFinite(number)) throw new Error(); return number; }
    throw new Error();
  }
  object(depth) {
    this.index++; const result = Object.create(null); const keys = new Set(); this.ws();
    if (this.text[this.index] === "}") { this.index++; return result; }
    while (true) {
      this.ws(); if (this.text[this.index] !== '"') throw new Error(); const key = this.string();
      if (keys.has(key)) fail(CONTROL_BUNDLE_REASONS.DUPLICATE_FIELD, "JSON contains a duplicate field"); keys.add(key);
      this.ws(); if (this.text[this.index++] !== ":") throw new Error(); result[key] = this.value(depth); this.ws();
      if (this.text[this.index] === "}") { this.index++; return result; }
      if (this.text[this.index++] !== ",") throw new Error();
    }
  }
  array(depth) {
    this.index++; const result = []; this.ws(); if (this.text[this.index] === "]") { this.index++; return result; }
    while (true) { result.push(this.value(depth)); this.ws(); if (this.text[this.index] === "]") { this.index++; return result; } if (this.text[this.index++] !== ",") throw new Error(); }
  }
  string() {
    const start = this.index; this.index++; let escaped = false;
    while (this.index < this.text.length) { const char = this.text[this.index++]; if (char === "\\") { escaped = !escaped; continue; } if (char === '"' && !escaped) { const raw = this.text.slice(start, this.index); try { return JSON.parse(raw); } catch { throw new Error(); } } escaped = false; }
    throw new Error();
  }
  ws() { while (/\s/.test(this.text[this.index] ?? "")) this.index++; }
}
