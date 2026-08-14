import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_CHAINS,
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
  normalizeAuditAnchorStatement,
  parseAuditAnchorPublicKey
} from "./audit-anchor-statement.mjs";
import { verifyAuditAnchor } from "./audit-anchor-verifier.mjs";
import {
  AUDIT_EXPORT_SNAPSHOT_TYPE,
  AUDIT_EXPORT_SNAPSHOT_VERSION,
  canonicalAuditExportEntry,
  foldAuditExportRoot
} from "./postgres/audit-export-snapshot-reader.mjs";

export const AUDIT_EXPORT_ISSUANCE_VERSION = 1;

export const AUDIT_EXPORT_ISSUANCE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AUDIT_EXPORT_ISSUANCE_CONFIG",
  INPUT: "ERR_AUDIT_EXPORT_ISSUANCE_INPUT",
  BINDING: "ERR_AUDIT_EXPORT_ISSUANCE_BINDING",
  CONFLICT: "ERR_AUDIT_EXPORT_ISSUANCE_CONFLICT",
  IN_PROGRESS: "ERR_AUDIT_EXPORT_ISSUANCE_IN_PROGRESS",
  UNCERTAIN: "ERR_AUDIT_EXPORT_ISSUANCE_UNCERTAIN",
  NOT_FOUND: "ERR_AUDIT_EXPORT_ISSUANCE_NOT_FOUND",
  REPOSITORY: "ERR_AUDIT_EXPORT_ISSUANCE_REPOSITORY",
  SIGNER: "ERR_AUDIT_EXPORT_ISSUANCE_SIGNER",
  SIGNER_OUTPUT: "ERR_AUDIT_EXPORT_ISSUANCE_SIGNER_OUTPUT",
  STALE_LIFECYCLE: "ERR_AUDIT_EXPORT_ISSUANCE_STALE_LIFECYCLE",
  HISTORICAL_KEY: "ERR_AUDIT_EXPORT_ISSUANCE_HISTORICAL_KEY",
  COMMIT: "ERR_AUDIT_EXPORT_ISSUANCE_COMMIT",
  OUTPUT: "ERR_AUDIT_EXPORT_ISSUANCE_OUTPUT"
});

const MESSAGES = Object.freeze({
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG]: "audit export issuance configuration is invalid",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT]: "audit export issuance input is invalid",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING]: "audit export issuance binding is invalid",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFLICT]: "audit export idempotency key conflicts with its request",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.IN_PROGRESS]: "audit export issuance is already in progress",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.UNCERTAIN]: "audit export signing outcome is uncertain",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.NOT_FOUND]: "audit export was not found",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY]: "audit export issuance storage is unavailable",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER]: "audit anchor signer is unavailable",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT]: "audit anchor signer returned an invalid result",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE]: "audit anchor signer lifecycle is stale",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY]: "historical audit anchor verification failed",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT]: "audit export issuance could not be committed",
  [AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT]: "audit export issuance returned an invalid result"
});

export const AUDIT_EXPORT_ISSUANCE_REPOSITORY_STATES = Object.freeze([
  "reserved",
  "committed",
  "in_progress",
  "uncertain",
  "conflict",
  "absent"
]);

const SERVICE_OPTION_KEYS = Object.freeze(["repository", "signer", "publicKeyResolver", "now", "maxTtlMs", "deploymentMode"]);
const ISSUE_INPUT_KEYS = Object.freeze([
  "organization_id",
  "export_id",
  "environment",
  "chain",
  "idempotency_key"
]);
const RANGE_KEYS = Object.freeze([
  "from_audit_position",
  "to_audit_position",
  "previous_root_digest",
  "root_digest",
  "record_count"
]);
const RESERVE_INPUT_KEYS = Object.freeze([
  "organization_id",
  "export_id",
  "environment",
  "chain",
  "idempotency_key"
]);
const AUTHORITY_KEYS = Object.freeze([
  "organization_id",
  "export_id",
  "environment",
  "chain",
  "idempotency_key",
  "range",
  "payload_digest",
  "request_digest",
  "issued_at",
  "expires_at",
  "key_id",
  "key_version",
  "lifecycle_version"
]);
const COMMIT_INPUT_KEYS = Object.freeze([
  ...AUTHORITY_KEYS,
  "claim_token",
  "audit_anchor"
]);
const UNCERTAIN_INPUT_KEYS = Object.freeze([
  ...AUTHORITY_KEYS,
  "claim_token",
  "reason"
]);
const RESERVED_KEYS = Object.freeze([
  "state",
  ...AUTHORITY_KEYS,
  "claim_token"
]);
const COMMITTED_KEYS = Object.freeze([
  "state",
  ...AUTHORITY_KEYS,
  "audit_anchor"
]);
const STATE_ONLY_KEYS = Object.freeze(["state"]);
const METADATA_KEYS = Object.freeze([
  "version",
  "type",
  "purpose",
  "domain",
  "protocol_version",
  "signing_version",
  "algorithm",
  "key_id",
  "key_version",
  "lifecycle_version",
  "public_key",
  "public_key_fingerprint"
]);
const PAYLOAD_KEYS = Object.freeze([
  "version", "type", "organization_id", "environment", "chain", "range", "entries"
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,255}$/u;
const CLAIM_TOKEN = /^[A-Za-z0-9._~:-]{1,512}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const DEPLOYMENT_MODES = new Set(["hosted", "evaluation"]);
const UNCERTAINTY_REASONS = new Set(["signer_failure", "stale_lifecycle", "signer_output", "commit_failure"]);

export class AuditExportIssuanceError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT]);
    this.name = "AuditExportIssuanceError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT;
  }
}

/**
 * Authoritative domain boundary for one organization-scoped audit export.
 *
 * The repository owns the transaction, sequence reservation, idempotency row,
 * and durable receipt. The signer owns the managed provider boundary. This
 * service intentionally accepts only a purpose-specific audit-anchor signer;
 * generic provider clients, signing bytes, private keys, and provider
 * diagnostics cannot cross this boundary or appear in a returned DTO.
 */
export function createAuditExportIssuanceService(options = {}) {
  try {
    assertPlainDataTree(options);
    assertExactKeys(options, SERVICE_OPTION_KEYS.filter((key) => Object.hasOwn(options, key)));
  } catch {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  }

  const {
    repository,
    signer,
    publicKeyResolver,
    now = () => Date.now(),
    maxTtlMs = AUDIT_ANCHOR_MAX_TTL_MS,
    deploymentMode = "hosted"
  } = options;
  validateConfiguration({ repository, signer, publicKeyResolver, now, maxTtlMs, deploymentMode });

  function currentNow() {
    let value;
    try { value = now(); } catch { throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG); }
    const result = value instanceof Date ? value.getTime() : value;
    if (!Number.isSafeInteger(result) || result < 0) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
    return result;
  }

  async function markUncertainBestEffort(values, reservation, reason) {
    if (!reservation || typeof reservation.claim_token !== "string") return;
    try {
      await repository.markAuditExportUncertain(toUncertainInput(values, reservation, reason));
    } catch { /* The original safe failure is retained below. */ }
  }

  async function issueAuditExport(input = {}, operationOptions = {}) {
    const values = normalizeIssueInput(input);
    const signal = normalizeOperationOptions(operationOptions);
    let reservationResult;
    try {
      reservationResult = await repository.reserveAuditExport(toReserveInput(values));
    } catch (error) {
      throw mapRepositoryError(error, "reserve");
    }

    let reservation;
    try {
      reservation = normalizeReserveOutcome(reservationResult, values, maxTtlMs);
    } catch (error) {
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
    }
    if (reservation.state === "committed") {
      return materializeCommitted(values, reservation, true, signal);
    }
    if (reservation.state !== "reserved") throw stateError(reservation.state);

    let metadata;
    let statement;
    try {
      metadata = await readSignerMetadata(signal);
      assertReservationSignerBinding(reservation, metadata);
      statement = buildStatement(values, reservation, currentNow(), maxTtlMs);
    } catch (error) {
      await markUncertainBestEffort(values, reservation, uncertaintyReason(error, "stale_lifecycle"));
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER);
    }

    let signed;
    try {
      signed = await signer.signAuditAnchor(statement, signal === undefined ? undefined : { signal });
    } catch {
      await markUncertainBestEffort(values, reservation, "signer_failure");
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER);
    }

    let anchor;
    try {
      const afterMetadata = await readSignerMetadata(signal);
      assertSameSignerMetadata(metadata, afterMetadata);
      anchor = verifySignedAnchor(signed, statement, values, reservation, afterMetadata, currentNow(), maxTtlMs);
    } catch (error) {
      await markUncertainBestEffort(values, reservation, uncertaintyReason(error, "signer_output"));
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT);
    }

    let committedResult;
    try {
      committedResult = await repository.commitAuditExport(toCommitInput(values, reservation, anchor));
    } catch {
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
    }

    let committed;
    try {
      committed = normalizeCommitOutcome(committedResult, values, maxTtlMs);
    } catch (error) {
      await markUncertainBestEffort(values, reservation, "commit_failure");
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
    }
    if (committed.state !== "committed") {
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw stateError(committed.state, AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
    }
    if (canonicalJson(committed.audit_anchor) !== canonicalJson(anchor)) {
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
    }
    const payload = await readCommittedPayload(values, committed);
    return publicResult(committed, payload, false, currentNow());
  }

  async function replayAuditExport(input = {}, operationOptions = {}) {
    const values = normalizeIssueInput(input);
    const signal = normalizeOperationOptions(operationOptions);
    let result;
    try {
      result = await repository.replayAuditExport(toReserveInput(values));
    } catch (error) {
      throw mapRepositoryError(error, "replay");
    }
    let outcome;
    try {
      outcome = normalizeReplayOutcome(result, values, maxTtlMs);
    } catch (error) {
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
    }
    if (outcome.state === "absent") return null;
    if (outcome.state !== "committed") throw stateError(outcome.state);
    return materializeCommitted(values, outcome, true, signal);
  }

  return Object.freeze({ issueAuditExport, replayAuditExport });

  async function materializeCommitted(values, record, replayed, signal) {
    let metadata;
    try {
      const currentNowMs = currentNow();
      metadata = await resolveHistoricalMetadata(record, signal);
      const reservation = committedReservation(record);
      const issuedAtMs = Date.parse(record.issued_at);
      const expectedStatement = buildStatement(values, reservation, issuedAtMs, maxTtlMs);
      const anchor = verifySignedAnchor(record.audit_anchor, expectedStatement, values, reservation, metadata, issuedAtMs, maxTtlMs, AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY);
      const payload = await readCommittedPayload(values, record);
      return publicResult({ ...record, audit_anchor: anchor }, payload, replayed, currentNowMs);
    } catch (error) {
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT);
    }
  }

  async function readSignerMetadata(signal) {
    let value;
    try {
      value = await signer.publicKeyMetadata(signal === undefined ? undefined : { signal });
    } catch {
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER);
    }
    return normalizePublicKeyMetadata(value, AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER);
  }

  async function resolveHistoricalMetadata(record, signal) {
    let value;
    try {
      value = await publicKeyResolver({
        purpose: AUDIT_ANCHOR_PURPOSE,
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
        signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
        key_id: record.key_id,
        key_version: record.key_version,
        lifecycle_version: record.lifecycle_version,
        ...(signal === undefined ? {} : { signal })
      });
    } catch {
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY);
    }
    const metadata = normalizePublicKeyMetadata(value, AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY);
    if (metadata.key_id !== record.key_id || metadata.key_version !== record.key_version
      || metadata.lifecycle_version !== record.lifecycle_version) {
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY);
    }
    return metadata;
  }

  async function readCommittedPayload(values, record) {
    let value;
    try {
      value = await repository.getAuditExportPayload(toReserveInput(values));
      return normalizeExportPayload(value, record);
    } catch (error) {
      if (error instanceof AuditExportIssuanceError) throw error;
      throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT);
    }
  }
}

export const createAuthoritativeAuditExportIssuer = createAuditExportIssuanceService;

function validateConfiguration({ repository, signer, publicKeyResolver, now, maxTtlMs, deploymentMode }) {
  if (!isObject(repository)
    || typeof repository.reserveAuditExport !== "function"
    || typeof repository.commitAuditExport !== "function"
    || typeof repository.replayAuditExport !== "function"
    || typeof repository.markAuditExportUncertain !== "function"
    || typeof repository.getAuditExportPayload !== "function") {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  }
  if (!isObject(signer)
    || typeof signer.publicKeyMetadata !== "function"
    || typeof signer.signAuditAnchor !== "function"
    || signer.purpose !== AUDIT_ANCHOR_PURPOSE
    || signer.algorithm !== AUDIT_ANCHOR_ALGORITHM
    || signer.version !== AUDIT_ANCHOR_SIGNING_VERSION
    || signer.protocol_version !== AUDIT_ANCHOR_PROTOCOL_VERSION
    || signer.signing_version !== AUDIT_ANCHOR_SIGNING_VERSION) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  }
  if (typeof publicKeyResolver !== "function") throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  if (deploymentMode !== undefined && !DEPLOYMENT_MODES.has(deploymentMode)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  if (deploymentMode === "hosted" && (signer.local === true || signer.mode === "local" || signer.profile === "evaluation"
    || ["privateKey", "private_key", "secret", "private_key_pem"].some((key) => Object.hasOwn(signer, key)))) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  }
  if (typeof now !== "function" || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > AUDIT_ANCHOR_MAX_TTL_MS) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  }
}

function normalizePublicKeyMetadata(value, failureCode) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, METADATA_KEYS);
    if (value.version !== AUDIT_ANCHOR_VERSION || value.type !== AUDIT_ANCHOR_TYPE
      || value.purpose !== AUDIT_ANCHOR_PURPOSE || value.domain !== AUDIT_ANCHOR_SIGNATURE_DOMAIN
      || value.protocol_version !== AUDIT_ANCHOR_PROTOCOL_VERSION
      || value.signing_version !== AUDIT_ANCHOR_SIGNING_VERSION
      || value.algorithm !== AUDIT_ANCHOR_ALGORITHM
      || !IDENTIFIER.test(value.key_id)
      || !Number.isSafeInteger(value.key_version) || value.key_version < 1
      || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1
      || typeof value.public_key !== "string"
      || typeof value.public_key_fingerprint !== "string") {
      throw new Error("invalid metadata");
    }
    const publicKey = parseAuditAnchorPublicKey(value.public_key, AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
    const fingerprint = auditAnchorPublicKeyFingerprint(publicKey);
    if (fingerprint !== value.public_key_fingerprint) throw new Error("fingerprint mismatch");
    return deepFreeze({
      version: value.version,
      type: value.type,
      purpose: value.purpose,
      domain: value.domain,
      protocol_version: value.protocol_version,
      signing_version: value.signing_version,
      algorithm: value.algorithm,
      key_id: value.key_id,
      key_version: value.key_version,
      lifecycle_version: value.lifecycle_version,
      public_key: value.public_key,
      public_key_fingerprint: value.public_key_fingerprint
    });
  } catch {
    throw issuanceError(failureCode);
  }
}

function normalizeIssueInput(input) {
  try {
    assertPlainDataTree(input);
    assertExactKeys(input, ISSUE_INPUT_KEYS);
    const organizationId = requiredUuid(input.organization_id);
    const exportId = requiredUuid(input.export_id);
    const environment = exactEnumeration(input.environment, ["staging", "production"]);
    const chain = exactEnumeration(input.chain, AUDIT_ANCHOR_CHAINS);
    const idempotencyKey = requiredIdempotencyKey(input.idempotency_key);
    return deepFreeze({
      version: AUDIT_EXPORT_ISSUANCE_VERSION,
      organization_id: organizationId,
      export_id: exportId,
      environment,
      chain,
      idempotency_key: idempotencyKey
    });
  } catch (error) {
    if (error instanceof AuditExportIssuanceError) throw error;
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  }
}

function normalizeRange(value) {
  assertPlainDataTree(value);
  assertExactKeys(value, RANGE_KEYS);
  const from = positiveInteger(value.from_audit_position);
  const to = positiveInteger(value.to_audit_position);
  const previousRootDigest = requiredDigest(value.previous_root_digest, true);
  const rootDigest = requiredDigest(value.root_digest, false);
  const recordCount = positiveInteger(value.record_count);
  if (to < from || recordCount !== to - from + 1) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  if ((from === 1 && previousRootDigest !== AUDIT_ANCHOR_ZERO_DIGEST)
    || (from > 1 && previousRootDigest === AUDIT_ANCHOR_ZERO_DIGEST)) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  }
  return deepFreeze({
    from_audit_position: from,
    to_audit_position: to,
    previous_root_digest: previousRootDigest,
    root_digest: rootDigest,
    record_count: recordCount
  });
}

function normalizeReserveOutcome(value, values, maxTtlMs) {
  assertPlainDataTree(value);
  if (!Object.hasOwn(value, "state") || typeof value.state !== "string" || !AUDIT_EXPORT_ISSUANCE_REPOSITORY_STATES.includes(value.state)) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
  if (["in_progress", "uncertain", "conflict"].includes(value.state)) {
    assertExactKeys(value, STATE_ONLY_KEYS);
    return Object.freeze({ state: value.state });
  }
  if (value.state === "committed") return normalizeCommittedOutcome(value, values, maxTtlMs);
  if (value.state !== "reserved") throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  return normalizeReserved(value, values, maxTtlMs);
}

function normalizeReplayOutcome(value, values, maxTtlMs) {
  assertPlainDataTree(value);
  if (!Object.hasOwn(value, "state") || typeof value.state !== "string" || !AUDIT_EXPORT_ISSUANCE_REPOSITORY_STATES.includes(value.state)) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
  if (value.state === "absent") {
    assertExactKeys(value, STATE_ONLY_KEYS);
    return Object.freeze({ state: "absent" });
  }
  if (value.state === "committed") return normalizeCommittedOutcome(value, values, maxTtlMs);
  if (["in_progress", "uncertain", "conflict"].includes(value.state)) {
    assertExactKeys(value, STATE_ONLY_KEYS);
    return Object.freeze({ state: value.state });
  }
  throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
}

function normalizeCommitOutcome(value, values, maxTtlMs) {
  assertPlainDataTree(value);
  if (!Object.hasOwn(value, "state") || typeof value.state !== "string" || !AUDIT_EXPORT_ISSUANCE_REPOSITORY_STATES.includes(value.state)) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
  }
  if (value.state !== "committed") {
    if (["in_progress", "uncertain", "conflict"].includes(value.state)) {
      assertExactKeys(value, STATE_ONLY_KEYS);
      return Object.freeze({ state: value.state });
    }
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT);
  }
  return normalizeCommittedOutcome(value, values, maxTtlMs);
}

function normalizeReserved(value, values, maxTtlMs) {
  assertExactKeys(value, RESERVED_KEYS);
  const record = normalizeAuthorityRecord(value, values, maxTtlMs);
  if (!CLAIM_TOKEN.test(value.claim_token)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  return deepFreeze({ ...record, state: "reserved", claim_token: value.claim_token });
}

function normalizeCommittedOutcome(value, values, maxTtlMs) {
  assertExactKeys(value, COMMITTED_KEYS);
  const record = normalizeAuthorityRecord(value, values, maxTtlMs);
  let anchor;
  try {
    anchor = normalizeAuditAnchor(value.audit_anchor, { allowExpired: true, allowFuture: true, maxTtlMs });
  } catch {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
  return deepFreeze({ ...record, state: "committed", audit_anchor: anchor });
}

function normalizeCommonRecord(value, values) {
  const organizationId = requiredUuid(value.organization_id);
  const exportId = requiredUuid(value.export_id);
  const environment = exactEnumeration(value.environment, ["staging", "production"]);
  const chain = exactEnumeration(value.chain, AUDIT_ANCHOR_CHAINS);
  const range = normalizeRange(value.range);
  const payloadDigest = requiredDigest(value.payload_digest, false);
  const requestDigest = requiredDigest(value.request_digest, false);
  const idempotencyKey = requiredIdempotencyKey(value.idempotency_key);
  if (organizationId !== values.organization_id || exportId !== values.export_id || environment !== values.environment
    || chain !== values.chain || idempotencyKey !== values.idempotency_key) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING);
  }
  const expectedRequestDigest = sha256(canonicalJson({
    version: AUDIT_EXPORT_ISSUANCE_VERSION,
    organization_id: organizationId,
    export_id: exportId,
    environment,
    chain,
    idempotency_key: idempotencyKey,
    range,
    payload_digest: payloadDigest
  }));
  if (requestDigest !== expectedRequestDigest) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING);
  return {
    organization_id: organizationId,
    export_id: exportId,
    environment,
    chain,
    range,
    payload_digest: payloadDigest,
    request_digest: requestDigest,
    idempotency_key: idempotencyKey
  };
}

function normalizeAuthorityRecord(value, values, maxTtlMs) {
  const record = normalizeCommonRecord(value, values);
  const issuedAt = requiredTimestamp(value.issued_at);
  const expiresAt = requiredTimestamp(value.expires_at);
  if (typeof value.key_id !== "string" || !IDENTIFIER.test(value.key_id)
    || !Number.isSafeInteger(value.key_version) || value.key_version < 1
    || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1
    || Date.parse(expiresAt) <= Date.parse(issuedAt)
    || Date.parse(expiresAt) - Date.parse(issuedAt) > maxTtlMs) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
  return {
    ...record,
    issued_at: issuedAt,
    expires_at: expiresAt,
    key_id: value.key_id,
    key_version: value.key_version,
    lifecycle_version: value.lifecycle_version
  };
}

function buildStatement(values, reservation, nowMs, maxTtlMs) {
  try {
    return normalizeAuditAnchorStatement({
      version: AUDIT_ANCHOR_VERSION,
      type: AUDIT_ANCHOR_TYPE,
      organization_id: values.organization_id,
      environment: values.environment,
      chain: values.chain,
      export_id: values.export_id,
      audit_position: reservation.range.to_audit_position,
      previous_audit_position: reservation.range.from_audit_position - 1,
      root_digest: reservation.range.root_digest,
      previous_root_digest: reservation.range.previous_root_digest,
      export_digest: reservation.payload_digest,
      record_count: reservation.range.record_count,
      purpose: AUDIT_ANCHOR_PURPOSE,
      protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
      signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
      lifecycle_version: reservation.lifecycle_version,
      key_id: reservation.key_id,
      key_version: reservation.key_version,
      issued_at: reservation.issued_at,
      expires_at: reservation.expires_at
    }, { now: nowMs, allowExpired: false, allowFuture: false, maxTtlMs });
  } catch (error) {
    if (error instanceof AuditExportIssuanceError) throw error;
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING);
  }
}

function verifySignedAnchor(value, expectedStatement, values, reservation, metadata, nowMs, maxTtlMs, failureCode = AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT) {
  let normalized;
  try {
    normalized = normalizeAuditAnchor(value, { now: nowMs, allowExpired: false, allowFuture: false, maxTtlMs });
  } catch {
    throw issuanceError(failureCode);
  }
  const statement = normalized.statement;
  if (statement.lifecycle_version !== reservation.lifecycle_version
    || statement.key_id !== reservation.key_id || statement.key_version !== reservation.key_version) {
    throw issuanceError(failureCode === AUDIT_EXPORT_ISSUANCE_ERROR_CODES.HISTORICAL_KEY
      ? failureCode
      : AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE);
  }
  if (statement.organization_id !== values.organization_id || statement.export_id !== values.export_id
    || statement.environment !== values.environment || statement.chain !== values.chain
    || statement.previous_audit_position !== expectedStatement.previous_audit_position
    || statement.audit_position !== expectedStatement.audit_position
    || statement.previous_root_digest !== expectedStatement.previous_root_digest
    || statement.root_digest !== expectedStatement.root_digest
    || statement.record_count !== expectedStatement.record_count
    || statement.export_digest !== reservation.payload_digest
    || statement.issued_at !== expectedStatement.issued_at || statement.expires_at !== expectedStatement.expires_at) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.BINDING);
  }
  if (normalized.signer_key_fingerprint !== metadata.public_key_fingerprint) {
    throw issuanceError(failureCode);
  }
  try {
    return verifyAuditAnchor(normalized, {
      publicKey: metadata.public_key,
      organizationId: values.organization_id,
      environment: values.environment,
      chain: values.chain,
      exportId: values.export_id,
      auditPosition: expectedStatement.audit_position,
      rootDigest: expectedStatement.root_digest,
      exportDigest: reservation.payload_digest,
      recordCount: expectedStatement.record_count,
      keyId: reservation.key_id,
      keyVersion: reservation.key_version,
      lifecycleVersion: reservation.lifecycle_version,
      previousAuditPosition: expectedStatement.previous_audit_position,
      previousRootDigest: expectedStatement.previous_root_digest,
      now: nowMs,
      maxTtlMs
    });
  } catch {
    throw issuanceError(failureCode);
  }
}

function assertReservationSignerBinding(reservation, metadata) {
  if (metadata.key_id !== reservation.key_id || metadata.key_version !== reservation.key_version
    || metadata.lifecycle_version !== reservation.lifecycle_version) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE);
  }
}

function committedReservation(record) {
  return Object.freeze({ ...authorityInput(record) });
}

function assertSameSignerMetadata(left, right) {
  if (left.key_id !== right.key_id || left.key_version !== right.key_version
    || left.lifecycle_version !== right.lifecycle_version
    || left.public_key_fingerprint !== right.public_key_fingerprint
    || left.public_key !== right.public_key) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE);
  }
}

function publicResult(record, payload, replayed, nowMs) {
  return deepFreeze({
    organization_id: record.organization_id,
    export_id: record.export_id,
    environment: record.environment,
    chain: record.chain,
    range: record.range,
    payload_digest: record.payload_digest,
    payload,
    audit_anchor: record.audit_anchor,
    replayed: replayed === true,
    validity: validityFor(record, nowMs)
  });
}

function normalizeExportPayload(value, record) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, PAYLOAD_KEYS);
    if (value.version !== AUDIT_EXPORT_SNAPSHOT_VERSION || value.type !== AUDIT_EXPORT_SNAPSHOT_TYPE
      || value.organization_id !== record.organization_id || value.environment !== record.environment
      || value.chain !== record.chain || canonicalJson(value.range) !== canonicalJson(record.range)
      || !Array.isArray(value.entries) || value.entries.length !== record.range.record_count) {
      throw new Error("payload identity");
    }
    let root = record.range.previous_root_digest;
    for (let index = 0; index < value.entries.length; index += 1) {
      const entry = canonicalAuditExportEntry(value.entries[index]);
      if (entry.organization_id !== record.organization_id || entry.environment !== record.environment
        || entry.chain !== record.chain || entry.export_position !== record.range.from_audit_position + index) {
        throw new Error("payload entry");
      }
      root = foldAuditExportRoot(root, entry);
    }
    if (root !== record.range.root_digest || sha256(canonicalJson(value)) !== record.payload_digest) {
      throw new Error("payload digest");
    }
    return deepFreeze(structuredClone(value));
  } catch {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT);
  }
}

function validityFor(record, nowMs) {
  const issuedAtMs = Date.parse(record.issued_at);
  const expiresAtMs = Date.parse(record.expires_at);
  if (!Number.isSafeInteger(nowMs) || nowMs < issuedAtMs) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.OUTPUT);
  return nowMs < expiresAtMs ? "active" : "expired";
}

function toReserveInput(values) {
  return exactObject({
    organization_id: values.organization_id,
    export_id: values.export_id,
    environment: values.environment,
    chain: values.chain,
    idempotency_key: values.idempotency_key
  }, RESERVE_INPUT_KEYS);
}

function toCommitInput(values, reservation, anchor) {
  return exactObject({
    ...authorityInput(reservation),
    claim_token: reservation.claim_token,
    audit_anchor: anchor
  }, COMMIT_INPUT_KEYS);
}

function toUncertainInput(values, reservation, reason) {
  if (!UNCERTAINTY_REASONS.has(reason)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFIG);
  return exactObject({
    ...authorityInput(reservation),
    claim_token: reservation.claim_token,
    reason
  }, UNCERTAIN_INPUT_KEYS);
}

function authorityInput(record) {
  return {
    organization_id: record.organization_id,
    export_id: record.export_id,
    environment: record.environment,
    chain: record.chain,
    idempotency_key: record.idempotency_key,
    range: record.range,
    payload_digest: record.payload_digest,
    request_digest: record.request_digest,
    issued_at: record.issued_at,
    expires_at: record.expires_at,
    key_id: record.key_id,
    key_version: record.key_version,
    lifecycle_version: record.lifecycle_version
  };
}

function mapRepositoryError(error, phase) {
  const code = typeof error?.code === "string" ? error.code.toLowerCase() : "";
  if (code.includes("conflict")) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFLICT);
  if (code.includes("in_progress") || code.includes("pending")) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.IN_PROGRESS);
  if (code.includes("uncertain")) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.UNCERTAIN);
  if (code.includes("not_found") || code.includes("absent")) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.NOT_FOUND);
  throw issuanceError(phase === "commit" ? AUDIT_EXPORT_ISSUANCE_ERROR_CODES.COMMIT : AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
}

function stateError(state, fallback = undefined) {
  if (state === "conflict") return issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.CONFLICT);
  if (state === "in_progress") return issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.IN_PROGRESS);
  if (state === "uncertain") return issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.UNCERTAIN);
  if (state === "absent") return issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.NOT_FOUND);
  return issuanceError(fallback ?? AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
}

function uncertaintyReason(error, fallback) {
  if (error instanceof AuditExportIssuanceError && error.code === AUDIT_EXPORT_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE) return "stale_lifecycle";
  if (error instanceof AuditExportIssuanceError && error.code === AUDIT_EXPORT_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT) return "signer_output";
  return UNCERTAINTY_REASONS.has(fallback) ? fallback : "signer_failure";
}

function normalizeOperationOptions(value) {
  if (value === undefined) return undefined;
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, Object.hasOwn(value, "signal") ? ["signal"] : []);
    if (value.signal !== undefined && (typeof AbortSignal === "undefined" || !(value.signal instanceof AbortSignal))) throw new Error("signal");
    return value.signal;
  } catch {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  }
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  return value.toLowerCase();
}

function requiredDigest(value, allowZero) {
  if (typeof value !== "string" || !DIGEST.test(value) || (!allowZero && value === AUDIT_ANCHOR_ZERO_DIGEST)) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  }
  return value;
}

function requiredIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  return value;
}

function requiredTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
  return value;
}

function exactEnumeration(value, allowed) {
  if (typeof value !== "string" || !allowed.includes(value)) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw issuanceError(AUDIT_EXPORT_ISSUANCE_ERROR_CODES.INPUT);
  return value;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function issuanceError(code) {
  return new AuditExportIssuanceError(code);
}

function assertExactKeys(value, keys) {
  if (!isObject(value)) throw new Error("object");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new Error("keys");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("descriptor");
  }
}

function exactObject(value, keys) {
  assertExactKeys(value, keys);
  return Object.freeze(value);
}

function assertPlainDataTree(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return;
  if (seen.has(value) || (!isObject(value) && !Array.isArray(value))) throw new Error("data tree");
  seen.add(value);
  if (Array.isArray(value)) {
    if (Reflect.ownKeys(value).length !== value.length + 1) throw new Error("array descriptor");
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("descriptor");
      assertPlainDataTree(descriptor.value, seen);
    }
    seen.delete(value);
    return;
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new Error("symbol");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("descriptor");
    assertPlainDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function isObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return value;
}
