import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3,
  normalizePromotionEvidenceV3Statement,
  promotionEvidenceV3StatementHash,
} from "./promotion-evidence-v3-statement.mjs";
import { verifyPromotionEvidenceV3 } from "./promotion-evidence-v3-verifier.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

export const PLATFORM_PROMOTION_ISSUANCE_VERSION = 1;

export const PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_PROMOTION_ISSUANCE_CONFIG",
  INPUT: "ERR_PLATFORM_PROMOTION_ISSUANCE_INPUT",
  BINDING: "ERR_PLATFORM_PROMOTION_ISSUANCE_BINDING",
  CONFLICT: "ERR_PLATFORM_PROMOTION_ISSUANCE_CONFLICT",
  IN_PROGRESS: "ERR_PLATFORM_PROMOTION_ISSUANCE_IN_PROGRESS",
  UNCERTAIN: "ERR_PLATFORM_PROMOTION_ISSUANCE_UNCERTAIN",
  REPOSITORY: "ERR_PLATFORM_PROMOTION_ISSUANCE_REPOSITORY",
  SIGNER: "ERR_PLATFORM_PROMOTION_ISSUANCE_SIGNER",
  SIGNER_OUTPUT: "ERR_PLATFORM_PROMOTION_ISSUANCE_SIGNER_OUTPUT",
  VERIFIER: "ERR_PLATFORM_PROMOTION_ISSUANCE_VERIFIER",
  STALE_LIFECYCLE: "ERR_PLATFORM_PROMOTION_ISSUANCE_STALE_LIFECYCLE",
  APPROVAL: "ERR_PLATFORM_PROMOTION_ISSUANCE_APPROVAL",
  COMMIT: "ERR_PLATFORM_PROMOTION_ISSUANCE_COMMIT",
  OUTPUT: "ERR_PLATFORM_PROMOTION_ISSUANCE_OUTPUT",
});

export const PLATFORM_PROMOTION_ISSUANCE_REPOSITORY_STATES = Object.freeze([
  "reserved",
  "committed",
  "in_progress",
  "uncertain",
  "conflict",
  "absent",
]);

const {
  CONFIG,
  INPUT,
  BINDING,
  CONFLICT,
  IN_PROGRESS,
  UNCERTAIN,
  REPOSITORY,
  SIGNER,
  SIGNER_OUTPUT,
  VERIFIER,
  STALE_LIFECYCLE,
  APPROVAL,
  COMMIT,
  OUTPUT,
} = PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES;

const SERVICE_OPTION_KEYS = Object.freeze(["repository", "signer", "publicKeyResolver", "now", "maxTtlMs"]);
const PUBLIC_INPUT_KEYS = Object.freeze([
  "promotion_id",
  "deployment_id",
  "environment",
  "candidate_id",
  "idempotency_key",
]);
const STATE_ONLY_KEYS = Object.freeze(["state"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,255}$/u;
const CLAIM_TOKEN = /^[A-Za-z0-9._~:-]{1,512}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RESERVATION_CORE_KEYS = Object.freeze([
  "promotion_id",
  "deployment_id",
  "environment",
  "candidate_id",
  "idempotency_key",
  "source_commit",
  "source_tree",
  "product_pkg_sha256",
  "image_digest",
  "sbom_sha256",
  "qualification_report_digests",
  "release_manifest_schema_version",
  "release_manifest_sha256",
  "platform_approval_id",
  "platform_approval_digest",
  "approval_state",
  "lifecycle_version",
  "key_id",
  "key_version",
  "issued_at",
  "expires_at",
  "signer_key_fingerprint",
]);
const OPTIONAL_RESERVATION_KEYS = Object.freeze([
  "request_digest",
  "approval_expires_at",
  "lifecycle_state",
  "lifecycle_status",
  "lifecycle_enabled",
]);
const VERIFICATION_CONTEXT_KEYS = Object.freeze([
  "allowExpired",
  "candidate_id",
  "deployment_id",
  "environment",
  "image_digest",
  "key_id",
  "key_version",
  "lifecycle_version",
  "maxTtlMs",
  "now",
  "platform_approval_digest",
  "platform_approval_id",
  "product_pkg_sha256",
  "purpose",
  "qualification_report_digests",
  "release_manifest_schema_version",
  "release_manifest_sha256",
  "signer_key_fingerprint",
  "signing_version",
  "source_commit",
  "source_tree",
  "protocol_version",
  "sbom_sha256",
]);
const RESERVED_KEYS = Object.freeze(["state", ...RESERVATION_CORE_KEYS, ...OPTIONAL_RESERVATION_KEYS, "claim_token"]);
const COMMITTED_KEYS = Object.freeze(["state", ...RESERVATION_CORE_KEYS, ...OPTIONAL_RESERVATION_KEYS, "promotion_evidence"]);

export class PlatformPromotionIssuanceError extends Error {
  constructor(code) {
    super(messageFor(code));
    this.name = "PlatformPromotionIssuanceError";
    this.code = Object.values(PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES).includes(code) ? code : OUTPUT;
  }
}

/**
 * Issue one deployment-scoped promotion evidence envelope.
 *
 * The repository owns reservation, idempotency, approval consumption, the
 * immutable artifact set, lifecycle fence, timestamps, and durable receipt.
 * The signer is intentionally only a `sign(statement)` capability.
 */
export function createPlatformPromotionIssuanceService(options = {}) {
  try {
    assertExactKeys(options, SERVICE_OPTION_KEYS.filter((key) => Object.hasOwn(options, key)));
  } catch {
    throw issuanceError(CONFIG);
  }

  const {
    repository,
    signer,
    publicKeyResolver,
    now = () => Date.now(),
    maxTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  } = options;
  validateConfiguration(repository, signer, publicKeyResolver, now, maxTtlMs);

  function currentNow() {
    let value;
    try { value = now(); } catch { throw issuanceError(CONFIG); }
    const result = value instanceof Date ? value.getTime() : value;
    if (!Number.isSafeInteger(result) || result < 0) throw issuanceError(CONFIG);
    return result;
  }

  async function markUncertainBestEffort(values, reservation, reason) {
    if (!reservation?.claim_token) return;
    try {
      await repository.markPlatformPromotionUncertain(toUncertainInput(reservation, reason));
    } catch {
      // The public error remains the safe terminal ambiguity. Diagnostics do
      // not cross this boundary and are never attached as an error cause.
    }
  }

  async function issuePlatformPromotion(input = {}) {
    const values = normalizePublicInput(input);
    const validationNow = currentNow();
    let reservedResult;
    try {
      reservedResult = await repository.reservePlatformPromotion(toRepositoryInput(values));
    } catch (error) {
      throw mapRepositoryError(error, "reserve");
    }

    let reservation;
    try {
      reservation = normalizeRepositoryOutcome(reservedResult, values, maxTtlMs, "reserve", validationNow);
    } catch (error) {
      if (error instanceof PlatformPromotionIssuanceError) throw error;
      throw issuanceError(REPOSITORY);
    }
    if (reservation.state === "committed") return materializeCommitted(values, reservation, true);
    if (reservation.state !== "reserved") throw stateError(reservation.state);

    let statement;
    try {
      statement = buildStatement(values, reservation, currentNow(), maxTtlMs);
    } catch (error) {
      await markUncertainBestEffort(values, reservation, uncertaintyReason(error, "signer_failure"));
      throw error instanceof PlatformPromotionIssuanceError ? error : issuanceError(BINDING);
    }

    let signed;
    try {
      // Exactly one signer call is made for a reservation. A failed call is
      // ambiguous because the provider may have accepted the request.
      signed = await signer.sign(statement);
    } catch {
      await markUncertainBestEffort(values, reservation, "signer_failure");
      throw issuanceError(UNCERTAIN);
    }

    let envelope;
    let verificationNow;
    try {
      verificationNow = currentNow();
      envelope = normalizeSignerOutput(signed, statement, reservation, verificationNow, maxTtlMs);
    } catch (error) {
      await markUncertainBestEffort(values, reservation, uncertaintyReason(error, "signer_output"));
      if (error instanceof PlatformPromotionIssuanceError) throw error;
      throw issuanceError(SIGNER_OUTPUT);
    }

    // The signer may self-check its provider response, but it is not the
    // commit authority. Re-run the trusted v3 verifier with every field that
    // came from the repository reservation immediately before commit.
    try {
      await verifyStoredEnvelope(envelope, reservation, verificationNow, maxTtlMs, false);
    } catch {
      await markUncertainBestEffort(values, reservation, "verification_failure");
      throw issuanceError(VERIFIER);
    }

    let committedResult;
    try {
      committedResult = await repository.commitPlatformPromotion(toCommitInput(reservation, envelope));
    } catch {
      return reconcileLostCommit(values, reservation, envelope);
    }

    let committed;
    try {
      committed = normalizeRepositoryOutcome(committedResult, values, maxTtlMs, "commit");
    } catch {
      return reconcileLostCommit(values, reservation, envelope);
    }
    if (committed.state !== "committed") return reconcileLostCommit(values, reservation, envelope);
    if (!sameEnvelope(committed.promotion_evidence, envelope)) return reconcileLostCommit(values, reservation, envelope);
    try {
      await verifyStoredEnvelope(committed.promotion_evidence, committed, currentNow(), maxTtlMs, false);
    } catch {
      await markUncertainBestEffort(values, reservation, "verification_failure");
      throw issuanceError(COMMIT);
    }
    return publicResult(committed, false);
  }

  async function reconcileLostCommit(values, reservation, envelope) {
    let replayed;
    try {
      replayed = await repository.replayPlatformPromotion(toRepositoryInput(values));
    } catch {
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw issuanceError(COMMIT);
    }
    try {
      const outcome = normalizeRepositoryOutcome(replayed, values, maxTtlMs, "replay");
      if (outcome.state === "committed") {
        if (!sameEnvelope(outcome.promotion_evidence, envelope)) {
          await markUncertainBestEffort(values, reservation, "commit_failure");
          throw issuanceError(COMMIT);
        }
        try {
          await verifyStoredEnvelope(outcome.promotion_evidence, outcome, currentNow(), maxTtlMs, true);
        } catch {
          await markUncertainBestEffort(values, reservation, "verification_failure");
          throw issuanceError(COMMIT);
        }
        return publicResult(outcome, true);
      }
      if (outcome.state === "uncertain") throw issuanceError(UNCERTAIN);
      if (outcome.state === "in_progress") throw issuanceError(IN_PROGRESS);
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw issuanceError(COMMIT);
    } catch (error) {
      if (error instanceof PlatformPromotionIssuanceError) throw error;
      await markUncertainBestEffort(values, reservation, "commit_failure");
      throw issuanceError(COMMIT);
    }
  }

  async function replayPlatformPromotion(input = {}) {
    const values = normalizePublicInput(input);
    const validationNow = currentNow();
    let result;
    try {
      result = await repository.replayPlatformPromotion(toRepositoryInput(values));
    } catch (error) {
      throw mapRepositoryError(error, "replay");
    }
    const outcome = normalizeRepositoryOutcome(result, values, maxTtlMs, "replay", validationNow);
    if (outcome.state === "absent") return null;
    if (outcome.state !== "committed") throw stateError(outcome.state);
    return materializeCommitted(values, outcome, true);
  }

  async function getCommittedPlatformPromotion(input = {}) {
    const values = normalizePublicInput(input);
    let result;
    try {
      result = await repository.getCommittedPlatformPromotion(toRepositoryInput(values));
    } catch (error) {
      throw mapRepositoryError(error, "retrieve");
    }
    try {
      const outcome = normalizeRepositoryOutcome(result, values, maxTtlMs, "retrieve", currentNow());
      if (outcome.state !== "committed") throw stateError(outcome.state, OUTPUT);
      return materializeCommitted(values, outcome, true);
    } catch (error) {
      if (error instanceof PlatformPromotionIssuanceError) throw error;
      throw issuanceError(OUTPUT);
    }
  }

  return Object.freeze({
    issuePlatformPromotion,
    replayPlatformPromotion,
    getCommittedPlatformPromotion,
  });

  async function materializeCommitted(values, outcome, replayed) {
    try {
      const envelope = normalizeSignerOutput(
        outcome.promotion_evidence,
        buildStatement(values, outcome, Date.parse(outcome.issued_at), maxTtlMs, true),
        outcome,
        Date.parse(outcome.issued_at),
        maxTtlMs,
        true
      );
      await verifyStoredEnvelope(envelope, outcome, currentNow(), maxTtlMs, true);
      return publicResult({ ...outcome, promotion_evidence: envelope }, replayed);
    } catch (error) {
      if (error instanceof PlatformPromotionIssuanceError) throw error;
      throw issuanceError(OUTPUT);
    }
  }

  async function verifyStoredEnvelope(envelope, reservation, verificationNow, ttlMs, allowExpired) {
    const context = toVerificationContext(reservation, verificationNow, ttlMs, allowExpired);
    const verified = await verifyPromotionEvidenceV3(envelope, { ...context, publicKeyResolver });
    if (!sameEnvelope(verified, envelope)) throw new Error("verification output mismatch");
    return verified;
  }
}

export const createAuthoritativePlatformPromotionIssuer = createPlatformPromotionIssuanceService;

function validateConfiguration(repository, signer, publicKeyResolver, now, maxTtlMs) {
  if (!isObject(repository)
    || typeof repository.reservePlatformPromotion !== "function"
    || typeof repository.commitPlatformPromotion !== "function"
    || typeof repository.replayPlatformPromotion !== "function"
    || typeof repository.markPlatformPromotionUncertain !== "function"
    || typeof repository.getCommittedPlatformPromotion !== "function") {
    throw issuanceError(CONFIG);
  }
  if (!isObject(signer) || typeof signer.sign !== "function"
    || ["privateKey", "private_key", "secret", "private_key_pem"].some((key) => Object.hasOwn(signer, key))) throw issuanceError(CONFIG);
  if (typeof publicKeyResolver !== "function") throw issuanceError(CONFIG);
  if (typeof now !== "function" || !Number.isSafeInteger(maxTtlMs)
    || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS) throw issuanceError(CONFIG);
}

function normalizePublicInput(value) {
  try {
    assertPlainDataTree(value);
    assertExactKeys(value, PUBLIC_INPUT_KEYS);
    if (typeof value.promotion_id !== "string" || !UUID.test(value.promotion_id)) throw new Error("promotion_id");
    if (typeof value.deployment_id !== "string" || !IDENTIFIER.test(value.deployment_id)) throw new Error("deployment_id");
    if (!['staging', 'production'].includes(value.environment)) throw new Error("environment");
    if (typeof value.candidate_id !== "string" || !CANDIDATE_ID.test(value.candidate_id)) throw new Error("candidate_id");
    if (typeof value.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(value.idempotency_key)) throw new Error("idempotency_key");
    return deepFreeze({ ...value });
  } catch (error) {
    if (error instanceof PlatformPromotionIssuanceError) throw error;
    throw issuanceError(INPUT);
  }
}

function normalizeRepositoryOutcome(value, values, maxTtlMs, phase, validationNow = Date.now()) {
  try {
    assertPlainDataTree(value);
    if (!isObject(value) || typeof value.state !== "string" || !PLATFORM_PROMOTION_ISSUANCE_REPOSITORY_STATES.includes(value.state)) throw new Error("state");
    if (value.state === "absent" || ["in_progress", "uncertain", "conflict"].includes(value.state)) {
      assertExactKeys(value, STATE_ONLY_KEYS);
      return Object.freeze({ state: value.state });
    }
    if (value.state === "reserved") {
      assertExactKeys(value, presentKeys(value, RESERVED_KEYS));
      return deepFreeze({ ...normalizeReservation(value, values, maxTtlMs, false, validationNow), state: "reserved", claim_token: requireClaim(value.claim_token) });
    }
    assertExactKeys(value, presentKeys(value, COMMITTED_KEYS));
    return deepFreeze({ ...normalizeReservation(value, values, maxTtlMs, true, validationNow), state: "committed", promotion_evidence: normalizeCommittedEnvelope(value.promotion_evidence, values, value, maxTtlMs) });
  } catch (error) {
    if (error instanceof PlatformPromotionIssuanceError) throw error;
    throw issuanceError(phase === "commit" ? COMMIT : REPOSITORY);
  }
}

function normalizeReservation(value, values, maxTtlMs, committed, validationNow) {
  for (const key of RESERVATION_CORE_KEYS) if (!Object.hasOwn(value, key)) throw new Error("missing reservation field");
  if (value.promotion_id !== values.promotion_id || value.deployment_id !== values.deployment_id
    || value.environment !== values.environment || value.candidate_id !== values.candidate_id
    || value.idempotency_key !== values.idempotency_key) throw issuanceError(BINDING);
  if (!UUID.test(value.promotion_id) || !IDENTIFIER.test(value.deployment_id)
    || !['staging', 'production'].includes(value.environment) || !CANDIDATE_ID.test(value.candidate_id)
    || !IDEMPOTENCY_KEY.test(value.idempotency_key) || !SOURCE_COMMIT.test(value.source_commit)
    || !SOURCE_COMMIT.test(value.source_tree) || !DIGEST.test(value.product_pkg_sha256)
    || !IMAGE_DIGEST.test(value.image_digest) || !DIGEST.test(value.sbom_sha256)
    || !DIGEST.test(value.release_manifest_sha256) || !UUID.test(value.platform_approval_id)
    || !DIGEST.test(value.platform_approval_digest) || value.approval_state !== "approved"
    || !Number.isSafeInteger(value.release_manifest_schema_version) || value.release_manifest_schema_version !== 4
    || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1
    || !IDENTIFIER.test(value.key_id) || !Number.isSafeInteger(value.key_version) || value.key_version < 1
    || !FINGERPRINT.test(value.signer_key_fingerprint)
    || !validTimestamp(value.issued_at) || !validTimestamp(value.expires_at)
    || Date.parse(value.expires_at) <= Date.parse(value.issued_at)
    || Date.parse(value.expires_at) - Date.parse(value.issued_at) > maxTtlMs) throw new Error("reservation shape");
  if (!Array.isArray(value.qualification_report_digests)) throw new Error("reports");
  if (value.approval_expires_at !== undefined && !validTimestamp(value.approval_expires_at)) throw new Error("approval expiry");
  if (value.approval_expires_at !== undefined && !committed && Date.parse(value.approval_expires_at) <= validationNow) throw issuanceError(APPROVAL);
  if (value.lifecycle_state !== undefined && value.lifecycle_state !== "active") throw issuanceError(STALE_LIFECYCLE);
  if (value.lifecycle_status !== undefined && value.lifecycle_status !== "active") throw issuanceError(STALE_LIFECYCLE);
  if (value.lifecycle_enabled !== undefined && value.lifecycle_enabled !== true) throw issuanceError(STALE_LIFECYCLE);
  if (value.request_digest !== undefined && !DIGEST.test(value.request_digest)) throw new Error("request digest");
  return { ...pickKnown(value, [...RESERVATION_CORE_KEYS, ...OPTIONAL_RESERVATION_KEYS]) };
}

function buildStatement(values, reservation, nowMs, maxTtlMs, historical = false) {
  try {
    return normalizePromotionEvidenceV3Statement({
      version: PROMOTION_EVIDENCE_V3_VERSION,
      type: PROMOTION_EVIDENCE_V3_TYPE,
      promotion_id: reservation.promotion_id,
      deployment_id: reservation.deployment_id,
      environment: reservation.environment,
      candidate_id: reservation.candidate_id,
      source_commit: reservation.source_commit,
      source_tree: reservation.source_tree,
      product_pkg_sha256: reservation.product_pkg_sha256,
      image_digest: reservation.image_digest,
      sbom_sha256: reservation.sbom_sha256,
      qualification_report_digests: reservation.qualification_report_digests,
      release_manifest_schema_version: reservation.release_manifest_schema_version,
      release_manifest_sha256: reservation.release_manifest_sha256,
      platform_approval_id: reservation.platform_approval_id,
      platform_approval_digest: reservation.platform_approval_digest,
      approval_state: reservation.approval_state,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
      signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      lifecycle_version: reservation.lifecycle_version,
      key_id: reservation.key_id,
      key_version: reservation.key_version,
      issued_at: reservation.issued_at,
      expires_at: reservation.expires_at,
    }, { now: nowMs, allowExpired: historical, allowFuture: historical, maxTtlMs });
  } catch (error) {
    if (error instanceof PlatformPromotionIssuanceError) throw error;
    throw issuanceError(BINDING);
  }
}

function normalizeSignerOutput(value, expectedStatement, reservation, nowMs, maxTtlMs, historical = false) {
  if (!isObject(value)) throw new Error("signer output");
  assertPlainDataTree(value);
  assertExactKeys(value, ["version", "type", "statement", "statement_hash", "signature_algorithm", "signer_key_fingerprint", "signature"]);
  const candidate = value;
  let envelope;
  try {
    envelope = normalizePromotionEvidenceV3(candidate, { now: nowMs, allowExpired: historical, allowFuture: historical, maxTtlMs });
  } catch {
    throw issuanceError(SIGNER_OUTPUT);
  }
  if (canonicalJson(envelope.statement) !== canonicalJson(expectedStatement)
    || envelope.statement_hash !== promotionEvidenceV3StatementHash(expectedStatement)
    || envelope.signer_key_fingerprint !== reservation.signer_key_fingerprint
    || envelope.signature_algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM) throw issuanceError(BINDING);
  return envelope;
}

function normalizeCommittedEnvelope(value, values, reservation, maxTtlMs) {
  const expected = buildStatement(values, reservation, Date.parse(reservation.issued_at), maxTtlMs, true);
  return normalizeSignerOutput(value, expected, reservation, Date.parse(reservation.issued_at), maxTtlMs, true);
}

function sameEnvelope(left, right) {
  try { return canonicalJson(left) === canonicalJson(right); } catch { return false; }
}

function publicResult(record, replayed) {
  return deepFreeze({
    promotion_id: record.promotion_id,
    deployment_id: record.deployment_id,
    environment: record.environment,
    candidate_id: record.candidate_id,
    promotion_evidence: record.promotion_evidence,
    replayed: replayed === true,
  });
}

function toRepositoryInput(values) {
  return Object.freeze({ ...values });
}

function toCommitInput(reservation, promotionEvidence) {
  return Object.freeze({
    ...pickKnown(reservation, PUBLIC_INPUT_KEYS),
    claim_token: reservation.claim_token,
    promotion_evidence: promotionEvidence,
  });
}

function toUncertainInput(reservation, reason) {
  return Object.freeze({
    ...pickKnown(reservation, PUBLIC_INPUT_KEYS),
    claim_token: reservation.claim_token,
    reason,
  });
}

function toVerificationContext(reservation, nowMs, maxTtlMs, allowExpired = false) {
  const context = {
    allowExpired,
    candidate_id: reservation.candidate_id,
    deployment_id: reservation.deployment_id,
    environment: reservation.environment,
    image_digest: reservation.image_digest,
    key_id: reservation.key_id,
    key_version: reservation.key_version,
    lifecycle_version: reservation.lifecycle_version,
    maxTtlMs,
    now: nowMs,
    platform_approval_digest: reservation.platform_approval_digest,
    platform_approval_id: reservation.platform_approval_id,
    product_pkg_sha256: reservation.product_pkg_sha256,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    qualification_report_digests: Object.freeze([...reservation.qualification_report_digests]),
    release_manifest_schema_version: reservation.release_manifest_schema_version,
    release_manifest_sha256: reservation.release_manifest_sha256,
    signer_key_fingerprint: reservation.signer_key_fingerprint,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    source_commit: reservation.source_commit,
    source_tree: reservation.source_tree,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    sbom_sha256: reservation.sbom_sha256,
  };
  assertExactKeys(context, VERIFICATION_CONTEXT_KEYS);
  return Object.freeze(context);
}

function mapRepositoryError(error, phase) {
  const code = typeof error?.code === "string" ? error.code.toLowerCase() : "";
  if (code.includes("conflict")) throw issuanceError(CONFLICT);
  if (code.includes("in_progress") || code.includes("pending")) throw issuanceError(IN_PROGRESS);
  if (code.includes("uncertain")) throw issuanceError(UNCERTAIN);
  throw issuanceError(phase === "commit" ? COMMIT : REPOSITORY);
}

function stateError(state, fallback = REPOSITORY) {
  if (state === "conflict") throw issuanceError(CONFLICT);
  if (state === "in_progress") throw issuanceError(IN_PROGRESS);
  if (state === "uncertain") throw issuanceError(UNCERTAIN);
  if (state === "absent") throw issuanceError(REPOSITORY);
  throw issuanceError(fallback);
}

function uncertaintyReason(error, fallback) {
  if (error instanceof PlatformPromotionIssuanceError && error.code === STALE_LIFECYCLE) return "stale_lifecycle";
  if (error instanceof PlatformPromotionIssuanceError && error.code === SIGNER_OUTPUT) return "signer_output";
  return fallback;
}

function messageFor(code) {
  const messages = {
    [CONFIG]: "platform promotion issuance configuration is invalid",
    [INPUT]: "platform promotion issuance input is invalid",
    [BINDING]: "platform promotion issuance binding is invalid",
    [CONFLICT]: "platform promotion idempotency conflicts with its request",
    [IN_PROGRESS]: "platform promotion issuance is already in progress",
    [UNCERTAIN]: "platform promotion signing outcome is uncertain",
    [REPOSITORY]: "platform promotion issuance storage is unavailable",
    [SIGNER]: "platform promotion signer is unavailable",
    [SIGNER_OUTPUT]: "platform promotion signer returned an invalid result",
    [VERIFIER]: "platform promotion evidence failed independent verification",
    [STALE_LIFECYCLE]: "platform promotion signer lifecycle is stale",
    [APPROVAL]: "platform promotion approval is invalid or expired",
    [COMMIT]: "platform promotion issuance could not be committed",
    [OUTPUT]: "platform promotion issuance returned an invalid result",
  };
  return messages[code] ?? messages[OUTPUT];
}

function issuanceError(code) { return new PlatformPromotionIssuanceError(code); }

function presentKeys(value, allowed) {
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !allowed.includes(key))) throw new Error("unknown repository field");
  return actual;
}

function pickKnown(value, keys) {
  const result = {};
  for (const key of keys) if (Object.hasOwn(value, key)) result[key] = value[key];
  return result;
}

function requireClaim(value) {
  if (typeof value !== "string" || !CLAIM_TOKEN.test(value)) throw new Error("claim");
  return value;
}

function validTimestamp(value) {
  return typeof value === "string" && TIMESTAMP.test(value) && new Date(value).toISOString() === value;
}

function assertExactKeys(value, keys) {
  if (!isObject(value)) throw new Error("object");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new Error("keys");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new Error("descriptor");
  }
}

function assertPlainDataTree(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error("number"); return; }
  if (typeof value !== "object" || seen.has(value)) throw new Error("data tree");
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== Array.prototype) throw new Error("prototype");
  seen.add(value);
  const keys = Array.isArray(value) ? Reflect.ownKeys(value).filter((key) => key !== "length") : Reflect.ownKeys(value);
  if (Array.isArray(value) && keys.length !== value.length) throw new Error("array");
  for (const key of keys) {
    if (typeof key !== "string") throw new Error("symbol");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new Error("accessor");
    assertPlainDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return value;
}

function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
