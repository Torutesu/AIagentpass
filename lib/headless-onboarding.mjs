import crypto from "node:crypto";

import { buildEnrollmentCandidateBinding, validateEnrollmentChallengeNonce } from "./device-enrollment-client.mjs";
import { SetupJournalError, loadSetupJournal } from "./setup-journal.mjs";

export const HEADLESS_ONBOARDING_SCHEMA_VERSION = 1;
export const HEADLESS_ONBOARDING_ERROR_VERSION = 1;

const SAFE_CODE = /^(?:[A-Z][A-Z0-9_]{1,63}|[a-z][a-z0-9_.-]{1,63})$/;
const SAFE_PATH = /(?:^|[\s(])(?:~|\/Users\/|\/private\/|\/tmp\/|\/var\/|\/Applications\/|\/Library\/|\/opt\/)[^\s),;]*/gu;
const CREDENTIAL = /\b(?:bearer|basic|token|secret|password|passwd|credential|authorization|cookie|assertion|private[_ -]?key|key[_ -]?material)\s*[:=]\s*[^\s,;)]*/giu;
const URL_CREDENTIAL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@/giu;
const INVITATION_KEYS = Object.freeze(["version", "proof_version", "enrollment_id", "organization_id", "device_id", "label", "platform", "candidate_binding", "challenge_id", "nonce", "expires_at", "challenge", "credential", "endpoint", "possession_receipt_verification"]);
const CHALLENGE_KEYS = Object.freeze(["challenge_id", "nonce", "expires_at", "candidate_id", "device_key_fingerprint"]);
const RECEIPT_VERIFICATION_KEYS = Object.freeze(["key_id", "algorithm", "public_key"]);
const SAFE_INVITATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64URL_CREDENTIAL = /^[A-Za-z0-9_-]{43}$/u;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;

const SAFE_ERROR_MESSAGES = Object.freeze({
  JOURNAL_BUSY: "Another setup operation is active; retry after it exits.",
  NOT_INITIALIZED: "Headless onboarding has not started.",
  TAMPERED_JOURNAL: "The durable onboarding state could not be verified.",
  TAMPERED_ANCHOR: "The durable onboarding anchor could not be verified.",
  ROLLBACK_DETECTED: "The durable onboarding state is not a safe forward sequence.",
  UNSAFE_STORAGE: "The durable onboarding storage is not safe to use.",
  UNKNOWN_STATE: "The durable onboarding state is unknown.",
  HANDLER_MISSING: "The next onboarding action is unavailable.",
  HANDLER_FAILED: "The next onboarding action did not complete.",
  INVALID_EVIDENCE: "The onboarding action did not produce verifiable evidence.",
  AMBIGUOUS_HANDLER_RESPONSE: "The onboarding action returned an ambiguous result.",
  SERVICE_APPROVAL_REQUIRED: "macOS approval is required before onboarding can continue.",
  SERVICE_REGISTRATION_FAILED: "The native service could not be registered.",
  SERVICE_RESTART_FAILED: "The native service could not be restarted safely.",
  CONTROL_RECONCILIATION_FAILED: "The native control state could not be reconciled.",
  INVALID_ENROLLMENT_INVITATION: "The enrollment handoff was rejected.",
  INVALID_ENROLLMENT_RESPONSE: "The enrollment response was rejected.",
  ONBOARDING_PROJECT_MISSING: "The configured onboarding project is unavailable.",
  TEST_COMMIT_NOT_VERIFIED: "The test commit could not be verified.",
  CONFIG_VERSION_MISMATCH: "The local configuration version is unsupported."
});

export class HeadlessOnboardingError extends Error {
  constructor(code, message, { causeCode = undefined } = {}) {
    super(message);
    this.name = "HeadlessOnboardingError";
    this.code = code;
    if (causeCode !== undefined) this.causeCode = causeCode;
  }
}

function exactObject(value, keys, label) {
  if (!object(value)) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", `${label} must be an object`);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) {
    throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", `${label} contains unknown or missing fields`);
  }
}

function publicKeyForInvitation(value, algorithm) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 8192 || CONTROL.test(value) || /PRIVATE\s+KEY/iu.test(value)) {
    throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Possession receipt verification key is invalid");
  }
  let key;
  try { key = crypto.createPublicKey(value); } catch { throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Possession receipt verification key is invalid"); }
  const matches = algorithm === "ed25519"
    ? key.type === "public" && key.asymmetricKeyType === "ed25519"
    : algorithm === "p256-sha256" && key.type === "public" && key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  if (!matches || key.export({ type: "spki", format: "pem" }).toString() !== value) {
    throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Possession receipt verification key is invalid");
  }
  return value;
}

/**
 * Parse the only invitation shape accepted by headless setup. The returned
 * value is a secret-bearing handoff and must remain in the caller's closure;
 * it is intentionally not suitable for journal details or public output.
 */
export function parseEnrollmentInvitation(value) {
  const invitation = object(value) && Object.hasOwn(value, "enrollment") ? value.enrollment : value;
  if (object(value) && Object.hasOwn(value, "enrollment")) exactObject(value, ["enrollment"], "Enrollment handoff");
  exactObject(invitation, INVITATION_KEYS, "Enrollment invitation");
  if (invitation.version !== 2 || invitation.proof_version !== 2 || invitation.platform !== "macos") throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "A v2 macOS enrollment invitation is required");
  for (const key of ["enrollment_id", "organization_id", "device_id", "label", "challenge_id", "nonce", "expires_at", "credential", "endpoint"]) {
    if (typeof invitation[key] !== "string" || invitation[key].length === 0 || CONTROL.test(invitation[key])) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation is missing a required v2 field");
  }
  if ([...invitation.label].length > 128 || invitation.label.trim().length === 0) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation label is invalid");
  if (invitation.endpoint !== `/v1/enrollments/${invitation.enrollment_id}`) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation endpoint is not bound to its enrollment");
  if (!BASE64URL_CREDENTIAL.test(invitation.credential) || Buffer.from(invitation.credential, "base64url").length !== 32 || Buffer.from(invitation.credential, "base64url").toString("base64url") !== invitation.credential) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation credential is invalid");
  let candidate;
  try { candidate = buildEnrollmentCandidateBinding(invitation.candidate_binding); } catch { throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation candidate binding is invalid"); }
  if (candidate.enrollment_id !== invitation.enrollment_id || candidate.organization_id !== invitation.organization_id || candidate.device_id !== invitation.device_id || candidate.expires_at !== invitation.expires_at || Date.parse(candidate.expires_at) <= Date.now()) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation candidate binding is invalid");
  if (invitation.challenge_id !== invitation.enrollment_id || !object(invitation.challenge)) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation challenge is invalid");
  exactObject(invitation.challenge, CHALLENGE_KEYS, "Enrollment invitation challenge");
  if (invitation.challenge.challenge_id !== invitation.challenge_id || invitation.challenge.nonce !== invitation.nonce || invitation.challenge.expires_at !== invitation.expires_at || invitation.challenge.candidate_id !== candidate.candidate_id || invitation.challenge.device_key_fingerprint !== candidate.device_key_fingerprint) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation challenge binding is invalid");
  try { validateEnrollmentChallengeNonce(invitation.nonce); } catch { throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation nonce is invalid"); }
  exactObject(invitation.possession_receipt_verification, RECEIPT_VERIFICATION_KEYS, "Possession receipt verification metadata");
  const verification = invitation.possession_receipt_verification;
  if (!["ed25519", "p256-sha256"].includes(verification.algorithm) || typeof verification.key_id !== "string" || !SAFE_INVITATION_ID.test(verification.key_id)) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Possession receipt verification metadata is invalid");
  publicKeyForInvitation(verification.public_key, verification.algorithm);
  return Object.freeze({
    version: 2,
    proof_version: 2,
    enrollment_id: invitation.enrollment_id,
    organization_id: invitation.organization_id,
    device_id: invitation.device_id,
    label: invitation.label,
    platform: "macos",
    candidate_binding: Object.freeze({ ...candidate }),
    challenge_id: invitation.challenge_id,
    nonce: invitation.nonce,
    expires_at: invitation.expires_at,
    challenge: Object.freeze({ ...invitation.challenge }),
    credential: invitation.credential,
    endpoint: invitation.endpoint,
    possession_receipt_verification: Object.freeze({ ...verification })
  });
}

/** Validate and normalize the credential-free HTTPS API base used by setup. */
export function validateHeadlessEnrollmentBaseUrl(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL is invalid"); }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash || !/^\/v1\/?$/u.test(parsed.pathname)) throw new HeadlessOnboardingError("INVALID_ENROLLMENT_INVITATION", "Enrollment requires a credential-free HTTPS /v1 endpoint");
  parsed.pathname = "/v1";
  return parsed.toString();
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function safeCode(value, fallback = "SETUP_UNAVAILABLE") {
  return typeof value === "string" && SAFE_CODE.test(value) ? value : fallback;
}

function publicMessage(code) {
  return SAFE_ERROR_MESSAGES[code] ?? "Headless onboarding could not continue safely.";
}

function errorCode(error) {
  if (error instanceof HeadlessOnboardingError) return safeCode(error.code);
  if (error instanceof SetupJournalError) return safeCode(error.code);
  return safeCode(error?.code, "SETUP_UNAVAILABLE");
}

function initialAction() {
  return {
    id: "verify_app",
    command: "agentpass setup --client claude-code --project DIR --team-id TEAMID --execute"
  };
}

function publicAction(action) {
  if (!object(action)) return null;
  const result = {};
  for (const key of ["id", "target_state", "command", "description"]) {
    if (typeof action[key] === "string" && action[key].length > 0) result[key] = action[key];
  }
  return Object.keys(result).length > 0 ? result : null;
}

function publicStatus(status) {
  if (!object(status)) throw new HeadlessOnboardingError("SETUP_UNAVAILABLE", "Invalid onboarding status");
  const result = {
    version: HEADLESS_ONBOARDING_SCHEMA_VERSION,
    initialized: true,
    journal_id: status.journal_id,
    revision: status.revision,
    state: status.state,
    updated_at: status.updated_at,
    setup_complete: status.setup_complete === true,
    next_actions: Array.isArray(status.next_actions) ? status.next_actions.map(publicAction).filter(Boolean) : [],
    history_length: status.history_length
  };
  for (const key of Object.keys(result)) if (result[key] === undefined) delete result[key];
  if (status.blocked_error !== undefined) result.blocked_error = publicError(status.blocked_error);
  return result;
}

export function publicOnboardingError(error, { state = undefined } = {}) {
  const code = errorCode(error);
  return {
    version: HEADLESS_ONBOARDING_ERROR_VERSION,
    ok: false,
    error: {
      code,
      message: publicMessage(code),
      remediation: "Run `agentpass setup status` and `agentpass doctor` before retrying."
    },
    ...(typeof state === "string" ? { state } : {})
  };
}

function publicError(value) {
  return {
    code: safeCode(value?.code),
    message: publicMessage(safeCode(value?.code)),
    remediation: "Run `agentpass doctor` and follow the reported remediation."
  };
}

/**
 * Read the one durable onboarding state used by setup, status, doctor, and the
 * display-only native client. Missing state is a normal not-started result;
 * every other journal error is returned as a blocked result and never mapped to
 * not_started. That distinction prevents a damaged journal from being reset by
 * a retry.
 */
export function readHeadlessOnboarding(options = {}) {
  const load = options.loadJournal ?? loadSetupJournal;
  try {
    const journal = load(options.journalOptions ?? {});
    return { ok: true, status: publicStatus(journal.status()) };
  } catch (error) {
    if (error instanceof SetupJournalError && error.code === "NOT_INITIALIZED") {
      return {
        ok: true,
        status: {
          version: HEADLESS_ONBOARDING_SCHEMA_VERSION,
          initialized: false,
          state: "not_started",
          setup_complete: false,
          next_actions: [initialAction()]
        }
      };
    }
    return { ok: false, status: null, error: publicOnboardingError(error) };
  }
}

export function requireHeadlessOnboarding(options = {}) {
  const result = readHeadlessOnboarding(options);
  if (!result.ok) {
    const error = new HeadlessOnboardingError(result.error.error.code, result.error.error.message);
    throw error;
  }
  return result.status;
}

/**
 * Remove free-form process, filesystem, and provider diagnostics before they
 * enter a machine-readable doctor report. Known safe words remain useful for
 * operators; unknown objects are summarized rather than serialized.
 */
export function redactDiagnostic(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return "diagnostic_available";
  let result = value.replace(URL_CREDENTIAL, "[credential-url]").replace(CREDENTIAL, (match) => {
    const equals = match.indexOf("=");
    const colon = match.indexOf(":");
    const separator = equals < 0 ? colon : colon < 0 ? equals : Math.min(equals, colon);
    return separator < 0 ? "[redacted]" : `${match.slice(0, separator + 1)}[redacted]`;
  });
  result = result.replace(SAFE_PATH, "[path]");
  result = result.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim();
  if (result.length > 256) result = `${result.slice(0, 253)}...`;
  return result || "diagnostic_available";
}

export function publicSetupResult(result) {
  if (!object(result)) return { version: HEADLESS_ONBOARDING_SCHEMA_VERSION, ok: true, changed: false };
  const journal = result.journal;
  const output = {
    version: HEADLESS_ONBOARDING_SCHEMA_VERSION,
    ok: true,
    execute: result.execute === true,
    dry_run: result.dry_run === true,
    changed: result.changed === true,
    ...(result.stale === true ? { stale: true } : {}),
    ...(typeof result.state === "string" ? { state: result.state } : {}),
    ...(publicAction(result.action) ? { action: publicAction(result.action) } : {}),
    ...(object(journal) ? { onboarding: publicStatus(journal) } : {})
  };
  return output;
}

export function publicSetupFailure(error, status = undefined) {
  const result = publicOnboardingError(error, { state: status?.state });
  if (status) result.onboarding = publicStatus(status);
  return result;
}
