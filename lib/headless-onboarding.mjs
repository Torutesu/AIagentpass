import { SetupJournalError, loadSetupJournal } from "./setup-journal.mjs";

export const HEADLESS_ONBOARDING_SCHEMA_VERSION = 1;
export const HEADLESS_ONBOARDING_ERROR_VERSION = 1;

const SAFE_CODE = /^(?:[A-Z][A-Z0-9_]{1,63}|[a-z][a-z0-9_.-]{1,63})$/;
const SAFE_PATH = /(?:^|[\s(])(?:~|\/Users\/|\/private\/|\/tmp\/|\/var\/|\/Applications\/|\/Library\/|\/opt\/)[^\s),;]*/gu;
const CREDENTIAL = /\b(?:bearer|basic|token|secret|password|passwd|credential|authorization|cookie|assertion|private[_ -]?key|key[_ -]?material)\s*[:=]\s*[^\s,;)]*/giu;
const URL_CREDENTIAL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@/giu;

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
