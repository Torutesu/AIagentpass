export const CURSOR_SECRET_SCAN_VERSION = 1;

const SECRET_KEY = /(?:access[_ -]?token|api[_ -]?key|authorization|bearer|certificate|cookie|credential|password|passwd|private[_ -]?key|refresh[_ -]?token|secret|session|signing[_ -]?key|token)/iu;
const SECRET_VALUE = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/u,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/iu,
  /\bBasic\s+[A-Za-z0-9+/=]{12,}/iu,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:sk|rk)-[A-Za-z0-9_-]{20,}\b/u,
  /(?:access[_ -]?token|api[_ -]?key|authorization|bearer|cookie|credential|password|passwd|private[_ -]?key|refresh[_ -]?token|secret|session|signing[_ -]?key|token)\s*[:=]\s*[^\s,;)}\]]{4,}/iu
];

export class CursorSecretScanError extends Error {
  constructor(code = "secret_detected") {
    super("Cursor adapter artifact failed the secret scan");
    this.name = "CursorSecretScanError";
    this.code = code;
  }
}

function secretFailure() {
  throw new CursorSecretScanError();
}

function scanText(value) {
  if (typeof value !== "string") secretFailure();
  if (SECRET_VALUE.some((pattern) => pattern.test(value))) secretFailure();
}

function scanEnvironment(value) {
  if (value === undefined) return 0;
  if (value === null || typeof value !== "object" || Array.isArray(value)) secretFailure();
  let count = 0;
  for (const [key, entry] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) secretFailure();
    scanText(key);
    scanText(entry);
    count += 1;
  }
  return count;
}

function scanArray(value, label) {
  if (value === undefined) return 0;
  if (!Array.isArray(value)) secretFailure();
  for (const entry of value) scanText(entry);
  return value.length;
}

/**
 * Scan only adapter-controlled boundaries. The result contains counts, never
 * matching text or artifact contents, so a failure is safe to log and return.
 */
export function scanCursorAdapterArtifacts({ argv = [], environment = {}, stdout = "", stderr = "" } = {}) {
  const argvCount = scanArray(argv, "argv");
  const environmentCount = scanEnvironment(environment);
  scanText(stdout);
  scanText(stderr);
  return Object.freeze({
    version: CURSOR_SECRET_SCAN_VERSION,
    safe: true,
    checked: Object.freeze({ argv: argvCount, environment: environmentCount, stdout: 1, stderr: 1 })
  });
}

export const assertCursorAdapterSecretFree = scanCursorAdapterArtifacts;

