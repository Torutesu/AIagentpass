export const CLAUDE_CODE_SECRET_SCAN_VERSION = 1;

const SECRET_KEY = /(?:access[_ -]?token|api[_ -]?key|authorization|bearer|certificate|cookie|credential|password|passwd|private[_ -]?key|refresh[_ -]?token|secret|session|signing[_ -]?key|token)/iu;
const SECRET_VALUE = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/u,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/iu,
  /\bBasic\s+[A-Za-z0-9+/=]{12,}/u,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:sk|rk)-[A-Za-z0-9_-]{20,}\b/u,
  /(?:access[_ -]?token|api[_ -]?key|authorization|bearer|cookie|credential|password|passwd|private[_ -]?key|refresh[_ -]?token|secret|session|signing[_ -]?key|token)\s*[:=]\s*[^\s,;)}\]]{4,}/iu
];

export class ClaudeCodeSecretScanError extends Error {
  constructor(code = "secret_detected") {
    super("Claude Code adapter artifact failed the secret scan");
    this.name = "ClaudeCodeSecretScanError";
    this.code = code;
  }
}

function secretFailure() {
  throw new ClaudeCodeSecretScanError();
}

function scanText(value) {
  if (typeof value !== "string" || SECRET_VALUE.some((pattern) => pattern.test(value))) secretFailure();
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

function scanArray(value) {
  if (value === undefined) return 0;
  if (!Array.isArray(value)) secretFailure();
  for (const entry of value) scanText(entry);
  return value.length;
}

/** Scan argv, environment, stdout, and stderr; return counts only. */
export function scanClaudeCodeAdapterArtifacts(input = {}) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) secretFailure();
  const allowed = new Set(["argv", "environment", "stdout", "stderr"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) secretFailure();
  const { argv = [], environment = {}, stdout = "", stderr = "" } = input;
  const argvCount = scanArray(argv);
  const environmentCount = scanEnvironment(environment);
  scanText(stdout);
  scanText(stderr);
  return Object.freeze({
    version: CLAUDE_CODE_SECRET_SCAN_VERSION,
    safe: true,
    checked: Object.freeze({ argv: argvCount, environment: environmentCount, stdout: 1, stderr: 1 })
  });
}

export const assertClaudeCodeAdapterSecretFree = scanClaudeCodeAdapterArtifacts;
