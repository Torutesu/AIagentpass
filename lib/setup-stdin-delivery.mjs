import { parseControlBundleJson } from "./control-bundle-v2.mjs";
import { parseEnrollmentInvitation, validateHeadlessEnrollmentBaseUrl } from "./headless-onboarding.mjs";
import { normalizeOnboardingInvitation } from "./onboarding-contract.mjs";

export const SETUP_STDIN_DELIVERY_MAX_BYTES = 16 * 1024;
export const SETUP_STDIN_DELIVERY_MAX_TIMEOUT_MS = 30 * 1000;

export const SETUP_STDIN_DELIVERY_ERRORS = Object.freeze({
  INVALID_OPTIONS: "ERR_SETUP_STDIN_DELIVERY_OPTIONS",
  TTY: "ERR_SETUP_STDIN_DELIVERY_TTY",
  EMPTY: "ERR_SETUP_STDIN_DELIVERY_EMPTY",
  TOO_LARGE: "ERR_SETUP_STDIN_DELIVERY_TOO_LARGE",
  TIMEOUT: "ERR_SETUP_STDIN_DELIVERY_TIMEOUT",
  READ: "ERR_SETUP_STDIN_DELIVERY_READ",
  REPLAY: "ERR_SETUP_STDIN_DELIVERY_REPLAY",
  INVALID_INVITATION: "INVALID_ENROLLMENT_INVITATION",
  EXPIRED: "ERR_SETUP_STDIN_DELIVERY_EXPIRED",
  ENDPOINT: "ERR_SETUP_STDIN_DELIVERY_ENDPOINT"
});

const STATIC_MESSAGES = Object.freeze({
  [SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS]: "Stdin enrollment options are invalid",
  [SETUP_STDIN_DELIVERY_ERRORS.TTY]: "Stdin enrollment requires redirected input",
  [SETUP_STDIN_DELIVERY_ERRORS.EMPTY]: "The enrollment invitation input is empty",
  [SETUP_STDIN_DELIVERY_ERRORS.TOO_LARGE]: "The enrollment invitation exceeds 16 KiB",
  [SETUP_STDIN_DELIVERY_ERRORS.TIMEOUT]: "Reading the enrollment invitation timed out",
  [SETUP_STDIN_DELIVERY_ERRORS.READ]: "The enrollment invitation could not be read",
  [SETUP_STDIN_DELIVERY_ERRORS.REPLAY]: "The enrollment invitation input was already consumed",
  [SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION]: "The enrollment invitation is invalid",
  [SETUP_STDIN_DELIVERY_ERRORS.EXPIRED]: "The enrollment invitation has expired",
  [SETUP_STDIN_DELIVERY_ERRORS.ENDPOINT]: "The enrollment invitation endpoint is invalid"
});

const consumedInputs = new WeakSet();

export class SetupStdinDeliveryError extends Error {
  constructor(code) {
    super(STATIC_MESSAGES[code] ?? STATIC_MESSAGES[SETUP_STDIN_DELIVERY_ERRORS.READ]);
    this.name = "SetupStdinDeliveryError";
    this.code = code;
  }
}

/**
 * Read exactly one v2 invitation from redirected stdin. The source is a
 * transient stream only: no input is echoed, logged, persisted, or copied to
 * argv/environment. The returned invitation is a fresh validated object;
 * temporary byte buffers are cleared in the finally path.
 */
export async function readSetupEnrollmentInvitationStdin(options = {}) {
  const config = normalizeOptions(options);
  if (config.input.isTTY === true) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.TTY);
  if (consumedInputs.has(config.input)) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.REPLAY);
  consumedInputs.add(config.input);

  const bytes = await readInput(config.input, config.timeoutMs);
  try {
    if (bytes.length === 0 || bytes.every((value) => value === 0x20 || value === 0x09 || value === 0x0a || value === 0x0d)) {
      throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.EMPTY);
    }

    let parsed;
    try {
      // This decoder rejects malformed UTF-8, duplicate keys, trailing JSON,
      // and excessive nesting before the invitation validator sees data.
      parsed = parseControlBundleJson(bytes, { maxBytes: SETUP_STDIN_DELIVERY_MAX_BYTES, maxDepth: 16 });
    } catch {
      throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION);
    }

    const expectedEndpoint = expectedEnrollmentEndpoint(config.enrollmentUrl, parsed);
    if (parsed && typeof parsed.endpoint === "string" && parsed.endpoint !== expectedEndpoint) {
      throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.ENDPOINT);
    }
    let normalized;
    try {
      normalized = normalizeOnboardingInvitation(parsed);
    } catch {
      throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION);
    }
    if (normalized.endpoint !== expectedEndpoint) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.ENDPOINT);
    if (Date.parse(normalized.expires_at) <= Date.now()) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.EXPIRED);

    try {
      return parseEnrollmentInvitation(normalized);
    } catch {
      throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION);
    }
  } finally {
    bytes.fill(0);
  }
}

function normalizeOptions(options) {
  if (!plainObject(options)) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  const allowed = new Set(["input", "enrollmentUrl", "timeoutMs"]);
  if (Object.keys(options).some((key) => !allowed.has(key))) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  const input = options.input ?? process.stdin;
  if (!input || typeof input.on !== "function" || typeof input.removeListener !== "function" || typeof input.pause !== "function") {
    throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  }
  if (typeof options.enrollmentUrl !== "string") throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  let enrollmentUrl;
  try {
    enrollmentUrl = validateHeadlessEnrollmentBaseUrl(options.enrollmentUrl);
  } catch {
    throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  }
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > SETUP_STDIN_DELIVERY_MAX_TIMEOUT_MS) {
    throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS);
  }
  return { input, enrollmentUrl, timeoutMs };
}

function expectedEnrollmentEndpoint(enrollmentUrl, parsed) {
  const enrollmentId = parsed && typeof parsed === "object" && typeof parsed.enrollment_id === "string"
    ? parsed.enrollment_id
    : undefined;
  if (!enrollmentId) throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION);
  let base;
  try { base = new URL(enrollmentUrl); } catch { throw new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.INVALID_OPTIONS); }
  return `${base.pathname}/enrollments/${enrollmentId}`;
}

function readInput(input, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("error", onError);
      input.removeListener("aborted", onAborted);
      input.removeListener("close", onClose);
    };
    const clearChunks = () => {
      for (const chunk of chunks) chunk.fill(0);
      chunks.length = 0;
    };
    const stop = () => {
      try { input.pause(); } catch {}
    };
    const destroyQuietly = () => {
      if (typeof input.destroy !== "function") return;
      const swallow = () => {};
      input.once?.("error", swallow);
      try { input.destroy(); } catch {}
      setImmediate(() => input.removeListener("error", swallow));
    };
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      clearChunks();
      if (error) {
        stop();
        if (error.code === SETUP_STDIN_DELIVERY_ERRORS.TOO_LARGE || error.code === SETUP_STDIN_DELIVERY_ERRORS.TIMEOUT) destroyQuietly();
        reject(error);
      } else {
        resolve(value);
      }
    };
    const onData = (chunk) => {
      if (settled) return;
      let bytes;
      try {
        bytes = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk instanceof Uint8Array ? chunk : String(chunk), "utf8");
      } catch {
        finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.READ));
        return;
      }
      total += bytes.length;
      if (total > SETUP_STDIN_DELIVERY_MAX_BYTES) {
        bytes.fill(0);
        finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.TOO_LARGE));
        return;
      }
      chunks.push(bytes);
      if (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array) chunk.fill(0);
    };
    const onEnd = () => {
      const value = Buffer.concat(chunks, total);
      finish(null, value);
    };
    const onError = () => finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.READ));
    const onAborted = () => finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.READ));
    const onClose = () => {
      if (!settled) finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.READ));
    };

    timer = setTimeout(() => finish(new SetupStdinDeliveryError(SETUP_STDIN_DELIVERY_ERRORS.TIMEOUT)), timeoutMs);
    input.on("data", onData);
    input.once("end", onEnd);
    input.once("error", onError);
    input.once("aborted", onAborted);
    input.once("close", onClose);
    input.resume?.();
  });
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
