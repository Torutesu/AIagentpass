const USAGE = "Usage: agentpass setup continue [--execute] [--browser --console-url HTTPS_URL --enrollment-url HTTPS_URL | --enrollment-url HTTPS_URL --enrollment-stdin]";
const CONTROL = /[\u0000-\u001f\u007f]/u;
const SECRET_LIKE = /(?:bearer|basic|token|secret|password|passwd|credential|authorization|cookie|private[_ -]?key|key[_ -]?material)\s*[:=]/iu;
const MAX_ARGUMENT_BYTES = 2048;

export function parseSetupContinueOptions(args = []) {
  let execute = false;
  let browser = false;
  let enrollmentStdin = false;
  let consoleUrl;
  let enrollmentUrl;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--execute" && !execute) { execute = true; continue; }
    if (argument === "--browser" && !browser) { browser = true; continue; }
    if (argument === "--enrollment-stdin" && !enrollmentStdin) { enrollmentStdin = true; continue; }
    if (argument === "--console-url" && consoleUrl === undefined) {
      consoleUrl = requiredValue(args, ++index);
      continue;
    }
    if (argument === "--enrollment-url" && enrollmentUrl === undefined) {
      enrollmentUrl = requiredValue(args, ++index);
      continue;
    }
    throw usageError();
  }

  const hasEnrollmentOption = browser || enrollmentStdin || consoleUrl !== undefined || enrollmentUrl !== undefined;
  if (hasEnrollmentOption && !execute) throw new Error("Browser or stdin enrollment requires --execute");
  if (browser && enrollmentStdin) throw new Error("Choose exactly one enrollment handoff: --browser or --enrollment-stdin");
  if (browser && (consoleUrl === undefined || enrollmentUrl === undefined)) {
    throw new Error("Browser enrollment requires --browser, --console-url, and --enrollment-url together");
  }
  if (enrollmentStdin && (consoleUrl !== undefined || enrollmentUrl === undefined)) {
    throw new Error("Stdin enrollment requires --enrollment-url and --enrollment-stdin, without --console-url");
  }
  if (!browser && !enrollmentStdin && (consoleUrl !== undefined || enrollmentUrl !== undefined)) throw usageError();

  return Object.freeze({ execute, browser, enrollmentStdin, consoleUrl, enrollmentUrl });
}

/**
 * A durable recovery descriptor is the authority for a resumed enrollment.
 * Do not let a later invocation replace it with a fresh browser/stdin
 * handoff or a caller-selected endpoint. The caller can retry the same
 * command with no enrollment arguments and the handler will perform its
 * signed GET-only recovery.
 */
export function assertFixedResumeDescriptorOptions(flags, descriptor) {
  if (descriptor === undefined || descriptor === null) return;
  if (flags?.browser === true || flags?.enrollmentStdin === true || flags?.consoleUrl !== undefined || flags?.enrollmentUrl !== undefined) {
    throw new Error("A durable enrollment recovery is already prepared; resume without browser, stdin, or URL options");
  }
}

function requiredValue(args, index) {
  const value = args[index];
  if (typeof value !== "string" || value.length === 0 || value.startsWith("--") || Buffer.byteLength(value, "utf8") > MAX_ARGUMENT_BYTES || CONTROL.test(value) || SECRET_LIKE.test(value)) throw usageError();
  return value;
}

function usageError() { return new Error(USAGE); }
