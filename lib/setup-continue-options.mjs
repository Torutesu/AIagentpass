const USAGE = "Usage: agentpass setup continue [--execute] [--browser --console-url HTTPS_URL --enrollment-url HTTPS_URL | --enrollment-url HTTPS_URL --enrollment-stdin]";

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

function requiredValue(args, index) {
  const value = args[index];
  if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) throw usageError();
  return value;
}

function usageError() { return new Error(USAGE); }
