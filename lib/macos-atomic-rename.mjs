import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * The native helper must call renameatx_np(2) with RENAME_EXCL.  Node's
 * renameSync is an unconditional replacement and therefore cannot be used for
 * the final integration install.  The helper is deliberately a tiny, fixed
 * executable rather than a shell command: all arguments are passed through
 * spawnSync with shell:false.
 */
export const ATOMIC_RENAME_HELPER_PROTOCOL = "agentpass.atomic-rename.v1";

export const ATOMIC_RENAME_EXIT_CODES = Object.freeze({
  SUCCESS: 0,
  DESTINATION_EXISTS: 17,
  UNSAFE_INPUT: 77,
  UNSUPPORTED_FILESYSTEM: 78
});

export const ATOMIC_RENAME_CODES = Object.freeze({
  COMPLETE: "ATOMIC_RENAME_COMPLETE",
  DESTINATION_EXISTS: "ATOMIC_RENAME_DESTINATION_EXISTS",
  UNSUPPORTED_PLATFORM: "ATOMIC_RENAME_UNSUPPORTED_PLATFORM",
  HELPER_UNAVAILABLE: "ATOMIC_RENAME_HELPER_UNAVAILABLE",
  HELPER_UNSAFE: "ATOMIC_RENAME_HELPER_UNSAFE",
  INVALID_PATH: "ATOMIC_RENAME_INVALID_PATH",
  INVALID_BOUNDARY: "ATOMIC_RENAME_INVALID_BOUNDARY",
  INVALID_OWNER: "ATOMIC_RENAME_INVALID_OWNER",
  SOURCE_UNSAFE: "ATOMIC_RENAME_SOURCE_UNSAFE",
  DESTINATION_UNSAFE: "ATOMIC_RENAME_DESTINATION_UNSAFE",
  DIFFERENT_PARENT: "ATOMIC_RENAME_DIFFERENT_PARENT",
  HELPER_FAILED: "ATOMIC_RENAME_HELPER_FAILED",
  HELPER_PROTOCOL: "ATOMIC_RENAME_HELPER_PROTOCOL",
  POSTCONDITION_FAILED: "ATOMIC_RENAME_POSTCONDITION_FAILED"
});

export class AtomicRenameNoReplaceError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "AtomicRenameNoReplaceError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_HELPER_OUTPUT_BYTES = 16 * 1024;
const DEFAULT_HELPER_NAME = "agentpass-atomic-rename";

function fail(code, message, details = undefined) {
  throw new AtomicRenameNoReplaceError(code, message, details);
}

function isIntegerOwner(value) {
  return Number.isInteger(value) && value >= 0;
}

function canonicalAbsolute(value, label, code = ATOMIC_RENAME_CODES.INVALID_PATH) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || !path.isAbsolute(value)) {
    fail(code, `${label} must be a non-empty absolute path`);
  }
  const normalized = path.normalize(value);
  if (normalized !== value || value.endsWith(path.sep) && value !== path.parse(value).root) {
    fail(code, `${label} must be normalized and must not contain dot segments`);
  }
  return value;
}

function baseName(value, label) {
  const name = path.basename(value);
  if (!name || name === "." || name === ".." || name.includes("\0") || name.includes(path.sep)) {
    fail(ATOMIC_RENAME_CODES.INVALID_PATH, `${label} must be a single path component`);
  }
  return name;
}

function insideBoundary(target, boundary, label) {
  const relative = path.relative(boundary, target);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    fail(ATOMIC_RENAME_CODES.INVALID_BOUNDARY, `${label} must be inside the supplied boundary`);
  }
}

function insideOrAtBoundary(target, boundary, label) {
  const relative = path.relative(boundary, target);
  if (relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    fail(ATOMIC_RENAME_CODES.INVALID_BOUNDARY, `${label} must be inside the supplied boundary`);
  }
}

function lstatOrFail(filesystem, target, code, label) {
  try {
    return filesystem.lstatSync(target);
  } catch (error) {
    fail(code, `${label} cannot be inspected`, { causeCode: error?.code });
  }
}

function trustedDirectory(filesystem, directory, owner, label, missingCode = ATOMIC_RENAME_CODES.INVALID_BOUNDARY) {
  const stat = lstatOrFail(filesystem, directory, missingCode, label);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
    fail(ATOMIC_RENAME_CODES.INVALID_BOUNDARY, `${label} must be a private directory owned by ${owner}`);
  }
  return stat;
}

function validateDirectoryChain(filesystem, boundary, targetDirectory, owner, label) {
  const boundaryStat = trustedDirectory(filesystem, boundary, owner, `${label} boundary`);
  insideOrAtBoundary(targetDirectory, boundary, `${label} parent`);
  const relative = path.relative(boundary, targetDirectory);
  let current = boundary;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const currentStat = trustedDirectory(filesystem, current, owner, `${label} parent`);
    if (boundaryStat.dev !== undefined && currentStat.dev !== undefined && currentStat.dev !== boundaryStat.dev) {
      fail(ATOMIC_RENAME_CODES.INVALID_BOUNDARY, `${label} parent crosses a filesystem boundary`);
    }
  }
}

function validateRegularSource(filesystem, source, owner) {
  const stat = lstatOrFail(filesystem, source, ATOMIC_RENAME_CODES.SOURCE_UNSAFE, "Atomic rename source");
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
    fail(ATOMIC_RENAME_CODES.SOURCE_UNSAFE, "Atomic rename source must be a private single-link regular file");
  }
  return stat;
}

function validateDestination(filesystem, destination, owner) {
  let stat;
  try { stat = filesystem.lstatSync(destination); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    fail(ATOMIC_RENAME_CODES.DESTINATION_UNSAFE, "Atomic rename destination cannot be inspected", { causeCode: error?.code });
  }
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== owner || (stat.mode & 0o022) !== 0) {
    fail(ATOMIC_RENAME_CODES.DESTINATION_UNSAFE, "Existing atomic rename destination is not a trusted regular file");
  }
  fail(ATOMIC_RENAME_CODES.DESTINATION_EXISTS, "Atomic rename destination already exists", { destination });
}

function validateHelper(filesystem, helperPath, helperBoundary, helperOwner) {
  try {
    validateDirectoryChain(filesystem, helperBoundary, path.dirname(helperPath), helperOwner, "Atomic rename helper");
  } catch (error) {
    if (error?.code === ATOMIC_RENAME_CODES.INVALID_BOUNDARY) {
      fail(ATOMIC_RENAME_CODES.HELPER_UNSAFE, "Atomic rename helper boundary is unsafe", { causeCode: error.code });
    }
    throw error;
  }
  const stat = lstatOrFail(filesystem, helperPath, ATOMIC_RENAME_CODES.HELPER_UNAVAILABLE, "Atomic rename helper");
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== helperOwner || (stat.mode & 0o022) !== 0 || (stat.mode & 0o6000) !== 0 || (stat.mode & 0o111) === 0) {
    fail(ATOMIC_RENAME_CODES.HELPER_UNSAFE, "Atomic rename helper must be an owned, non-writable executable");
  }
  return stat;
}

function safeSpawnResult(result) {
  if (result?.error) {
    fail(ATOMIC_RENAME_CODES.HELPER_FAILED, "Atomic rename helper could not be started", { causeCode: result.error.code });
  }
  if (!result || typeof result !== "object" || !Number.isInteger(result.status) || result.status < 0 || result.status > 255) {
    fail(ATOMIC_RENAME_CODES.HELPER_PROTOCOL, "Atomic rename helper returned an invalid process result");
  }
  return result;
}

function helperArgs({ sourceParent, sourceName, destinationParent, destinationName, boundary, owner, sourceStat }) {
  const sourceMtime = typeof sourceStat.mtimeNs === "bigint"
    ? sourceStat.mtimeNs.toString()
    : String(Math.round(sourceStat.mtimeMs * 1_000_000));
  return [
    "--protocol", ATOMIC_RENAME_HELPER_PROTOCOL,
    "--operation", "rename-no-replace",
    "--source-parent", sourceParent,
    "--source-name", sourceName,
    "--destination-parent", destinationParent,
    "--destination-name", destinationName,
    "--boundary", boundary,
    "--owner", String(owner),
    "--source-dev", String(sourceStat.dev),
    "--source-ino", String(sourceStat.ino),
    "--source-size", String(sourceStat.size),
    "--source-mtime-ns", sourceMtime
  ];
}

function defaultSpawn(file, args, options) {
  return spawnSync(file, args, options);
}

function defaultHelperPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "native", "macos", "Resources", "bin", DEFAULT_HELPER_NAME);
}

/**
 * Atomically moves source to an absent destination on macOS.
 *
 * The packaged helper contract is intentionally narrow. It must open both
 * parent directories with O_DIRECTORY|O_NOFOLLOW, verify owner/mode/device,
 * the boundary, and the expected source identity, then call renameatx_np(
 * sourceFd, sourceName, destinationFd, destinationName, RENAME_EXCL) and
 * fsync the affected directory. It must not
 * accept a shell command, a script, or a destination replacement operation.
 *
 * This wrapper performs the same checks before invoking the helper so callers
 * fail closed early, but the helper's descriptor-relative checks are the
 * security boundary against pathname substitution during the call.
 */
export function atomicRenameNoReplaceSync(options = {}) {
  const filesystem = options.fs ?? fs;
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") fail(ATOMIC_RENAME_CODES.UNSUPPORTED_PLATFORM, "Atomic rename-no-replace is available only on macOS");

  const source = canonicalAbsolute(options.source, "source");
  const destination = canonicalAbsolute(options.destination, "destination");
  const boundary = canonicalAbsolute(options.boundary, "boundary", ATOMIC_RENAME_CODES.INVALID_BOUNDARY);
  const helperPath = canonicalAbsolute(options.helperPath ?? defaultHelperPath(), "helperPath", ATOMIC_RENAME_CODES.HELPER_UNSAFE);
  const helperBoundary = canonicalAbsolute(options.helperBoundary ?? path.dirname(helperPath), "helperBoundary", ATOMIC_RENAME_CODES.INVALID_BOUNDARY);
  const owner = options.owner ?? process.getuid?.();
  const helperOwner = options.helperOwner ?? 0;
  if (!isIntegerOwner(owner) || !isIntegerOwner(helperOwner)) fail(ATOMIC_RENAME_CODES.INVALID_OWNER, "source and helper owners must be non-negative integers");

  const sourceParent = path.dirname(source);
  const destinationParent = path.dirname(destination);
  if (sourceParent !== destinationParent) fail(ATOMIC_RENAME_CODES.DIFFERENT_PARENT, "Atomic rename-no-replace requires one parent directory");
  validateDirectoryChain(filesystem, boundary, sourceParent, owner, "Atomic rename target");
  insideBoundary(source, boundary, "source");
  insideBoundary(destination, boundary, "destination");
  const sourceName = baseName(source, "source");
  const destinationName = baseName(destination, "destination");
  const sourceStat = validateRegularSource(filesystem, source, owner);
  validateDestination(filesystem, destination, owner);
  validateHelper(filesystem, helperPath, helperBoundary, helperOwner);

  const spawnFileSync = options.spawnFileSync ?? defaultSpawn;
  if (typeof spawnFileSync !== "function") fail(ATOMIC_RENAME_CODES.HELPER_PROTOCOL, "spawnFileSync dependency must be callable");
  const result = safeSpawnResult(spawnFileSync(helperPath, helperArgs({
    sourceParent,
    sourceName,
    destinationParent,
    destinationName,
    boundary,
    owner,
    sourceStat
  }), {
    shell: false,
    windowsHide: true,
    encoding: "utf8",
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxBuffer: MAX_HELPER_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C" }
  }));

  if (result.status === ATOMIC_RENAME_EXIT_CODES.DESTINATION_EXISTS) {
    fail(ATOMIC_RENAME_CODES.DESTINATION_EXISTS, "Atomic rename helper refused to replace an existing destination", { destination });
  }
  if (result.status !== ATOMIC_RENAME_EXIT_CODES.SUCCESS) {
    fail(ATOMIC_RENAME_CODES.HELPER_FAILED, "Atomic rename helper failed", {
      status: result.status,
      signal: result.signal ?? null,
      stderr: typeof result.stderr === "string" ? result.stderr.slice(0, MAX_HELPER_OUTPUT_BYTES) : ""
    });
  }

  let destinationStat;
  try { destinationStat = filesystem.lstatSync(destination); }
  catch (error) { fail(ATOMIC_RENAME_CODES.POSTCONDITION_FAILED, "Atomic rename helper reported success but destination is absent", { causeCode: error?.code }); }
  if (!destinationStat.isFile() || destinationStat.isSymbolicLink() || destinationStat.uid !== owner || (destinationStat.mode & 0o022) !== 0 || destinationStat.dev !== sourceStat.dev || destinationStat.ino !== sourceStat.ino) {
    fail(ATOMIC_RENAME_CODES.POSTCONDITION_FAILED, "Atomic rename helper reported an unsafe destination");
  }
  try {
    filesystem.lstatSync(source);
    fail(ATOMIC_RENAME_CODES.POSTCONDITION_FAILED, "Atomic rename helper reported success but source remains present");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return Object.freeze({
    code: ATOMIC_RENAME_CODES.COMPLETE,
    source,
    destination,
    helperPath,
    sourceDevice: sourceStat.dev,
    destinationDevice: destinationStat.dev
  });
}

export const renameNoReplaceSync = atomicRenameNoReplaceSync;
