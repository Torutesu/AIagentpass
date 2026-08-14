import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { atomicWrite, defaultConfigDir, secureMkdir } from "./config.mjs";

export const SETUP_JOURNAL_VERSION = 1;
export const SETUP_JOURNAL_KIND = "agentpass.setup-journal";
export const SETUP_JOURNAL_ANCHOR_KIND = "agentpass.setup-journal-anchor";
export const SETUP_JOURNAL_FILENAME = "setup-journal.json";
export const SETUP_JOURNAL_ANCHOR_FILENAME = "setup-journal.anchor.json";

// The order is part of the local setup protocol. Do not reorder existing states.
export const SETUP_STATES = Object.freeze([
  "not_started",
  "app_verified",
  "local_config_initialized",
  "native_bridge_selected",
  "service_registered",
  "bootstrap_started",
  "approval_key_enrolled",
  "service_keys_activated",
  "device_enrolled",
  "editor_connected",
  "test_commit_verified",
  "complete"
]);

const STATE_INDEX = new Map(SETUP_STATES.map((state, index) => [state, index]));

const NEXT_ACTIONS = Object.freeze({
  not_started: [{ id: "verify_app", target_state: "app_verified", command: "agentpass setup continue", description: "Verify the signed AgentPass application" }],
  app_verified: [{ id: "initialize_local_config", target_state: "local_config_initialized", command: "agentpass setup continue", description: "Initialize user-owned local configuration" }],
  local_config_initialized: [{ id: "select_native_bridge", target_state: "native_bridge_selected", command: "agentpass setup continue", description: "Select and verify the native bridge" }],
  native_bridge_selected: [{ id: "register_service", target_state: "service_registered", command: "agentpass setup continue", description: "Register the background native service" }],
  service_registered: [{ id: "start_bootstrap", target_state: "bootstrap_started", command: "agentpass setup continue", description: "Start the native bootstrap ceremony" }],
  bootstrap_started: [{ id: "enroll_approval_key", target_state: "approval_key_enrolled", command: "agentpass setup continue", description: "Enroll the approval key" }],
  approval_key_enrolled: [{ id: "activate_service_keys", target_state: "service_keys_activated", command: "agentpass setup continue", description: "Activate the non-exportable service keys" }],
  service_keys_activated: [{ id: "enroll_device", target_state: "device_enrolled", command: "agentpass setup continue --execute --browser --console-url HTTPS_CONSOLE --enrollment-url HTTPS_API/v1", description: "Open Console and enroll this device through the one-time local handoff" }],
  device_enrolled: [{ id: "connect_editor", target_state: "editor_connected", command: "agentpass setup continue", description: "Connect a coding agent integration" }],
  editor_connected: [{ id: "verify_test_commit", target_state: "test_commit_verified", command: "agentpass setup continue", description: "Verify a policy-compliant test commit" }],
  test_commit_verified: [{ id: "complete_setup", target_state: "complete", command: "agentpass setup continue", description: "Record setup completion" }],
  complete: []
});

const JOURNAL_KEYS = ["kind", "version", "journal_id", "revision", "state", "updated_at", "history", "integrity"];
const HISTORY_KEYS = ["revision", "state", "completed_at", "details"];
const INTEGRITY_KEYS = ["algorithm", "previous_hash", "hash"];
const ANCHOR_KEYS = ["kind", "version", "journal_id", "revision", "tip_hash", "previous_tip", "tip"];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const ISO_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SAFE_DETAIL_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const SENSITIVE_DETAIL_KEY = /(token|secret|password|private|credential|authorization|capability|signature|assertion|payload|key_material)/i;

export class SetupJournalError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "SetupJournalError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function fail(code, message, details) {
  throw new SetupJournalError(code, message, details);
}

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  fail("TAMPERED_JOURNAL", "Setup journal contains a non-canonical value");
}

function hashUnsignedJournal(journal) {
  const unsigned = {
    kind: journal.kind,
    version: journal.version,
    journal_id: journal.journal_id,
    revision: journal.revision,
    state: journal.state,
    updated_at: journal.updated_at,
    history: journal.history
  };
  return crypto.createHash("sha256").update(canonicalize(unsigned)).digest("hex");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sameJson(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function assertObject(value, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code, `${label} must be an object`);
}

function assertExactKeys(value, keys, code, label) {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.some((key) => !expected.has(key)) || keys.some((key) => !Object.hasOwn(value, key))) {
    fail(code, `${label} contains unknown or missing fields`);
  }
}

function assertUuid(value, code, label) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) fail(code, `${label} is invalid`);
}

function assertIso(value, code, label) {
  if (typeof value !== "string" || !ISO_PATTERN.test(value) || Number.isNaN(Date.parse(value))) fail(code, `${label} is invalid`);
}

function assertHash(value, code, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) fail(code, `${label} is invalid`);
}

function validateDetails(details, code = "TAMPERED_JOURNAL") {
  assertObject(details, code, "Setup transition details");
  const keys = Object.keys(details);
  if (keys.length > 32) fail(code, "Setup transition details contain too many fields");
  for (const key of keys) {
    if (!SAFE_DETAIL_KEY.test(key) || SENSITIVE_DETAIL_KEY.test(key)) fail(code, "Setup transition details contain an unsafe field");
    const value = details[key];
    if (!(value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value)))) {
      fail(code, "Setup transition details must contain scalar values only");
    }
    if (typeof value === "string" && value.length > 512) fail(code, "Setup transition detail is too long");
  }
}

function validateHistory(history, code) {
  if (!Array.isArray(history) || history.length === 0 || history.length > SETUP_STATES.length) fail(code, "Setup journal history is invalid");
  for (let index = 0; index < history.length; index += 1) {
    const entry = history[index];
    assertObject(entry, code, "Setup journal history entry");
    assertExactKeys(entry, HISTORY_KEYS, code, "Setup journal history entry");
    if (entry.revision !== index || entry.state !== SETUP_STATES[index]) fail("ROLLBACK_DETECTED", "Setup journal history is not an exact forward state sequence");
    assertIso(entry.completed_at, code, "Setup journal completion time");
    validateDetails(entry.details, code);
  }
}

function validateJournal(value, expectedCode = "TAMPERED_JOURNAL") {
  assertObject(value, expectedCode, "Setup journal");
  assertExactKeys(value, JOURNAL_KEYS, expectedCode, "Setup journal");
  if (value.kind !== SETUP_JOURNAL_KIND || value.version !== SETUP_JOURNAL_VERSION) fail(expectedCode, "Setup journal kind or version is unsupported");
  assertUuid(value.journal_id, expectedCode, "Setup journal ID");
  if (!Number.isInteger(value.revision) || value.revision < 0 || value.revision >= SETUP_STATES.length) fail(expectedCode, "Setup journal revision is invalid");
  if (!STATE_INDEX.has(value.state)) fail("UNKNOWN_STATE", "Setup journal contains an unknown state");
  assertIso(value.updated_at, expectedCode, "Setup journal update time");
  assertObject(value.integrity, expectedCode, "Setup journal integrity");
  assertExactKeys(value.integrity, INTEGRITY_KEYS, expectedCode, "Setup journal integrity");
  if (value.integrity.algorithm !== "sha256") fail(expectedCode, "Setup journal integrity algorithm is unsupported");
  if (value.integrity.previous_hash !== null) assertHash(value.integrity.previous_hash, expectedCode, "Setup journal previous hash");
  assertHash(value.integrity.hash, expectedCode, "Setup journal hash");
  if (value.integrity.hash !== hashUnsignedJournal(value)) fail("TAMPERED_JOURNAL", "Setup journal integrity hash does not match its contents");
  validateHistory(value.history, expectedCode);
  if (value.history.length !== value.revision + 1 || value.history.at(-1).state !== value.state || value.history.at(-1).completed_at !== value.updated_at) fail("ROLLBACK_DETECTED", "Setup journal tip does not match its history");
  return value;
}

function validateAnchor(value) {
  assertObject(value, "TAMPERED_ANCHOR", "Setup journal anchor");
  assertExactKeys(value, ANCHOR_KEYS, "TAMPERED_ANCHOR", "Setup journal anchor");
  if (value.kind !== SETUP_JOURNAL_ANCHOR_KIND || value.version !== SETUP_JOURNAL_VERSION) fail("TAMPERED_ANCHOR", "Setup journal anchor kind or version is unsupported");
  assertUuid(value.journal_id, "TAMPERED_ANCHOR", "Setup journal anchor ID");
  if (!Number.isInteger(value.revision) || value.revision < 0 || value.revision >= SETUP_STATES.length) fail("TAMPERED_ANCHOR", "Setup journal anchor revision is invalid");
  assertHash(value.tip_hash, "TAMPERED_ANCHOR", "Setup journal anchor tip hash");
  if (value.previous_tip !== null) validateJournal(value.previous_tip, "TAMPERED_ANCHOR");
  validateJournal(value.tip, "TAMPERED_ANCHOR");
  if (value.tip.journal_id !== value.journal_id || value.tip.revision !== value.revision || value.tip.integrity.hash !== value.tip_hash) fail("TAMPERED_ANCHOR", "Setup journal anchor tip metadata does not match");
  if (value.previous_tip && (value.previous_tip.revision + 1 !== value.tip.revision || value.previous_tip.journal_id !== value.journal_id || value.tip.integrity.previous_hash !== value.previous_tip.integrity.hash)) fail("TAMPERED_ANCHOR", "Setup journal anchor transition is not contiguous");
  if (!value.previous_tip && value.tip.revision !== 0) fail("TAMPERED_ANCHOR", "Setup journal anchor is missing its previous tip");
  return value;
}

function makeJournal({ journalId, revision, state, updatedAt, history, previousHash }) {
  const journal = {
    kind: SETUP_JOURNAL_KIND,
    version: SETUP_JOURNAL_VERSION,
    journal_id: journalId,
    revision,
    state,
    updated_at: updatedAt,
    history,
    integrity: { algorithm: "sha256", previous_hash: previousHash, hash: "0".repeat(64) }
  };
  journal.integrity.hash = hashUnsignedJournal(journal);
  return journal;
}

function makeAnchor(tip, previousTip) {
  return {
    kind: SETUP_JOURNAL_ANCHOR_KIND,
    version: SETUP_JOURNAL_VERSION,
    journal_id: tip.journal_id,
    revision: tip.revision,
    tip_hash: tip.integrity.hash,
    previous_tip: previousTip,
    tip
  };
}

function nowIso(clock) {
  const value = typeof clock === "function" ? clock() : new Date().toISOString();
  assertIso(value, "INVALID_TIME", "Setup journal clock value");
  return value;
}

function resolvePaths(options = {}) {
  const suppliedJournalPath = options.journalPath ?? options.filePath;
  const suppliedDirectory = options.directory ?? options.dir;
  const directory = path.resolve(suppliedDirectory ?? (suppliedJournalPath ? path.dirname(suppliedJournalPath) : defaultConfigDir));
  const journalPath = path.resolve(suppliedJournalPath ?? path.join(directory, SETUP_JOURNAL_FILENAME));
  const anchorPath = path.resolve(options.anchorPath ?? path.join(directory, SETUP_JOURNAL_ANCHOR_FILENAME));
  if (!path.isAbsolute(directory) || !path.isAbsolute(journalPath) || !path.isAbsolute(anchorPath)) fail("INVALID_PATH", "Setup journal paths must be absolute");
  if (journalPath === anchorPath) fail("INVALID_PATH", "Setup journal and anchor paths must differ");
  if (path.dirname(journalPath) !== directory || path.dirname(anchorPath) !== directory) fail("INVALID_PATH", "Setup journal files must be inside the configured directory");
  return { directory, journalPath, anchorPath, lockPath: `${journalPath}.lock` };
}

function assertSecureDirectory(directory) {
  let stat;
  try { stat = fs.lstatSync(directory); }
  catch (error) {
    if (error.code === "ENOENT") fail("NOT_INITIALIZED", `Setup journal directory does not exist: ${directory}`);
    fail("UNSAFE_STORAGE", `Cannot inspect setup journal directory: ${directory}`);
  }
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("UNSAFE_STORAGE", "Setup journal directory must be a real directory");
  if (uid !== undefined && stat.uid !== uid) fail("UNSAFE_STORAGE", "Setup journal directory is not owned by the current user");
  if ((stat.mode & 0o077) !== 0) fail("UNSAFE_STORAGE", "Setup journal directory is too permissive");
}

function assertSecureFile(file, code) {
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (error) {
    if (error.code === "ENOENT") return false;
    fail("UNSAFE_STORAGE", `Cannot inspect setup journal storage: ${file}`);
  }
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) fail(code, `Setup journal storage is not a regular file: ${file}`);
  if (uid !== undefined && stat.uid !== uid) fail(code, `Setup journal storage is not owned by the current user: ${file}`);
  if ((stat.mode & 0o077) !== 0) fail(code, `Setup journal storage is too permissive: ${file}`);
  if (stat.nlink !== 1) fail(code, `Setup journal storage must not be hard-linked: ${file}`);
  if (stat.size > 256 * 1024) fail(code, `Setup journal storage is too large: ${file}`);
  return true;
}

function readJsonFile(file, code) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { fail(code, `Setup journal storage contains invalid JSON: ${file}`); }
}

function writeJson(file, value) {
  atomicWrite(file, `${JSON.stringify(value, null, 2)}\n`, 0o600);
  assertSecureFile(file, "UNSAFE_STORAGE");
}

function pidIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === "EPERM"; }
}

function acquireLock(paths) {
  assertSecureDirectory(paths.directory);
  let descriptor;
  try {
    descriptor = fs.openSync(paths.lockPath, "wx", 0o600);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    assertSecureFile(paths.lockPath, "JOURNAL_BUSY");
    let lock;
    try { lock = readJsonFile(paths.lockPath, "JOURNAL_BUSY"); } catch (readError) { throw readError; }
    if (lock?.pid !== process.pid && !pidIsAlive(lock?.pid)) {
      fs.unlinkSync(paths.lockPath);
      return acquireLock(paths);
    }
    fail("JOURNAL_BUSY", "Another AgentPass setup operation is using the setup journal");
  }
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() })}\n`);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  return () => {
    try { fs.unlinkSync(paths.lockPath); } catch (error) { if (error.code !== "ENOENT") throw error; }
  };
}

function runLocked(paths, operation) {
  const release = acquireLock(paths);
  try { return operation(); } finally { release(); }
}

function loadPair(paths, { allowMissing = false } = {}) {
  assertSecureDirectory(paths.directory);
  const journalExists = assertSecureFile(paths.journalPath, "TAMPERED_JOURNAL");
  const anchorExists = assertSecureFile(paths.anchorPath, "TAMPERED_ANCHOR");
  if (!journalExists && !anchorExists) {
    if (allowMissing) return null;
    fail("NOT_INITIALIZED", "AgentPass setup has not been initialized");
  }
  if (!anchorExists) fail("TAMPERED_ANCHOR", "Setup journal anchor is missing");
  const anchor = validateAnchor(readJsonFile(paths.anchorPath, "TAMPERED_ANCHOR"));
  if (!journalExists) {
    // The anchor is written first. If a process crashed before the journal rename,
    // its previous tip proves the exact candidate that may be safely recovered.
    if (anchor.previous_tip && anchor.previous_tip.revision + 1 !== anchor.tip.revision) fail("ROLLBACK_DETECTED", "Setup journal cannot recover an unproven tip");
    writeJson(paths.journalPath, anchor.tip);
    return anchor.tip;
  }
  const journal = validateJournal(readJsonFile(paths.journalPath, "TAMPERED_JOURNAL"));
  if (journal.journal_id !== anchor.journal_id) fail("ROLLBACK_DETECTED", "Setup journal identity does not match its anchor");
  if (sameJson(journal, anchor.tip)) return journal;
  if (sameJson(journal, anchor.previous_tip)) {
    // Crash after the anchor rename but before the journal rename.
    writeJson(paths.journalPath, anchor.tip);
    return anchor.tip;
  }
  if (journal.revision === anchor.tip.revision + 1 && journal.integrity.previous_hash === anchor.tip_hash) {
    // This is a forward journal from a completed journal rename. Re-anchor it.
    writeJson(paths.anchorPath, makeAnchor(journal, anchor.tip));
    return journal;
  }
  if (journal.revision < anchor.tip.revision || journal.revision > anchor.tip.revision + 1) fail("ROLLBACK_DETECTED", "Setup journal revision is not contiguous with its durable anchor");
  fail("TAMPERED_JOURNAL", "Setup journal and anchor do not describe one contiguous state");
}

function makeInitialJournal(journalId, at) {
  const history = [{ revision: 0, state: "not_started", completed_at: at, details: {} }];
  return makeJournal({ journalId, revision: 0, state: "not_started", updatedAt: at, history, previousHash: null });
}

function statusFromJournal(journal, changed = undefined, transition = undefined) {
  const status = {
    version: journal.version,
    journal_id: journal.journal_id,
    revision: journal.revision,
    state: journal.state,
    updated_at: journal.updated_at,
    setup_complete: journal.state === "complete",
    next_actions: clone(NEXT_ACTIONS[journal.state]),
    history_length: journal.history.length
  };
  if (changed !== undefined) status.changed = changed;
  if (transition !== undefined) status.transition = transition;
  return status;
}

export function nextActionsForState(state) {
  if (!STATE_INDEX.has(state)) fail("UNKNOWN_STATE", `Unknown setup state: ${String(state)}`);
  return clone(NEXT_ACTIONS[state]);
}

export function setupJournalPaths(options = {}) {
  return resolvePaths(options);
}

export class SetupJournal {
  constructor(options = {}) {
    this.paths = resolvePaths(options);
    this.clock = options.clock ?? options.now ?? (() => new Date().toISOString());
  }

  initialize() {
    const paths = this.paths;
    try { secureMkdir(paths.directory); }
    catch (error) { fail("UNSAFE_STORAGE", error.message); }
    assertSecureDirectory(paths.directory);
    return runLocked(paths, () => {
      const existing = loadPair(paths, { allowMissing: true });
      if (existing) return statusFromJournal(existing, false);
      const at = nowIso(this.clock);
      const journal = makeInitialJournal(crypto.randomUUID(), at);
      const anchor = makeAnchor(journal, null);
      // The anchor carries the complete candidate, so either side of a crash is recoverable.
      writeJson(paths.anchorPath, anchor);
      writeJson(paths.journalPath, journal);
      return statusFromJournal(journal, true);
    });
  }

  read() {
    return runLocked(this.paths, () => clone(loadPair(this.paths)));
  }

  status() {
    return statusFromJournal(this.read());
  }

  transition(targetState, { details = {}, at = undefined } = {}) {
    if (!STATE_INDEX.has(targetState)) fail("UNKNOWN_STATE", `Unknown setup state: ${String(targetState)}`);
    validateDetails(details, "INVALID_DETAILS");
    return runLocked(this.paths, () => {
      const current = loadPair(this.paths);
      const currentIndex = STATE_INDEX.get(current.state);
      const targetIndex = STATE_INDEX.get(targetState);
      if (targetIndex === currentIndex) return statusFromJournal(current, false);
      if (targetIndex < currentIndex) fail("ROLLBACK_REJECTED", `Setup journal cannot transition from ${current.state} back to ${targetState}`);
      if (targetIndex !== currentIndex + 1) fail("INVALID_TRANSITION", `Setup journal must transition from ${current.state} to ${SETUP_STATES[currentIndex + 1]}`);
      const completedAt = nowIso(at ? () => at : this.clock);
      if (Date.parse(completedAt) < Date.parse(current.updated_at)) fail("INVALID_TIME", "Setup journal transition time cannot move backwards");
      const history = [...current.history, { revision: current.revision + 1, state: targetState, completed_at: completedAt, details: clone(details) }];
      const next = makeJournal({ journalId: current.journal_id, revision: current.revision + 1, state: targetState, updatedAt: completedAt, history, previousHash: current.integrity.hash });
      validateJournal(next, "TAMPERED_JOURNAL");
      const anchor = makeAnchor(next, current);
      validateAnchor(anchor);
      // Persist the intent before the visible journal tip, both with fsync'd atomic writes.
      writeJson(this.paths.anchorPath, anchor);
      writeJson(this.paths.journalPath, next);
      return statusFromJournal(next, true, { from: current.state, to: targetState, revision: next.revision });
    });
  }

  continue(options = {}) {
    const current = this.status();
    const next = current.next_actions[0]?.target_state;
    if (!next) return { ...current, changed: false };
    return this.transition(next, options);
  }
}

export function createSetupJournal(options = {}) {
  const journal = new SetupJournal(options);
  journal.initialize();
  return journal;
}

export function loadSetupJournal(options = {}) {
  const journal = new SetupJournal(options);
  journal.read();
  return journal;
}

export function readSetupJournal(options = {}) {
  return loadSetupJournal(options).status();
}

export function transitionSetupJournal({ state, targetState = state, ...options } = {}) {
  return loadSetupJournal(options).transition(targetState, options);
}

export function continueSetupJournal(options = {}) {
  return loadSetupJournal(options).continue(options);
}

export function defaultSetupJournalDirectory() {
  return path.join(os.homedir(), ".agentpass");
}
