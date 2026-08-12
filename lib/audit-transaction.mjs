import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { audit as defaultAppendAudit, verifyAudit as defaultVerifyAudit } from "./audit.mjs";
import { defaultConfigDir } from "./config.mjs";

const VERSION = 1;
const EMPTY_HASH = "0".repeat(64);
const MAX_STATE_BYTES = 2 * 1024 * 1024;
const MAX_REQUESTS = 4096;
const MAX_SIGNATURE_BYTES = 1024 * 1024;
const MAX_ID_LENGTH = 128;
const MAX_REASON_LENGTH = 64;
const DIGEST = /^[0-9a-f]{64}$/;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_REASON = /^[a-z][a-z0-9._:-]{0,63}$/;

/**
 * A durable fence around an authorization decision and its external signer.
 *
 * The audit implementation is deliberately injected.  The default is the
 * repository's hash-linked audit primitive, but brokers can provide their
 * native append/sync implementation without changing this transaction.
 */
export class AuthorizationAuditTransaction {
  constructor(options = {}) {
    const directory = options.directory ?? options.dir ?? options.configDir ?? defaultConfigDir;
    this.directory = secureDirectory(directory);
    this.stateFile = path.join(this.directory, "audit-transaction.state.json");
    this.lockFile = path.join(this.directory, "audit-transaction.state.lock");
    this.appendAudit = options.appendAudit ?? options.appendEvent ?? options.append ?? ((event) => defaultAppendAudit(event, this.directory));
    this.verifyAudit = options.verifyAudit ?? options.verifyChain ?? options.verify ?? (() => defaultVerifyAudit(this.directory));
    this.lockStaleMs = options.lockStaleMs ?? 10_000;
    this.maxLockAttempts = options.maxLockAttempts ?? 200;
    this._queue = Promise.resolve();
    if (typeof this.appendAudit !== "function" || typeof this.verifyAudit !== "function") throw new TypeError("Audit dependencies must be functions");
    assertBoundedNumber(this.lockStaleMs, "lockStaleMs", 0, 86_400_000);
    assertBoundedNumber(this.maxLockAttempts, "maxLockAttempts", 1, 10_000);
  }

  /** Execute an allow, deny, or pre-signer error decision. */
  execute(input = {}) {
    return this._serial(() => this._execute(input));
  }

  /** Broker-friendly spelling for execute. */
  authorize(input = {}, signer) {
    if (typeof input === "object" && signer !== undefined) return this.execute({ ...input, signer });
    return this.execute(input);
  }

  /** Record a durable non-signing decision. */
  recordDecision(input = {}) {
    return this._serial(() => this._recordDecision(input));
  }

  /** Mark every request that cannot be proven complete as outcome_unknown. */
  recover() {
    return this._serial(() => this._recover());
  }

  recoverUnresolved() {
    return this.recover();
  }

  /** Read one redacted, restart-safe outcome without invoking a signer. */
  getOutcome(requestId, options = {}) {
    assertRequestId(requestId);
    const state = this._loadState();
    const entry = state.requests[requestId];
    if (entry && options.requestDigest !== undefined) {
      if (!DIGEST.test(options.requestDigest) || entry.intent.request_digest !== options.requestDigest) throw transactionError("request_id_reuse", requestId);
    }
    return entry ? publicOutcome(entry) : null;
  }

  _execute(input) {
    return withFileLock(this, () => this.__execute(input));
  }

  async __execute(input) {
    const { intent, decision = "allow", reason, signer } = splitInput(input);
    const normalized = normalizeIntent(intent);
    const initialState = this._loadState();
    const existing = initialState.requests[normalized.request_id];
    if (existing) {
      assertSameRequest(existing, normalized);
      if (existing.phase === "terminal") return publicOutcome(existing);
      if (existing.phase === "outcome_unknown_pending" || existing.phase === "outcome_unknown") return publicOutcome(existing);
      if (existing.phase === "result_pending" || existing.phase === "signer_completed") return this._retryResult(existing);
      return this._recoverOne(existing);
    }
    if (compactTerminalRequests(initialState)) this._saveState(initialState);

    if (!["allow", "deny", "error"].includes(decision)) throw transactionError("invalid_decision", normalized.request_id);
    const safeReason = normalizeReason(reason, decision === "deny" ? "denied" : decision === "error" ? "error" : "allowed");
    if (decision !== "allow") return this._recordNewDecision(normalized, decision, safeReason);
    if (typeof signer !== "function") throw transactionError("signer_required", normalized.request_id);

    await this._assertAuditHealthy();
    let intentRecord;
    try {
      intentRecord = await this.appendAudit(intentEvent(normalized));
    } catch (error) {
      throw transactionError("intent_not_durable", normalized.request_id, error);
    }

    const state = this._loadState();
    const entry = newEntry(normalized, "intent_durable");
    entry.intent_hash = auditHash(intentRecord);
    state.requests[normalized.request_id] = entry;
    this._saveState(state);

    entry.phase = "signer_started";
    this._saveState(state);
    let signerResult;
    try {
      signerResult = await signer({ request_id: normalized.request_id, payload_digest: normalized.payload_digest });
    } catch {
      entry.phase = "signer_completed";
      entry.signer = { status: "ambiguous" };
      entry.result = { decision: "outcome_unknown", reason: "signer_outcome_unknown" };
      this._saveState(state);
      return this._finishOrWithhold(entry);
    }

    const normalizedSigner = normalizeSignerResult(signerResult);
    entry.phase = "signer_completed";
    entry.signer = normalizedSigner.audit;
    entry.result = normalizedSigner.result;
    if (normalizedSigner.signature) entry.signature_base64 = normalizedSigner.signature.toString("base64");
    this._saveState(state);
    return this._finishOrWithhold(entry);
  }

  _recordDecision(input) {
    return withFileLock(this, () => this.__recordDecision(input));
  }

  async __recordDecision(input) {
    const normalized = normalizeIntent(input.intent ?? input.request ?? input);
    const decision = input.decision;
    if (!["deny", "error"].includes(decision)) throw transactionError("non_signing_decision_required", normalized.request_id);
    const initialState = this._loadState();
    const existing = initialState.requests[normalized.request_id];
    if (existing) {
      assertSameRequest(existing, normalized);
      if (existing.phase === "terminal" || existing.phase === "outcome_unknown" || existing.phase === "outcome_unknown_pending") return publicOutcome(existing);
      if (existing.phase === "result_pending") return this._retryResult(existing);
      return this._recoverOne(existing);
    }
    if (compactTerminalRequests(initialState)) this._saveState(initialState);
    return this._recordNewDecision(normalized, decision, normalizeReason(input.reason, decision === "deny" ? "denied" : "error"));
  }

  async _recordNewDecision(intent, decision, reason) {
    const state = this._loadState();
    const entry = newEntry(intent, "result_pending");
    entry.result = { decision, reason };
    state.requests[intent.request_id] = entry;
    this._saveState(state);
    return this._finishOrWithhold(entry);
  }

  async _retryResult(entry) {
    if (!entry.result) return this._recoverOne(entry);
    return this._finishOrWithhold(entry);
  }

  async _finishOrWithhold(entry) {
    if (entry.phase === "outcome_unknown" || entry.phase === "outcome_unknown_pending") return publicOutcome(entry);
    entry.phase = "result_pending";
    const state = this._loadState();
    state.requests[entry.request_id] = entry;
    this._saveState(state);
    await this._assertAuditHealthy();
    try {
      const resultRecord = await this.appendAudit(resultEvent(entry));
      entry.result_hash = auditHash(resultRecord);
      entry.phase = "terminal";
      this._saveState(state);
      return publicOutcome(entry);
    } catch (error) {
      // The signer result is intentionally not returned until this succeeds.
      throw transactionError("result_not_durable", entry.request_id, error);
    }
  }

  _recover() {
    return withFileLock(this, () => this.__recover());
  }

  async __recover() {
    const state = this._loadState();
    const incidents = [];
    for (const entry of Object.values(state.requests)) {
      if (["terminal", "outcome_unknown", "outcome_unknown_pending"].includes(entry.phase)) {
        if (entry.phase === "outcome_unknown_pending") incidents.push(await this._recoverOne(entry));
        else incidents.push(publicOutcome(entry));
        continue;
      }
      incidents.push(await this._recoverOne(entry));
    }
    return incidents;
  }

  async _recoverOne(entry) {
    const state = this._loadState();
    entry.phase = "outcome_unknown_pending";
    entry.result = { decision: "outcome_unknown", reason: "restart_recovery" };
    state.requests[entry.request_id] = entry;
    this._saveState(state);
    try {
      const record = await this.appendAudit(resultEvent(entry));
      entry.result_hash = auditHash(record);
      entry.phase = "outcome_unknown";
      this._saveState(state);
      return publicOutcome(entry);
    } catch {
      return publicOutcome(entry);
    }
  }

  async _assertAuditHealthy() {
    const verified = await this.verifyAudit();
    if (verified && verified.valid === false) throw transactionError("audit_chain_invalid");
  }

  _loadState() {
    assertSafeFile(this.stateFile, true);
    if (!fs.existsSync(this.stateFile)) return emptyState();
    const stat = fs.statSync(this.stateFile);
    if (stat.size > MAX_STATE_BYTES) throw transactionError("transaction_state_too_large");
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(this.stateFile, "utf8")); }
    catch { throw transactionError("transaction_state_invalid"); }
    validateState(parsed);
    return parsed;
  }

  _saveState(state) {
    validateState(state);
    const encoded = JSON.stringify(state);
    if (Buffer.byteLength(encoded) > MAX_STATE_BYTES) throw transactionError("transaction_state_too_large");
    assertSafeFile(this.stateFile, true);
    const temporary = `${this.stateFile}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
    let fd;
    try {
      fd = fs.openSync(temporary, "wx", 0o600);
      fs.writeFileSync(fd, `${encoded}\n`);
      fs.fchmodSync(fd, 0o600);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(temporary, this.stateFile);
      fs.chmodSync(this.stateFile, 0o600);
      syncDirectory(this.directory);
    } finally {
      if (fd !== undefined) try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(temporary); } catch {}
    }
  }

  _serial(operation) {
    const result = this._queue.then(operation, operation);
    this._queue = result.catch(() => {});
    return result;
  }
}

export function createAuthorizationTransaction(options) {
  return new AuthorizationAuditTransaction(options);
}

export const createAuditTransaction = createAuthorizationTransaction;

export async function runAuthorizationTransaction(options, input) {
  return createAuthorizationTransaction(options).execute(input);
}

export async function recoverAuthorizationTransactions(options) {
  return createAuthorizationTransaction(options).recover();
}

function splitInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw transactionError("request_invalid");
  const { intent, decision = "allow", reason, signer, request, ...direct } = input;
  return { intent: intent ?? request ?? direct, decision, reason, signer };
}

function normalizeIntent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw transactionError("request_invalid");
  const allowed = new Set(["request_id", "request_digest", "trusted_context_digest", "policy_sequence", "capability_sequence", "payload_digest"]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw transactionError("request_contains_sensitive_or_unknown_field");
  const requestId = value.request_id;
  assertRequestId(requestId);
  for (const [key, label] of [["trusted_context_digest", "trusted_context_digest"], ["payload_digest", "payload_digest"]]) {
    if (!DIGEST.test(value[key] ?? "")) throw transactionError(`${label}_invalid`, requestId);
  }
  if (value.request_digest !== undefined && !DIGEST.test(value.request_digest)) throw transactionError("request_digest_invalid", requestId);
  for (const key of ["policy_sequence", "capability_sequence"]) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) throw transactionError(`${key}_invalid`, requestId);
  }
  return { request_id: requestId, ...(value.request_digest === undefined ? {} : { request_digest: value.request_digest }), trusted_context_digest: value.trusted_context_digest, policy_sequence: value.policy_sequence, capability_sequence: value.capability_sequence, payload_digest: value.payload_digest };
}

function normalizeReason(value, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || value.length > MAX_REASON_LENGTH || !SAFE_REASON.test(value)) throw transactionError("reason_invalid");
  return value;
}

function intentEvent(intent) {
  return { event: "authorized_intent", request_id: intent.request_id, ...(intent.request_digest ? { request_digest: intent.request_digest } : {}), trusted_context_digest: intent.trusted_context_digest, policy_sequence: intent.policy_sequence, capability_sequence: intent.capability_sequence, payload_digest: intent.payload_digest };
}

function resultEvent(entry) {
  const event = { event: entry.result.decision, request_id: entry.request_id, intent_hash: entry.intent_hash ?? EMPTY_HASH, reason: entry.result.reason };
  return event;
}

function normalizeSignerResult(value) {
  let signature;
  let failed = false;
  let statusCode;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || typeof value === "string") signature = Buffer.from(value);
  else if (value && typeof value === "object") {
    if (value.ok === true || value.status === 0) signature = value.signature ?? value.stdout;
    else if (value.ok === false || (Number.isInteger(value.status) && value.status !== 0)) { failed = true; statusCode = Number.isSafeInteger(value.status) ? value.status : undefined; }
  }
  if (signature !== undefined && !Buffer.isBuffer(signature)) signature = Buffer.from(signature);
  if (signature && (signature.length === 0 || signature.length > MAX_SIGNATURE_BYTES)) throw transactionError("signer_output_invalid");
  if (signature) return { signature, audit: { status: "succeeded", bytes: signature.length }, result: { decision: "allow", reason: "allowed" } };
  if (failed) return { audit: { status: "failed", ...(statusCode === undefined ? {} : { status_code: statusCode }) }, result: { decision: "error", reason: "signer_failed" } };
  throw transactionError("signer_result_invalid");
}

function newEntry(intent, phase) {
  return { request_id: intent.request_id, fingerprint: fingerprint(intent), intent, phase, intent_hash: null, signer: null, signature_base64: null, result: null, result_hash: null };
}

function publicOutcome(entry) {
  const outcome = { request_id: entry.request_id, outcome: entry.result?.decision ?? "outcome_unknown", reason: entry.result?.reason ?? "outcome_unknown", replayed: entry.phase === "terminal" };
  if (outcome.outcome === "allow" && entry.phase === "terminal" && entry.signature_base64) outcome.signature = Buffer.from(entry.signature_base64, "base64");
  return outcome;
}

function assertSameRequest(entry, intent) {
  if (entry.fingerprint !== fingerprint(intent)) throw transactionError("request_id_reuse", intent.request_id);
}

function fingerprint(intent) {
  return crypto.createHash("sha256").update(canonicalJson(intent)).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function auditHash(value) {
  const hash = value?.hash ?? value?.event_hash ?? value?.audit_hash;
  return typeof hash === "string" && DIGEST.test(hash) ? hash : null;
}

function emptyState() { return { version: VERSION, requests: {} }; }

function compactTerminalRequests(state) {
  const ids = Object.keys(state.requests);
  if (ids.length < 2048) return false;
  let changed = false;
  let remaining = ids.length;
  for (const id of ids) {
    if (remaining <= 1024) break;
    if (["terminal", "outcome_unknown"].includes(state.requests[id]?.phase)) { delete state.requests[id]; changed = true; remaining -= 1; }
  }
  return changed;
}

function validateState(state) {
  if (!state || state.version !== VERSION || !state.requests || typeof state.requests !== "object" || Array.isArray(state.requests)) throw transactionError("transaction_state_invalid");
  const ids = Object.keys(state.requests);
  if (ids.length > MAX_REQUESTS) throw transactionError("transaction_state_too_large");
  for (const id of ids) {
    const entry = state.requests[id];
    if (id !== entry?.request_id || !REQUEST_ID.test(id) || !entry || typeof entry !== "object" || !DIGEST.test(entry.fingerprint ?? "")) throw transactionError("transaction_state_invalid");
    if (!["intent_durable", "signer_started", "signer_completed", "result_pending", "outcome_unknown_pending", "outcome_unknown", "terminal"].includes(entry.phase)) throw transactionError("transaction_state_invalid");
    if (entry.signature_base64 !== null && (typeof entry.signature_base64 !== "string" || entry.signature_base64.length > Math.ceil(MAX_SIGNATURE_BYTES * 4 / 3) + 8)) throw transactionError("transaction_state_invalid");
    if (entry.signature_base64 !== null) {
      let signature;
      try { signature = Buffer.from(entry.signature_base64, "base64"); } catch { throw transactionError("transaction_state_invalid"); }
      if (signature.length > MAX_SIGNATURE_BYTES || signature.toString("base64") !== entry.signature_base64) throw transactionError("transaction_state_invalid");
    }
    try {
      const normalizedIntent = normalizeIntent(entry.intent);
      if (fingerprint(normalizedIntent) !== entry.fingerprint) throw new Error("fingerprint mismatch");
    } catch { throw transactionError("transaction_state_invalid"); }
    if (entry.intent_hash !== null && !DIGEST.test(entry.intent_hash)) throw transactionError("transaction_state_invalid");
    if (entry.result_hash !== null && !DIGEST.test(entry.result_hash)) throw transactionError("transaction_state_invalid");
    if (entry.result !== null && (!entry.result || !["allow", "deny", "error", "outcome_unknown"].includes(entry.result.decision) || !SAFE_REASON.test(entry.result.reason ?? ""))) throw transactionError("transaction_state_invalid");
  }
  return state;
}

function assertRequestId(value) {
  if (typeof value !== "string" || value.length > MAX_ID_LENGTH || !REQUEST_ID.test(value)) throw transactionError("request_id_invalid");
}

function transactionError(code, requestId, cause) {
  const error = new Error(`Authorization transaction failed: ${code}`);
  error.code = code;
  if (requestId) error.request_id = requestId;
  if (cause) error.cause = cause;
  error.outcome = code === "result_not_durable" ? "outcome_unknown" : undefined;
  return error;
}

function assertBoundedNumber(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${name} is out of bounds`);
}

function secureDirectory(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) throw new TypeError("Transaction directory must be absolute");
  const resolved = path.resolve(value);
  try { fs.mkdirSync(resolved, { recursive: true, mode: 0o700 }); }
  catch { throw new Error("Unsafe transaction directory"); }
  let stat;
  try { stat = fs.lstatSync(resolved); }
  catch { throw new Error("Unsafe transaction directory"); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Unsafe transaction directory");
  // Canonicalize trusted system ancestors such as macOS's /tmp symlink, while
  // still rejecting a symlink at the actual transaction-directory boundary.
  const canonical = fs.realpathSync(resolved);
  fs.chmodSync(canonical, 0o700);
  const canonicalStat = fs.lstatSync(canonical);
  if (!canonicalStat.isDirectory() || canonicalStat.isSymbolicLink()) throw new Error("Unsafe transaction directory");
  return canonical;
}

function assertSafeFile(file, missingAllowed) {
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (error) { if (missingAllowed && error.code === "ENOENT") return; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("Unsafe audit transaction state file");
  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) throw new Error("Unsafe audit transaction state owner");
  if ((stat.mode & 0o077) !== 0) throw new Error("Unsafe audit transaction state permissions");
}

async function acquireLock(file, staleMs, maxAttempts) {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const token = crypto.randomBytes(16).toString("hex");
      try {
        const fd = fs.openSync(file, "wx", 0o600);
        try {
          fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, created_at: Date.now(), token }));
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      return token;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      assertSafeFile(file, false);
      let lease;
      try {
        if (fs.statSync(file).size > 1024) throw new Error("lock too large");
        lease = JSON.parse(fs.readFileSync(file, "utf8"));
      } catch { throw new Error("Audit transaction lock is invalid; inspect it before removal"); }
      if (!Number.isInteger(lease.pid) || !Number.isSafeInteger(lease.created_at) || typeof lease.token !== "string" || !/^[0-9a-f]{32}$/.test(lease.token)) throw new Error("Audit transaction lock is invalid; inspect it before removal");
      const age = Date.now() - lease.created_at;
      if (age >= staleMs) {
        let dead = false;
        try { process.kill(lease.pid, 0); } catch (probe) { dead = probe.code === "ESRCH"; }
        if (dead) { fs.unlinkSync(file); continue; }
      }
      await delay(5);
    }
  }
  throw new Error("Audit transaction state is busy");
}

async function withFileLock(transaction, operation) {
  const token = await acquireLock(transaction.lockFile, transaction.lockStaleMs, transaction.maxLockAttempts);
  try { return await operation(); }
  finally {
    try {
      assertSafeFile(transaction.lockFile, false);
      const lease = JSON.parse(fs.readFileSync(transaction.lockFile, "utf8"));
      if (lease.token === token) fs.unlinkSync(transaction.lockFile);
    } catch {}
  }
}

function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

function syncDirectory(directory) {
  try { const fd = fs.openSync(directory, "r"); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch {}
}
