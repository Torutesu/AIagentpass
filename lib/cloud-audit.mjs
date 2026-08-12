import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";

import { canonicalDeviceRequest, sha256 } from "../apps/cloud-api/src/auth.mjs";
import { canonicalJson, normalizeAuditEvent } from "../packages/protocol/src/index.mjs";

const VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const DEFAULT_BATCH_SIZE = 64;
const DEFAULT_MAX_EVENT_BYTES = 16 * 1024;
const DEFAULT_MAX_BATCH_BYTES = 256 * 1024;
const DEFAULT_MAX_QUEUE_EVENTS = 1024;
const DEFAULT_MAX_QUEUE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_AUDIT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);
const FORBIDDEN_KEY = /(?:payload|environment|env|session|capabilit|private[_-]?key|secret|bearer|access[_-]?token|refresh[_-]?token|password)/i;
const REDACTED_KEYS = Object.freeze([
  "version", "event_id", "request_id", "agent_id", "operation", "decision", "reason",
  "policy_sequence", "capability_sequence", "repository", "branch", "remote", "payload_digest",
  "device_timestamp", "previous_hash", "event_hash"
]);

export class CloudAuditError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "CloudAuditError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export class QueueFullError extends CloudAuditError {
  constructor(message = "Cloud audit queue is full") { super("ERR_AUDIT_QUEUE_FULL", message); this.name = "QueueFullError"; }
}

export class AuditConflictError extends CloudAuditError {
  constructor(batchId, code = "audit_conflict") {
    super("ERR_AUDIT_CONFLICT", `Cloud rejected audit batch ${batchId}`, { batch_id: batchId, response_code: code });
    this.name = "AuditConflictError";
  }
}

/**
 * Keep only the protocol-v1 audit fields. Local audit records are deliberately
 * not sent as-is; aliases are accepted only for fields emitted by older local
 * audit writers.
 */
export function redactAuditEvent(input) {
  if (!plainObject(input)) throw invalid("audit_event", "must be an object");
  const output = {
    version: input.version,
    event_id: input.event_id,
    request_id: input.request_id,
    agent_id: input.agent_id,
    operation: input.operation,
    decision: input.decision,
    reason: input.reason,
    policy_sequence: input.policy_sequence ?? input.control_sequence,
    capability_sequence: input.capability_sequence,
    repository: input.repository,
    branch: input.branch,
    remote: input.remote,
    payload_digest: input.payload_digest ?? input.payload_sha256,
    device_timestamp: input.device_timestamp ?? input.timestamp,
    previous_hash: input.previous_hash,
    event_hash: input.event_hash ?? input.hash
  };
  // This check is intentionally against keys, not values: prohibited fields
  // are dropped even when a caller supplies them under a nested object.
  for (const key of Object.keys(input)) {
    if (FORBIDDEN_KEY.test(key) && !REDACTED_KEYS.includes(key)) continue;
  }
  try {
    const normalized = normalizeForHash(output);
    return { ...normalized, event_hash: computeCloudAuditEventHash(normalized) };
  } catch (error) {
    throw invalid("audit_event", error.message);
  }
}

export function computeCloudAuditEventHash(input) {
  const { event_hash: _ignored, ...preimage } = input;
  return crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex");
}

export function validateAuditEvent(input) {
  let event;
  try { event = normalizeAuditEvent(input); }
  catch (error) { throw invalid("audit_event", error.message); }
  const encoded = Buffer.from(canonicalJson(event), "utf8");
  if (encoded.length > DEFAULT_MAX_EVENT_BYTES) throw invalid("audit_event", "event is too large");
  if (event.event_hash !== computeCloudAuditEventHash(event)) throw invalid("audit_event", "event_hash does not match the canonical redacted event");
  return event;
}

function normalizeForHash(input) {
  // normalizeAuditEvent requires the transport hash field. A syntactically
  // valid placeholder lets us normalize first, then compute the actual chain.
  return normalizeAuditEvent({ ...input, event_hash: input.event_hash ?? ZERO_HASH });
}

function rechainAuditEvents(events, previousHash) {
  let previous = previousHash;
  return events.map((event) => {
    const normalized = normalizeForHash({ ...event, previous_hash: previous });
    const chained = { ...normalized, event_hash: computeCloudAuditEventHash(normalized) };
    previous = chained.event_hash;
    return chained;
  });
}

export function validateAuditBatch(events, options = {}) {
  const batchSize = boundedInteger(options.batchSize ?? DEFAULT_BATCH_SIZE, 1, 500, "batchSize");
  const maxEventBytes = boundedInteger(options.maxEventBytes ?? DEFAULT_MAX_EVENT_BYTES, 256, 1024 * 1024, "maxEventBytes");
  const maxBatchBytes = boundedInteger(options.maxBatchBytes ?? DEFAULT_MAX_BATCH_BYTES, 512, 4 * 1024 * 1024, "maxBatchBytes");
  if (!Array.isArray(events) || events.length < 1 || events.length > batchSize) throw invalid("events", `must contain 1-${batchSize} items`);
  const normalized = events.map((event, index) => {
    let value;
    try { value = redactAuditEvent(event); }
    catch (error) { throw invalid(`events[${index}]`, error.message); }
    const bytes = Buffer.byteLength(canonicalJson(value), "utf8");
    if (bytes > maxEventBytes) throw invalid(`events[${index}]`, "event is too large");
    return value;
  });
  const ids = new Set();
  let previous = undefined;
  for (const event of normalized) {
    if (ids.has(event.event_id)) throw invalid("events", "event_id must be unique within a batch");
    ids.add(event.event_id);
    if (previous !== undefined && event.previous_hash !== previous) throw invalid("events", "events must be hash-chain ordered");
    previous = event.event_hash;
  }
  const bytes = Buffer.byteLength(canonicalJson({ events: normalized }), "utf8");
  if (bytes > maxBatchBytes) throw invalid("events", "batch is too large");
  return { events: normalized, bytes };
}

/** Read one complete, bounded JSONL batch without advancing the cursor. */
export async function readAuditBatch(file, cursor = {}, options = {}) {
  const batchSize = boundedInteger(options.batchSize ?? DEFAULT_BATCH_SIZE, 1, 500, "batchSize");
  const maxAuditBytes = boundedInteger(options.maxAuditBytes ?? DEFAULT_MAX_AUDIT_BYTES, 1, 256 * 1024 * 1024, "maxAuditBytes");
  const maxLineBytes = boundedInteger(options.maxLineBytes ?? DEFAULT_MAX_EVENT_BYTES * 2, 256, 2 * 1024 * 1024, "maxLineBytes");
  const offset = cursor.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0) throw invalid("cursor.offset", "must be a non-negative safe integer");
  const handle = await openSafeRead(file, "audit log");
  try {
    const stat = await handle.stat();
    if (stat.size > maxAuditBytes) throw invalid("audit log", "file is too large");
    if (offset > stat.size) throw new CloudAuditError("ERR_AUDIT_CURSOR", "audit cursor is beyond the end of the audit log");
    if (offset === stat.size) return { events: [], nextCursor: { ...cursor, offset, line: cursor.line ?? 0 } };
    const content = await handle.readFile();
    const bytes = content.subarray(offset);
    const complete = bytes.lastIndexOf(0x0a);
    if (complete < 0) {
      if (bytes.length > maxLineBytes) throw invalid("audit log", "unterminated line is too large");
      return { events: [], nextCursor: { ...cursor, offset, line: cursor.line ?? 0 } };
    }
    const completeBytes = bytes.subarray(0, complete + 1);
    const lines = completeBytes.toString("utf8").split("\n").filter((line) => line.length > 0);
    const selected = [];
    let consumed = 0;
    let line = cursor.line ?? 0;
    for (const text of lines) {
      const lineBytes = Buffer.byteLength(text, "utf8");
      if (lineBytes > maxLineBytes) throw invalid(`audit line ${line + 1}`, "line is too large");
      let parsed;
      try { parsed = parseJsonSafe(text); } catch { throw invalid(`audit line ${line + 1}`, "line is not valid UTF-8 JSON or contains duplicate keys"); }
      const redacted = redactAuditEvent(parsed);
      const eventBytes = Buffer.byteLength(canonicalJson(redacted), "utf8");
      if (selected.length > 0 && (selected.length >= batchSize || Buffer.byteLength(canonicalJson({ events: [...selected, redacted] }), "utf8") > (options.maxBatchBytes ?? DEFAULT_MAX_BATCH_BYTES))) break;
      if (selected.length === 0 && eventBytes > (options.maxBatchBytes ?? DEFAULT_MAX_BATCH_BYTES)) throw invalid(`audit line ${line + 1}`, "event exceeds batch limit");
      selected.push(redacted);
      consumed += Buffer.byteLength(text, "utf8") + 1;
      line += 1;
    }
    if (selected.length === 0) return { events: [], nextCursor: { ...cursor, offset, line: cursor.line ?? 0 } };
    const validated = validateAuditBatch(rechainAuditEvents(selected, cursor.head_hash ?? ZERO_HASH), options);
    const nextCursor = { version: VERSION, offset: offset + consumed, line, head_hash: validated.events.at(-1).event_hash };
    return { events: validated.events, bytes: validated.bytes, nextCursor };
  } finally { await handle.close(); }
}

/**
 * Create a local-first uploader. `queuePath` and `cursorPath` are separate so
 * a crash can only cause a stable batch to be retried, never silently skipped.
 */
export function createCloudAuditClient(options = {}) {
  const config = normalizeOptions(options);
  let operation = Promise.resolve();
  const serialize = (fn) => { const result = operation.then(fn, fn); operation = result.catch(() => undefined); return result; };

  const client = {
    enqueue: (events) => serialize(() => enqueueEvents(events)),
    enqueueFromAudit: () => serialize(() => enqueueFromAudit()),
    upload: () => serialize(() => uploadOne()),
    flush: (input = {}) => serialize(() => flush(input)),
    pending: () => serialize(() => loadQueue()),
    cursor: () => serialize(() => loadCursor()),
    redact: redactAuditEvent,
    validate: (events, input = {}) => validateAuditBatch(events, { ...config, ...input })
  };
  return client;

  async function loadQueue() { return loadQueueFrom(config.queuePath, config); }
  async function saveQueue(queue) { return saveJson(config.queuePath, queue); }
  async function loadCursor() {
    const cursor = await loadJson(config.cursorPath, { version: VERSION, offset: 0, line: 0, head_hash: ZERO_HASH });
    if (!plainObject(cursor) || cursor.version !== VERSION || !Number.isSafeInteger(cursor.offset) || cursor.offset < 0 || !Number.isSafeInteger(cursor.line ?? 0) || (cursor.line ?? 0) < 0 || !HASH.test(cursor.head_hash ?? ZERO_HASH)) {
      throw new CloudAuditError("ERR_AUDIT_CURSOR", "audit cursor is invalid");
    }
    return { version: VERSION, offset: cursor.offset, line: cursor.line ?? 0, head_hash: cursor.head_hash ?? ZERO_HASH };
  }
  async function saveCursor(cursor) {
    if (!plainObject(cursor) || !Number.isSafeInteger(cursor.offset) || cursor.offset < 0 || !Number.isSafeInteger(cursor.line) || cursor.line < 0 || !HASH.test(cursor.head_hash ?? ZERO_HASH)) throw new CloudAuditError("ERR_AUDIT_CURSOR", "audit cursor is invalid");
    return saveJson(config.cursorPath, { version: VERSION, offset: cursor.offset, line: cursor.line, head_hash: cursor.head_hash ?? ZERO_HASH });
  }

  async function enqueueEvents(events) {
    const validated = validateAuditBatch(events, config);
    const queue = await loadQueue();
    const batch = makeBatch(validated.events, config);
    if (queue.batches.some((item) => item.batch_id === batch.batch_id)) return { queued: false, duplicate: true, batch_id: batch.batch_id, queue: queueInfo(queue) };
    assertQueueCapacity(queue, batch, config);
    queue.batches.push(batch);
    await saveQueue(queue);
    return { queued: true, batch_id: batch.batch_id, queue: queueInfo(queue) };
  }

  async function enqueueFromAudit() {
    if (!config.auditPath) throw new CloudAuditError("ERR_AUDIT_PATH_REQUIRED", "auditPath is required to read local audit batches");
    const queue = await loadQueue();
    const cursor = await loadCursor();
    const batchRead = await readAuditBatch(config.auditPath, cursor, config);
    if (batchRead.events.length === 0) return { queued: false, eof: true, queue: queueInfo(queue), cursor };
    const validated = validateAuditBatch(batchRead.events, config);
    const batch = makeBatch(validated.events, config);
    if (!queue.batches.some((item) => item.batch_id === batch.batch_id)) {
      assertQueueCapacity(queue, batch, config);
      queue.batches.push(batch);
      await saveQueue(queue);
    }
    // The queue is durable before this cursor is advanced. A crash between
    // these writes re-reads the same content and is harmlessly deduplicated.
    await saveCursor(batchRead.nextCursor);
    return { queued: true, batch_id: batch.batch_id, queue: queueInfo(queue), cursor: batchRead.nextCursor };
  }

  async function uploadOne() {
    const queue = await loadQueue();
    const batch = queue.batches[0];
    if (!batch) return { status: "idle", queue: queueInfo(queue) };
    let response;
    try { response = await sendBatch(batch); }
    catch (error) {
      return { status: "retry", batch_id: batch.batch_id, error: publicError(error), queue: queueInfo(queue) };
    }
    const outcome = classifyResponse(response, batch.batch_id);
    if (outcome.status === "accepted" || outcome.status === "gap") {
      queue.batches.shift();
      await saveQueue(queue);
    }
    return { ...outcome, batch_id: batch.batch_id, queue: queueInfo(queue) };
  }

  async function flush(input) {
    const maxBatches = boundedInteger(input.maxBatches ?? Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, "maxBatches");
    const results = [];
    for (let count = 0; count < maxBatches; count += 1) {
      const queue = await loadQueue();
      if (queue.batches.length === 0 && config.auditPath) {
        const added = await enqueueFromAudit();
        if (!added.queued) break;
      }
      const result = await uploadOne();
      results.push(result);
      if (["retry", "conflict", "gap-blocked"].includes(result.status) || result.status === "idle") break;
    }
    const queue = await loadQueue();
    return { results, queue: queueInfo(queue) };
  }

  async function sendBatch(batch) {
    const body = Buffer.from(canonicalJson({ batch_id: batch.batch_id, events: batch.events }), "utf8");
    const url = new URL(config.endpoint);
    const target = `${url.pathname}${url.search}`;
    const timestamp = clockMilliseconds(config.clock());
    const nonce = await Promise.resolve(config.nonce());
    if (typeof nonce !== "string" || !NONCE.test(nonce)) throw new CloudAuditError("ERR_AUDIT_NONCE", "nonce must be 32-128 safe characters");
    const bodyDigest = sha256(body);
    const canonical = canonicalDeviceRequest({ method: "POST", path: target, body_digest: bodyDigest, timestamp, nonce });
    const signature = await createSignature(config, { canonical, method: "POST", path: target, bodyDigest, timestamp, nonce });
    const headers = {
      "content-type": "application/json",
      "AgentPass-Device": config.deviceId,
      "AgentPass-Timestamp": String(timestamp),
      "AgentPass-Nonce": nonce,
      "AgentPass-Content-SHA256": bodyDigest,
      "AgentPass-Signature": signature
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeoutMs);
    let timeoutTimer;
    try {
      const result = await Promise.race([
        config.fetchImpl(config.endpoint, { method: "POST", headers, body, redirect: "error", signal: controller.signal }),
        new Promise((_, reject) => { timeoutTimer = setTimeout(() => reject(new CloudAuditError("ERR_AUDIT_TIMEOUT", "cloud audit request timed out")), config.timeoutMs); })
      ]);
      return await readResponse(result, config.maxResponseBytes);
    } finally { clearTimeout(timer); if (timeoutTimer) clearTimeout(timeoutTimer); }
  }
}

export const createAuditUploader = createCloudAuditClient;
export const createCloudAuditUploader = createCloudAuditClient;
export const redactCloudAuditEvent = redactAuditEvent;
export const validateCloudAuditBatch = validateAuditBatch;

export async function uploadAuditBatches(options = {}) {
  return createCloudAuditClient(options).flush(options);
}

function normalizeOptions(input) {
  if (!plainObject(input)) throw new TypeError("cloud audit options must be an object");
  const baseUrl = input.baseUrl ?? input.url;
  if (typeof baseUrl !== "string") throw new TypeError("baseUrl is required");
  const parsed = new URL(baseUrl);
  const loopbackTestMode = input.loopbackTestMode === true || input.allowLoopbackHttp === true;
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:" && !(loopbackTestMode && parsed.protocol === "http:" && LOOPBACK.has(hostname))) {
    throw new CloudAuditError("ERR_AUDIT_URL", "cloud audit endpoint must use HTTPS (HTTP is limited to explicit loopback test mode)");
  }
  if (parsed.username || parsed.password || parsed.hash) throw new CloudAuditError("ERR_AUDIT_URL", "cloud audit URL cannot contain credentials or fragments");
  const organizationId = input.organizationId ?? input.organization_id;
  const deviceId = input.deviceId ?? input.device_id;
  if (!safeId(organizationId) || !safeId(deviceId)) throw new TypeError("organizationId and deviceId are required safe identifiers");
  const endpoint = new URL(`/v1/organizations/${encodeURIComponent(organizationId)}/audit/events`, parsed);
  const queuePath = input.queuePath ?? path.join(input.stateDir ?? path.dirname(input.auditPath ?? process.cwd()), "cloud-audit-queue.json");
  const cursorPath = input.cursorPath ?? path.join(input.stateDir ?? path.dirname(input.auditPath ?? process.cwd()), "cloud-audit.cursor.json");
  const clock = input.clock ?? input.now ?? (() => Date.now());
  const nonce = input.nonce ?? (() => crypto.randomBytes(24).toString("base64url"));
  const fetchImpl = input.fetchImpl ?? input.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl is required");
  if (typeof clock !== "function" || typeof nonce !== "function") throw new TypeError("clock and nonce must be functions");
  if (!input.sign && !input.signing && !input.signer && !input.signRequest && !input.privateKey && !input.devicePrivateKey && !input.signingKey) throw new TypeError("a device signing function or private key is required");
  return Object.freeze({
    ...input,
    auditPath: input.auditPath ?? input.auditFile,
    endpoint: endpoint.toString(), organizationId, deviceId, queuePath, cursorPath, clock, nonce, fetchImpl,
    signing: input.sign ?? input.signing ?? input.signer ?? input.signRequest,
    privateKey: input.privateKey ?? input.devicePrivateKey ?? input.signingKey,
    batchSize: boundedInteger(input.batchSize ?? DEFAULT_BATCH_SIZE, 1, 500, "batchSize"),
    maxEventBytes: boundedInteger(input.maxEventBytes ?? DEFAULT_MAX_EVENT_BYTES, 256, 1024 * 1024, "maxEventBytes"),
    maxBatchBytes: boundedInteger(input.maxBatchBytes ?? DEFAULT_MAX_BATCH_BYTES, 512, 4 * 1024 * 1024, "maxBatchBytes"),
    maxQueueEvents: boundedInteger(input.maxQueueEvents ?? DEFAULT_MAX_QUEUE_EVENTS, 1, 1_000_000, "maxQueueEvents"),
    maxQueueBytes: boundedInteger(input.maxQueueBytes ?? DEFAULT_MAX_QUEUE_BYTES, 1024, 256 * 1024 * 1024, "maxQueueBytes"),
    maxAuditBytes: boundedInteger(input.maxAuditBytes ?? DEFAULT_MAX_AUDIT_BYTES, 1, 256 * 1024 * 1024, "maxAuditBytes"),
    maxResponseBytes: boundedInteger(input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES, 1024, 16 * 1024 * 1024, "maxResponseBytes"),
    timeoutMs: boundedInteger(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1, 120_000, "timeoutMs")
  });
}

async function createSignature(config, request) {
  let result;
  const configured = config.signing;
  const signer = typeof configured === "function" ? configured : configured?.sign;
  if (signer) result = await signer({ ...request });
  else result = crypto.sign(null, Buffer.from(request.canonical, "utf8"), config.privateKey);
  if (result && typeof result === "object" && !Buffer.isBuffer(result)) result = result.signature;
  if (Buffer.isBuffer(result)) result = result.toString("base64");
  if (typeof result !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(result)) throw new CloudAuditError("ERR_AUDIT_SIGNATURE", "signer returned an invalid signature");
  return result;
}

async function readResponse(response, maxBytes) {
  if (!response || !Number.isInteger(response.status)) throw new CloudAuditError("ERR_AUDIT_RESPONSE", "cloud response is invalid");
  let text = "";
  try {
    if (typeof response.text === "function") text = await response.text();
    else if (typeof response.json === "function") {
      const body = await response.json();
      if (Buffer.byteLength(JSON.stringify(body), "utf8") > maxBytes) throw new CloudAuditError("ERR_AUDIT_RESPONSE", "cloud response is too large");
      return { status: response.status, body };
    }
  } catch { throw new CloudAuditError("ERR_AUDIT_RESPONSE", "cloud response could not be read"); }
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new CloudAuditError("ERR_AUDIT_RESPONSE", "cloud response is too large");
  if (!text) return { status: response.status, body: {} };
  try { return { status: response.status, body: parseJsonSafe(text) }; }
  catch { throw new CloudAuditError("ERR_AUDIT_RESPONSE", "cloud response is not valid JSON"); }
}

function classifyResponse(response, batchId) {
  const body = plainObject(response.body) ? response.body : {};
  const error = plainObject(body.error) ? body.error : {};
  const code = typeof error.code === "string" ? error.code : undefined;
  const ingestion = plainObject(body.ingestion) ? body.ingestion : {};
  if (response.status >= 200 && response.status < 300) {
    const gaps = Array.isArray(ingestion.gaps) ? ingestion.gaps.map((gap) => redactResponseGap(gap)) : [];
    return { status: gaps.length ? "gap" : "accepted", accepted: arrayOfIds(ingestion.accepted), duplicates: arrayOfIds(ingestion.duplicates), gaps, response_status: response.status };
  }
  if (response.status === 409 && isConflictCode(code)) return { status: "conflict", error_code: code ?? "audit_conflict", response_status: response.status };
  if (response.status === 409 && isGapCode(code)) return { status: "gap-blocked", error_code: code ?? "audit_gap", expected_previous_hash: safeHash(error.expected_previous_hash), response_status: response.status };
  return { status: "retry", error_code: code ?? `http_${response.status}`, response_status: response.status };
}

function redactResponseGap(value) {
  if (!plainObject(value)) return { invalid: true };
  return {
    gap_id: typeof value.gap_id === "string" ? value.gap_id : undefined,
    event_id: typeof value.event_id === "string" ? value.event_id : undefined,
    expected_previous_hash: safeHash(value.expected_previous_hash),
    received_previous_hash: safeHash(value.received_previous_hash)
  };
}

function isConflictCode(code) { return typeof code === "string" && /(?:conflict|dedup)/i.test(code); }
function isGapCode(code) { return typeof code === "string" && /gap/i.test(code); }
function arrayOfIds(value) { return Array.isArray(value) ? value.filter((item) => typeof item === "string" && ID.test(item)).slice(0, 500) : []; }
function safeHash(value) { return typeof value === "string" && HASH.test(value) ? value : undefined; }

async function loadQueueFrom(file, config) {
  const value = await loadJson(file, { version: VERSION, batches: [] });
  if (!plainObject(value) || value.version !== VERSION || !Array.isArray(value.batches)) throw new CloudAuditError("ERR_AUDIT_QUEUE", "audit queue is invalid");
  const batches = value.batches.map((batch) => {
    if (!plainObject(batch) || !safeBatchId(batch.batch_id) || !Array.isArray(batch.events)) throw new CloudAuditError("ERR_AUDIT_QUEUE", "audit queue entry is invalid");
    const validated = validateAuditBatch(batch.events, config);
    const expected = makeBatch(validated.events, config);
    if (expected.batch_id !== batch.batch_id) throw new CloudAuditError("ERR_AUDIT_QUEUE", "audit queue batch identity is invalid");
    return { batch_id: batch.batch_id, events: validated.events, bytes: expected.bytes };
  });
  const queue = { version: VERSION, batches };
  const info = queueInfo(queue);
  if (info.events > config.maxQueueEvents || info.bytes > config.maxQueueBytes) throw new QueueFullError("Persisted cloud audit queue exceeds configured bounds");
  return queue;
}

function queueInfo(queue) {
  return { batches: queue.batches.length, events: queue.batches.reduce((sum, batch) => sum + batch.events.length, 0), bytes: queue.batches.reduce((sum, batch) => sum + batch.bytes, 0) };
}

function makeBatch(events, config) {
  const identity = { organization_id: config.organizationId, device_id: config.deviceId, events };
  return { batch_id: `audit-${sha256(canonicalJson(identity))}`, events, bytes: Buffer.byteLength(canonicalJson({ batch_id: `audit-${sha256(canonicalJson(identity))}`, events }), "utf8") };
}

function assertQueueCapacity(queue, batch, config) {
  const info = queueInfo(queue);
  if (info.events + batch.events.length > config.maxQueueEvents || info.bytes + batch.bytes > config.maxQueueBytes) throw new QueueFullError();
}

async function openSafeRead(file, label) {
  await assertSafePath(file, label, false);
  const flags = fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW ?? 0);
  let handle;
  try { handle = await fs.open(file, flags); } catch (error) { throw new CloudAuditError("ERR_AUDIT_READ", `unable to read ${label}`, { cause: error.code }); }
  const stat = await handle.stat();
  if (!stat.isFile() || (process.getuid && stat.uid !== process.getuid())) { await handle.close(); throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} must be a current-user regular file`); }
  return handle;
}

async function loadJson(file, fallback) {
  try {
    await assertSafePath(file, "audit state", true);
    const text = decodeUtf8(await fs.readFile(file));
    try { return parseJsonSafe(text); } catch { throw new CloudAuditError("ERR_AUDIT_STATE", "audit state is not valid UTF-8 JSON or contains duplicate keys"); }
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    if (error instanceof CloudAuditError) throw error;
    throw new CloudAuditError("ERR_AUDIT_STATE", "unable to read audit state", { cause: error.code });
  }
}

// These functions are kept outside the client closure so state validation and
// the atomic-write behavior are also directly testable.
async function saveJson(file, value) {
  await assertSafePath(file, "audit state", true);
  const directory = path.dirname(file);
  const temporary = `${file}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  const encoded = `${canonicalJson(value)}\n`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(encoded, "utf8");
    await handle.sync();
  } finally {
    if (handle) await handle.close();
  }
  await assertSafePath(temporary, "audit temporary state", false);
  await fs.rename(temporary, file);
  try { const parent = await fs.open(directory, "r"); await parent.sync(); await parent.close(); } catch {}
}

async function assertSafePath(file, label, allowMissing) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} path must be absolute`);
  const parts = path.resolve(file).split(path.sep);
  let current = path.isAbsolute(file) ? path.parse(file).root : "";
  for (const part of parts.slice(1, -1)) {
    current = path.join(current, part);
    try {
      // macOS exposes the conventional temporary directory through /var,
      // which is itself a system symlink. It is outside the caller-controlled
      // path; all descendants remain subject to the symlink check.
      if (current !== "/var" && (await fs.lstat(current)).isSymbolicLink()) throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} parent cannot be a symlink`);
    }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  try {
    const stat = await fs.lstat(file);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} must be a regular file`);
    if (process.getuid && stat.uid !== process.getuid()) throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} is not owned by the current user`);
    if ((stat.mode & 0o077) !== 0) throw new CloudAuditError("ERR_AUDIT_STORAGE", `${label} permissions are too broad`);
  } catch (error) {
    if (error.code === "ENOENT" && allowMissing) return;
    if (error.code === "ENOENT") throw error;
    throw error;
  }
}

function safeBatchId(value) { return typeof value === "string" && /^audit-[0-9a-f]{64}$/.test(value); }
function safeId(value) { return typeof value === "string" && ID.test(value); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function boundedInteger(value, min, max, label) { if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`${label} is out of bounds`); return value; }
function invalid(pathName, message) { return new CloudAuditError("ERR_AUDIT_VALIDATION", `${pathName}: ${message}`); }
function clockMilliseconds(value) { const number = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(number) || number < 0) throw new CloudAuditError("ERR_AUDIT_CLOCK", "clock must return a non-negative millisecond timestamp"); return number; }
function publicError(error) { return { code: error?.code ?? "ERR_AUDIT_NETWORK", message: error?.code ? error.message : "cloud audit upload failed" }; }

function decodeUtf8(value) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(value); }
  catch { throw new CloudAuditError("ERR_AUDIT_ENCODING", "audit state is not valid UTF-8"); }
}

function parseJsonSafe(text) {
  if (typeof text !== "string") throw new TypeError("JSON text is required");
  let index = 0;
  parseValue(0);
  skipWhitespace();
  if (index !== text.length) throw new Error("trailing JSON data");
  // The first pass above rejects duplicate keys and excessive nesting; the
  // standard parser then materializes the already-validated value.
  return JSON.parse(text);

  function parseValue(depth) {
    if (depth > 64) throw new Error("JSON is too deeply nested");
    skipWhitespace();
    const character = text[index];
    if (character === "{") return parseObject(depth + 1);
    if (character === "[") return parseArray(depth + 1);
    if (character === '"') return parseString();
    const start = index;
    while (index < text.length && !/[\s,\]}]/.test(text[index])) index += 1;
    if (start === index) throw new Error("JSON value is missing");
    const token = text.slice(start, index);
    return JSON.parse(token);
  }

  function parseObject(depth) {
    index += 1;
    const keys = new Set();
    skipWhitespace();
    if (text[index] === "}") { index += 1; return {}; }
    while (index < text.length) {
      skipWhitespace();
      if (text[index] !== '"') throw new Error("object key is invalid");
      const key = parseString();
      if (keys.has(key)) throw new Error("duplicate object key");
      keys.add(key);
      skipWhitespace();
      if (text[index] !== ":") throw new Error("object colon is missing");
      index += 1;
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "}") { index += 1; return {}; }
      if (text[index] !== ",") throw new Error("object comma is missing");
      index += 1;
    }
    throw new Error("object is unterminated");
  }

  function parseArray(depth) {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") { index += 1; return []; }
    while (index < text.length) {
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "]") { index += 1; return []; }
      if (text[index] !== ",") throw new Error("array comma is missing");
      index += 1;
    }
    throw new Error("array is unterminated");
  }

  function parseString() {
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === "\\") { index += 2; continue; }
      if (character === '"') { index += 1; return JSON.parse(text.slice(start, index)); }
      if (character < " ") throw new Error("control character in string");
      index += 1;
    }
    throw new Error("string is unterminated");
  }

  function skipWhitespace() { while (/[\s]/.test(text[index] ?? "")) index += 1; }
}
