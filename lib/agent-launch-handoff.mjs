import fs from "node:fs";

import { canonicalJson } from "./identity.mjs";

export const AGENT_LAUNCH_HANDOFF_FD = 3;
export const AGENT_LAUNCH_HANDOFF_SCHEMA_VERSION = 1;
export const AGENT_LAUNCH_HANDOFF_MAX_BYTES = 16 * 1024;
export const AGENT_LAUNCH_HANDOFF_MAX_PROOF_BYTES = 4 * 1024;
export const AGENT_LAUNCH_HANDOFF_TYPE = "agentpass.launch-authority";

export const AGENT_LAUNCH_HANDOFF_ERRORS = Object.freeze({
  UNAVAILABLE: "AGENT_LIFECYCLE_HANDOFF_NOT_AVAILABLE",
  INVALID: "AGENT_LIFECYCLE_HANDOFF_INVALID",
  OVERSIZED: "AGENT_LIFECYCLE_HANDOFF_OVERSIZED",
  MISMATCH: "AGENT_LIFECYCLE_HANDOFF_BINDING_MISMATCH"
});

const HANDOFF_KEYS = Object.freeze([
  "schema_version", "agent_id", "agent_kind", "requested_ttl_seconds", "proof"
]);
const AUTHORITY_ENVELOPE_KEYS = Object.freeze(["version", "type", "project", "agent", "issued_at", "expires_at", "authority"]);
const AGENT_KINDS = Object.freeze({ "claude-code": "claude_code", cursor: "cursor" });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export class AgentLaunchHandoffError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AgentLaunchHandoffError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AgentLaunchHandoffError(code, message);
}

/**
 * Validate the exact authority envelope produced by the trusted
 * Console/Device handoff. The inner document is the private document
 * consumed by the Native Agent Host. Project and expiry are kept in the
 * envelope so the CLI can bind them before stripping the envelope and
 * relaying only the native document over the fresh FD3 pipe.
 */
export function normalizeAgentLaunchAuthority(value, expected = {}, nowMs = Date.now()) {
  if (!plainObject(value) || !exactKeys(value, AUTHORITY_ENVELOPE_KEYS)
    || value.version !== AGENT_LAUNCH_HANDOFF_SCHEMA_VERSION
    || value.type !== AGENT_LAUNCH_HANDOFF_TYPE
    || value.project !== expected.project
    || value.agent !== expected.agent
    || !RFC3339_MILLISECONDS.test(value.issued_at)
    || !RFC3339_MILLISECONDS.test(value.expires_at)) {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff is invalid");
  }
  const issuedAtMs = Date.parse(value.issued_at);
  const expiresAtMs = Date.parse(value.expires_at);
  if (!Number.isSafeInteger(issuedAtMs) || !Number.isSafeInteger(expiresAtMs)
    || expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs !== expected.ttl_seconds * 1_000
    || issuedAtMs > nowMs
    || expiresAtMs <= nowMs) {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.MISMATCH, "The launch handoff is expired or does not match the requested expiry");
  }

  const inner = value.authority;
  if (!plainObject(inner)
    || !exactKeys(inner, HANDOFF_KEYS)
    || inner.schema_version !== AGENT_LAUNCH_HANDOFF_SCHEMA_VERSION
    || typeof inner.agent_id !== "string"
    || !UUID.test(inner.agent_id)
    || inner.agent_id !== inner.agent_id.toLowerCase()
    || typeof inner.agent_kind !== "string"
    || !Object.values(AGENT_KINDS).includes(inner.agent_kind)
    || !Number.isSafeInteger(inner.requested_ttl_seconds)
    || typeof inner.proof !== "string") {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff authority is invalid");
  }

  const proofBytes = Buffer.from(inner.proof, "utf8");
  if (proofBytes.length < 16 || proofBytes.length > AGENT_LAUNCH_HANDOFF_MAX_PROOF_BYTES) {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff proof is invalid");
  }
  let proof;
  try { proof = JSON.parse(inner.proof); } catch { fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff proof is invalid"); }
  if (!plainObject(proof) || canonicalJson(proof) !== inner.proof) {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff proof is invalid");
  }

  const expectedKind = AGENT_KINDS[expected.agent];
  if (expectedKind === undefined
    || inner.agent_kind !== expectedKind
    || inner.requested_ttl_seconds !== expected.ttl_seconds) {
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.MISMATCH, "The launch handoff does not match the requested agent or expiry");
  }

  const bytes = Buffer.from(canonicalJson(inner), "utf8");
  if (bytes.length > AGENT_LAUNCH_HANDOFF_MAX_BYTES) fail(AGENT_LAUNCH_HANDOFF_ERRORS.OVERSIZED, "The launch handoff is oversized");
  return Object.freeze({
    version: AGENT_LAUNCH_HANDOFF_SCHEMA_VERSION,
    type: AGENT_LAUNCH_HANDOFF_TYPE,
    project: value.project,
    agent: value.agent,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    authority: Object.freeze({ ...inner }),
    bytes
  });
}

/**
 * Consume the upstream one-time handoff. Only a FIFO or socket is accepted;
 * this function never opens, reads, or creates a path-based authority store.
 */
export function readAgentLaunchAuthority({
  fd = AGENT_LAUNCH_HANDOFF_FD,
  fstat = fs.fstatSync,
  read = fs.readSync,
  close = fs.closeSync
} = {}) {
  let data;
  let ownsDescriptor = false;
  try {
    const stat = fstat(fd);
    ownsDescriptor = true;
    if (!stat || (stat.isFIFO?.() !== true && stat.isSocket?.() !== true)) {
      fail(AGENT_LAUNCH_HANDOFF_ERRORS.UNAVAILABLE, "The one-time launch handoff is not available");
    }
    const chunks = [];
    let total = 0;
    const buffer = Buffer.alloc(4 * 1024);
    try {
      while (true) {
        const count = read(fd, buffer, 0, buffer.length, null);
        if (count === 0) break;
        if (!Number.isSafeInteger(count) || count < 0 || count > buffer.length) {
          fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The one-time launch handoff could not be read");
        }
        total += count;
        if (total > AGENT_LAUNCH_HANDOFF_MAX_BYTES) fail(AGENT_LAUNCH_HANDOFF_ERRORS.OVERSIZED, "The launch handoff is oversized");
        chunks.push(Buffer.from(buffer.subarray(0, count)));
      }
      data = Buffer.concat(chunks, total);
    } finally {
      buffer.fill(0);
      for (const chunk of chunks) chunk.fill(0);
    }
  } catch (error) {
    if (error instanceof AgentLaunchHandoffError) throw error;
    fail(AGENT_LAUNCH_HANDOFF_ERRORS.UNAVAILABLE, "The one-time launch handoff is not available");
  } finally {
    if (ownsDescriptor) {
      try { close(fd); } catch { /* the descriptor is already unavailable */ }
    }
  }

  try {
    if (!data || data.length === 0) fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff is empty");
    let value;
    try { value = JSON.parse(data.toString("utf8")); } catch { fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff is invalid"); }
    if (!plainObject(value) || canonicalJson(value) !== data.toString("utf8")) {
      fail(AGENT_LAUNCH_HANDOFF_ERRORS.INVALID, "The launch handoff is not canonical");
    }
    return value;
  } finally {
    data?.fill(0);
  }
}

export function serializeAgentLaunchAuthority(value, expected) {
  const normalized = normalizeAgentLaunchAuthority(value, expected);
  const bytes = Buffer.from(normalized.bytes);
  return Object.freeze({ ...normalized, bytes });
}

function exactKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && keys.every((key) => typeof key === "string" && expected.includes(key));
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
