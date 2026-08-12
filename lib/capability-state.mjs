import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { atomicWrite, secureMkdir } from "./config.mjs";
import { canonicalJson } from "../packages/capability/src/index.mjs";

const VERSION = 1;
const MAX_BYTES = 1024 * 1024;
const MAX_CONSUMED = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;

export function loadCapabilityState(file) {
  assertPath(file);
  if (!fs.existsSync(file)) return emptyState();
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_BYTES || (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o077) !== 0) throw new Error("Capability state storage is unsafe");
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error("Capability state is invalid"); }
  return validateState(parsed);
}

export function reserveCapabilityUse(file, { capability, agentId, requestId, now = Date.now() } = {}) {
  if (!capability || typeof capability !== "object" || !UUID.test(capability.capability_id ?? "") || !UUID.test(agentId ?? "") || !UUID.test(requestId ?? "")) throw new Error("Capability reservation input is invalid");
  if (!Number.isSafeInteger(capability.sequence) || capability.sequence < 1 || typeof capability.expires_at !== "string") throw new Error("Capability reservation evidence is invalid");
  const nowMs = Number(now);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("Capability reservation clock is invalid");
  const lease = acquireCapabilityLock(file);
  try {
  const state = loadCapabilityState(file);
  const existing = state.consumed[capability.capability_id];
  if (existing) {
    if (existing.request_id === requestId && existing.agent_id === agentId) return { replayed: true, state };
    throw new Error("Cloud capability has already been consumed");
  }
  const envelopeHash = crypto.createHash("sha256").update(canonicalJson(capability)).digest("hex");
  const previous = state.agents[agentId] ?? { highest_sequence: 0, highest_capability_hash: null };
  if (capability.sequence < previous.highest_sequence) throw new Error("Cloud capability sequence rolled back");
  if (capability.sequence === previous.highest_sequence && previous.highest_capability_hash !== envelopeHash) throw new Error("Cloud capability sequence conflicts with durable evidence");
  state.agents[agentId] = { highest_sequence: capability.sequence, highest_capability_hash: envelopeHash };
  for (const [id, record] of Object.entries(state.consumed)) {
    if (Date.parse(record.expires_at) <= nowMs) delete state.consumed[id];
  }
  if (Object.keys(state.consumed).length >= MAX_CONSUMED) throw new Error("Capability replay ledger is full");
  state.consumed[capability.capability_id] = { agent_id: agentId, request_id: requestId, sequence: capability.sequence, envelope_hash: envelopeHash, expires_at: capability.expires_at };
  saveCapabilityState(file, state);
  return { replayed: false, state };
  } finally { releaseCapabilityLock(lease); }
}

export function saveCapabilityState(file, state) {
  const normalized = validateState(state);
  secureMkdir(path.dirname(file));
  atomicWrite(file, `${canonicalJson(normalized)}\n`, 0o600);
  return normalized;
}

function emptyState() { return { version: VERSION, agents: {}, consumed: {} }; }

function validateState(value) {
  if (!plain(value) || !sameKeys(value, ["version", "agents", "consumed"]) || value.version !== VERSION || !plain(value.agents) || !plain(value.consumed)) throw new Error("Capability state is invalid");
  if (Object.keys(value.consumed).length > MAX_CONSUMED) throw new Error("Capability replay ledger is too large");
  for (const [agentId, head] of Object.entries(value.agents)) {
    if (!UUID.test(agentId) || !plain(head) || !sameKeys(head, ["highest_sequence", "highest_capability_hash"]) || !Number.isSafeInteger(head.highest_sequence) || head.highest_sequence < 0 || (head.highest_capability_hash !== null && !SHA256.test(head.highest_capability_hash))) throw new Error("Capability sequence state is invalid");
  }
  for (const [capabilityId, record] of Object.entries(value.consumed)) {
    if (!UUID.test(capabilityId) || !plain(record) || !sameKeys(record, ["agent_id", "request_id", "sequence", "envelope_hash", "expires_at"]) || !UUID.test(record.agent_id) || !UUID.test(record.request_id) || !Number.isSafeInteger(record.sequence) || record.sequence < 1 || !SHA256.test(record.envelope_hash) || !Number.isFinite(Date.parse(record.expires_at))) throw new Error("Capability replay evidence is invalid");
  }
  return JSON.parse(JSON.stringify(value));
}

function assertPath(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("Capability state path must be absolute");
  const parent = path.dirname(file);
  if (fs.existsSync(parent) && fs.lstatSync(parent).isSymbolicLink()) throw new Error("Capability state parent is unsafe");
  if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) throw new Error("Capability state file is unsafe");
}
function acquireCapabilityLock(file) {
  secureMkdir(path.dirname(file));
  const lock = `${file}.lock`;
  const token = crypto.randomBytes(24).toString("base64url");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, token }), { flag: "wx", mode: 0o600 });
      return { lock, token };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let record;
      const stat = fs.lstatSync(lock);
      try { record = JSON.parse(fs.readFileSync(lock, "utf8")); } catch { throw new Error("Capability state lock is invalid"); }
      const uid = process.getuid?.();
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid) || !Number.isSafeInteger(record?.pid) || typeof record?.token !== "string") throw new Error("Capability state lock is unsafe");
      try { process.kill(record.pid, 0); throw new Error("Capability state is locked by a live process"); }
      catch (probe) { if (probe.message === "Capability state is locked by a live process" || probe.code === "EPERM") throw probe; if (probe.code !== "ESRCH") throw probe; }
      fs.unlinkSync(lock);
    }
  }
  throw new Error("Capability state lock could not be acquired");
}
function releaseCapabilityLock(lease) {
  let record;
  try { record = JSON.parse(fs.readFileSync(lease.lock, "utf8")); } catch { throw new Error("Capability state lock changed before release"); }
  if (record.pid !== process.pid || record.token !== lease.token) throw new Error("Capability state lock ownership changed before release");
  fs.unlinkSync(lease.lock);
}
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
function sameKeys(value, keys) { const actual = Object.keys(value); return actual.length === keys.length && actual.every((key) => keys.includes(key)); }
