import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_LEASE_TYPE,
  normalizeAgentSessionLease
} from "./agent-session-lease.mjs";

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_VERSION = 1;
export const AGENT_LAUNCH_AUTHORITY_HANDOFF_REQUEST_TYPE = "agentpass.agent-launch-authority-handoff-request";
export const AGENT_LAUNCH_AUTHORITY_HANDOFF_BINDING_TYPE = "agentpass.agent-launch-authority-handoff-binding";

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_REQUEST_KEYS = Object.freeze([
  "version", "type", "request_id", "adapter_id", "adapter_version", "nonce"
]);

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_BINDING_KEYS = Object.freeze([
  "version", "type", "request_id", "organization_id", "device_id", "agent_id", "agent_kind",
  "adapter_id", "adapter_version", "session_id", "not_before", "expires_at", "nonce_sha256", "lease_sha256"
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const NONCE = /^[A-Za-z0-9_-]+$/u;
const MIN_NONCE_BYTES = 16;
const MAX_NONCE_BYTES = 64;

export class AgentLaunchAuthorityHandoffContractError extends TypeError {
  constructor(code = "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_INPUT") {
    super("Agent launch authority handoff contract is invalid");
    this.name = "AgentLaunchAuthorityHandoffContractError";
    this.code = code;
  }
}

/**
 * The request contains only public correlation and binding material. The raw
 * nonce is transient and is reduced to a digest before it crosses the
 * repository boundary. It is never a URL, log, durable record, or response.
 */
export function normalizeAgentLaunchAuthorityHandoffRequest(value) {
  try {
    exactObject(value, AGENT_LAUNCH_AUTHORITY_HANDOFF_REQUEST_KEYS);
    const request = Object.freeze({
      version: exact(value.version, AGENT_LAUNCH_AUTHORITY_HANDOFF_VERSION),
      type: exact(value.type, AGENT_LAUNCH_AUTHORITY_HANDOFF_REQUEST_TYPE),
      request_id: uuid(value.request_id),
      adapter_id: uuid(value.adapter_id),
      adapter_version: semver(value.adapter_version),
      nonce: canonicalNonce(value.nonce)
    });
    return Object.freeze({
      ...request,
      nonce_sha256: crypto.createHash("sha256").update(Buffer.from(request.nonce, "base64url")).digest("hex")
    });
  } catch (error) {
    if (error instanceof AgentLaunchAuthorityHandoffContractError) throw error;
    throw new AgentLaunchAuthorityHandoffContractError();
  }
}

/**
 * Normalize the exact Session binder result required by this boundary. A
 * partial signing-capability audience projection is intentionally rejected:
 * it cannot prove adapter, expiry, or complete Lease authority binding.
 */
export function normalizeAgentLaunchAuthoritySessionBinding(value, { organizationId, deviceId, sessionId, now }) {
  try {
    exactObject(value, ["authorized", "lease"]);
    if (value.authorized !== true) throw new AgentLaunchAuthorityHandoffContractError("ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_SESSION");
    const lease = normalizeAgentSessionLease(value.lease, { now, allowExpired: false });
    if (lease.type !== AGENT_SESSION_LEASE_TYPE
      || lease.organization_id !== uuid(organizationId)
      || lease.device_id !== uuid(deviceId)
      || lease.session_id !== uuid(sessionId)
      || lease.used_signatures >= lease.max_signatures) {
      throw new AgentLaunchAuthorityHandoffContractError("ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_SESSION");
    }
    return Object.freeze({ authorized: true, lease });
  } catch (error) {
    if (error instanceof AgentLaunchAuthorityHandoffContractError) throw error;
    throw new AgentLaunchAuthorityHandoffContractError("ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_SESSION");
  }
}

/**
 * Construct the repository-only public binding. The native proof is not part
 * of this value: the current Cloud contracts cannot verify or mint the native
 * bootstrap/session proof consumed by the signed Host.
 */
export function createAgentLaunchAuthorityHandoffBinding({ request, lease, organizationId, deviceId, sessionId, now }) {
  try {
    const normalizedRequest = normalizeAgentLaunchAuthorityHandoffRequest(request);
    const normalizedLease = normalizeAgentSessionLease(lease, { now, allowExpired: false });
    const organization = uuid(organizationId);
    const device = uuid(deviceId);
    const session = uuid(sessionId);
    if (normalizedLease.organization_id !== organization
      || normalizedLease.device_id !== device
      || normalizedLease.session_id !== session
      || normalizedLease.adapter_id !== normalizedRequest.adapter_id
      || normalizedLease.adapter_version !== normalizedRequest.adapter_version
      || normalizedLease.used_signatures >= normalizedLease.max_signatures) {
      throw new AgentLaunchAuthorityHandoffContractError("ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_SESSION");
    }
    return Object.freeze({
      version: AGENT_LAUNCH_AUTHORITY_HANDOFF_VERSION,
      type: AGENT_LAUNCH_AUTHORITY_HANDOFF_BINDING_TYPE,
      request_id: normalizedRequest.request_id,
      organization_id: normalizedLease.organization_id,
      device_id: normalizedLease.device_id,
      agent_id: normalizedLease.agent_id,
      agent_kind: normalizedLease.agent_kind,
      adapter_id: normalizedLease.adapter_id,
      adapter_version: normalizedLease.adapter_version,
      session_id: normalizedLease.session_id,
      not_before: normalizedLease.not_before,
      expires_at: normalizedLease.expires_at,
      nonce_sha256: normalizedRequest.nonce_sha256,
      lease_sha256: sha256(canonicalJson(normalizedLease))
    });
  } catch (error) {
    if (error instanceof AgentLaunchAuthorityHandoffContractError) throw error;
    throw new AgentLaunchAuthorityHandoffContractError("ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_SESSION");
  }
}

export function assertAgentLaunchAuthorityHandoffBinding(value) {
  try {
    exactObject(value, AGENT_LAUNCH_AUTHORITY_HANDOFF_BINDING_KEYS);
    if (value.version !== AGENT_LAUNCH_AUTHORITY_HANDOFF_VERSION
      || value.type !== AGENT_LAUNCH_AUTHORITY_HANDOFF_BINDING_TYPE
      || !UUID.test(value.request_id)
      || !UUID.test(value.organization_id)
      || !UUID.test(value.device_id)
      || !UUID.test(value.agent_id)
      || !["claude-code", "cursor"].includes(value.agent_kind)
      || !UUID.test(value.adapter_id)
      || !SEMVER.test(value.adapter_version)
      || !UUID.test(value.session_id)
      || !TIMESTAMP.test(value.not_before)
      || !TIMESTAMP.test(value.expires_at)
      || !SHA256.test(value.nonce_sha256)
      || !SHA256.test(value.lease_sha256)
      || new Date(value.not_before).toISOString() !== value.not_before
      || new Date(value.expires_at).toISOString() !== value.expires_at
      || Date.parse(value.expires_at) <= Date.parse(value.not_before)) {
      throw new AgentLaunchAuthorityHandoffContractError();
    }
    return Object.freeze(value);
  } catch (error) {
    if (error instanceof AgentLaunchAuthorityHandoffContractError) throw error;
    throw new AgentLaunchAuthorityHandoffContractError();
  }
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Reflect.ownKeys(value).some((key) => typeof key !== "string")
    || Object.keys(value).length !== keys.length
    || Object.keys(value).some((key) => !keys.includes(key))) {
    throw new AgentLaunchAuthorityHandoffContractError();
  }
}

function exact(value, expected) {
  if (value !== expected) throw new AgentLaunchAuthorityHandoffContractError();
  return expected;
}

function uuid(value) {
  if (typeof value !== "string" || !UUID.test(value) || value !== value.toLowerCase()) throw new AgentLaunchAuthorityHandoffContractError();
  return value;
}

function semver(value) {
  if (typeof value !== "string" || !SEMVER.test(value)) throw new AgentLaunchAuthorityHandoffContractError();
  return value;
}

function canonicalNonce(value) {
  if (typeof value !== "string" || !NONCE.test(value)) throw new AgentLaunchAuthorityHandoffContractError();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < MIN_NONCE_BYTES || bytes.length > MAX_NONCE_BYTES || bytes.toString("base64url") !== value) {
    throw new AgentLaunchAuthorityHandoffContractError();
  }
  return value;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
