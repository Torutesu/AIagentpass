export type AuditExportEnvironment = "staging" | "production";
export type AuditExportChain = "admin" | "device" | "cloud_agent";
export type AuditExportRole = "owner" | "admin" | "auditor" | "viewer";

export type AuditExport = Readonly<{
  organization_id: string;
  export_id: string;
  environment: AuditExportEnvironment;
  chain: AuditExportChain;
  range: Readonly<Record<string, unknown>>;
  payload_digest: string;
  payload: Readonly<Record<string, unknown>>;
  audit_anchor: Readonly<Record<string, unknown> & { expires_at?: string }>;
  validity: "active" | "expired";
}>;

export type AuditExportVerification = Readonly<{
  payload_digest: boolean;
  root: boolean;
  anchor: boolean;
  historical_key: boolean;
  valid: boolean;
  reason: "valid" | "invalid_export" | "payload_digest_mismatch" | "root_mismatch" | "anchor_invalid" | "historical_key_unavailable";
}>;

export class AuditExportClientError extends Error {
  readonly code: "empty" | "expired" | "corrupt" | "offline" | "response_loss" | "invalid_response" | "role_denied";
  constructor(code: AuditExportClientError["code"], message: string) {
    super(message);
    this.name = "AuditExportClientError";
    this.code = code;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const EXPORT_KEYS = ["organization_id", "export_id", "environment", "chain", "range", "payload_digest", "payload", "audit_anchor", "validity"];
const VERIFY_KEYS = ["payload_digest", "root", "anchor", "historical_key", "valid", "reason"];

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function parseAuditExport(value: unknown): AuditExport {
  // Cloud uses { audit_export, request_id }; the BFF deliberately returns only
  // audit_export. Supporting both exact shapes keeps request_id out of UI state.
  const audit_export = record(value) && hasExactKeys(value, ["audit_export", "request_id"])
    && typeof value.request_id === "string" ? value.audit_export : value;
  if (!record(audit_export) || !hasExactKeys(audit_export, EXPORT_KEYS)
    || typeof audit_export.organization_id !== "string" || !UUID.test(audit_export.organization_id)
    || typeof audit_export.export_id !== "string" || !UUID.test(audit_export.export_id)
    || !["staging", "production"].includes(String(audit_export.environment))
    || !["admin", "device", "cloud_agent"].includes(String(audit_export.chain))
    || !record(audit_export.range) || !record(audit_export.payload) || !record(audit_export.audit_anchor)
    || typeof audit_export.payload_digest !== "string" || !SHA256.test(audit_export.payload_digest)
    || !["active", "expired"].includes(String(audit_export.validity))) {
    throw new AuditExportClientError("invalid_response", "Audit export invalid response");
  }
  return structuredClone(audit_export) as AuditExport;
}

function parseVerification(value: unknown): AuditExportVerification {
  const source = record(value) && hasExactKeys(value, ["verification", "request_id"])
    && typeof value.request_id === "string" ? value.verification : value;
  if (!record(source) || !hasExactKeys(source, VERIFY_KEYS)
    || ["payload_digest", "root", "anchor", "historical_key", "valid"].some((key) => typeof source[key] !== "boolean")
    || !["valid", "invalid_export", "payload_digest_mismatch", "root_mismatch", "anchor_invalid", "historical_key_unavailable"].includes(String(source.reason))) {
    throw new AuditExportClientError("invalid_response", "Verification invalid response");
  }
  return Object.freeze(structuredClone(source)) as AuditExportVerification;
}

function roleAccess(role: AuditExportRole) {
  return Object.freeze({
    canCreate: role === "owner" || role === "admin",
    canRead: role === "owner" || role === "admin" || role === "auditor",
    canVerify: role === "owner" || role === "admin" || role === "auditor",
    canDownload: role === "owner" || role === "admin" || role === "auditor",
  });
}

async function jsonResponse(response: Response): Promise<unknown> {
  if (response.status === 404) throw new AuditExportClientError("empty", "Audit export empty");
  if (!response.ok) throw new AuditExportClientError(response.status >= 500 ? "response_loss" : "corrupt", "Audit export request failed");
  if (!/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") ?? "")) throw new AuditExportClientError("invalid_response", "Invalid response type");
  try { return await response.json(); }
  catch { throw new AuditExportClientError("invalid_response", "Invalid response JSON"); }
}

async function request(path: string, init: RequestInit, fetchImpl: typeof fetch): Promise<Response> {
  try {
    return await fetchImpl(path, { ...init, credentials: "same-origin", cache: "no-store", redirect: "error" });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new AuditExportClientError(typeof navigator !== "undefined" && navigator.onLine === false ? "offline" : "response_loss", "Audit export transport_failed or offline");
  }
}

export function createAuditExportClient({ role, fetchImpl = globalThis.fetch }: { role: AuditExportRole; fetchImpl?: typeof fetch }) {
  const access = roleAccess(role);
  const authorize = (allowed: boolean) => { if (!allowed) throw new AuditExportClientError("role_denied", "Role denied"); };
  return Object.freeze({
    ...access,
    async createAuditExport(input: { export_id: string; environment: AuditExportEnvironment; chain: AuditExportChain; csrf: string; recentAuth: string; contextHash: string; signal?: AbortSignal }) {
      authorize(access.canCreate);
      // audit.export.create is bound to context_hash by the passkey ceremony.
      const response = await request("/api/console?operation=audit-export", { method: "POST", signal: input.signal, headers: { "content-type": "application/json", "agentpass-csrf": input.csrf, "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": input.recentAuth }, body: JSON.stringify({ export_id: input.export_id, environment: input.environment, chain: input.chain }) }, fetchImpl);
      const result = parseAuditExport(await jsonResponse(response));
      if (result.validity === "expired") throw new AuditExportClientError("expired", "Audit export expired");
      return result;
    },
    async getAuditExport(input: { export_id: string; environment: AuditExportEnvironment; chain: AuditExportChain; recentAuth: string; context_hash: string; signal?: AbortSignal }) {
      authorize(access.canRead);
      // audit.export.retrieve is bound to context_hash by the passkey ceremony.
      const path = `/api/console?resource=audit-export&export_id=${encodeURIComponent(input.export_id)}&environment=${input.environment}&chain=${input.chain}`;
      return parseAuditExport(await jsonResponse(await request(path, { method: "GET", signal: input.signal, headers: { "agentpass-recent-auth": input.recentAuth } }, fetchImpl)));
    },
    async verifyAuditExport(auditExport: AuditExport, recentAuth: string, csrf: string, signal?: AbortSignal) {
      authorize(access.canVerify);
      const response = await request("/api/console?operation=audit-export-verify", { method: "POST", signal, headers: { "content-type": "application/json", "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth }, body: JSON.stringify(auditExport) }, fetchImpl);
      return parseVerification(await jsonResponse(response));
    },
    async downloadAuditExport(input: { export_id: string; environment: AuditExportEnvironment; chain: AuditExportChain; recentAuth: string; signal?: AbortSignal }) {
      authorize(access.canDownload);
      const path = `/api/console?resource=audit-export-download&export_id=${encodeURIComponent(input.export_id)}&environment=${input.environment}&chain=${input.chain}`;
      const response = await request(path, { method: "GET", signal: input.signal, headers: { "agentpass-recent-auth": input.recentAuth } }, fetchImpl);
      if (!response.ok) throw new AuditExportClientError("response_loss", "Download response-loss");
      const bytes = await response.arrayBuffer();
      const blob = new Blob([bytes], { type: "application/json" });
      const objectUrl = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = `agentpass-audit-${input.chain}-${input.export_id}.json`;
        anchor.click();
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
    },
  });
}
