const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const SEMVER = /^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const AGENT_KINDS = new Set(["claude-code", "cursor"]);
const MAX_POLICIES = 128;

/**
 * Cloud-side allowlist for native process-binding policy identifiers.
 *
 * This registry does not attest a process. The native broker owns that job.
 * It prevents a Human request from naming an arbitrary or wrong-adapter
 * native policy and makes the release-approved policy set immutable for the
 * lifetime of a hosted runtime instance.
 */
export function createProcessBindingPolicyRegistry(document) {
  const policies = normalizeDocument(document);
  const byId = new Map(policies.map((policy) => [policy.policy_id, policy]));

  async function resolve(input = {}) {
    try {
      const policy = byId.get(identifier(input.process_binding_policy_id));
      if (!policy || policy.status !== "enabled") return Object.freeze({ allowed: false, reason: "policy_unavailable" });
      if (policy.agent_kind !== agentKind(input.agent_kind)
        || policy.adapter_id !== uuid(input.adapter_id)
        || !policy.adapter_versions.includes(semver(input.adapter_version))) {
        return Object.freeze({ allowed: false, reason: "policy_binding_mismatch" });
      }
      uuid(input.organization_id);
      uuid(input.device_id);
      uuid(input.agent_id);
      positiveInteger(input.control_sequence);
      return Object.freeze({ allowed: true, policy_id: policy.policy_id, release_id: policy.release_id });
    } catch {
      return Object.freeze({ allowed: false, reason: "invalid_binding" });
    }
  }

  return Object.freeze({ resolve, size: policies.length, policyIds: Object.freeze(policies.map((policy) => policy.policy_id)) });
}

export function normalizeProcessBindingPolicyDocument(document) {
  return Object.freeze({ version: 1, policies: normalizeDocument(document) });
}

function normalizeDocument(value) {
  exactObject(value, ["version", "policies"]);
  if (value.version !== 1 || !Array.isArray(value.policies) || value.policies.length < 1 || value.policies.length > MAX_POLICIES) throw new TypeError("process binding policy document is invalid");
  const ids = new Set();
  const policies = value.policies.map((entry) => {
    exactObject(entry, ["policy_id", "release_id", "agent_kind", "adapter_id", "adapter_versions", "status"]);
    const policyId = identifier(entry.policy_id);
    if (ids.has(policyId)) throw new TypeError("process binding policy document is invalid");
    ids.add(policyId);
    if (!Array.isArray(entry.adapter_versions) || entry.adapter_versions.length < 1 || entry.adapter_versions.length > 32) throw new TypeError("process binding policy document is invalid");
    const versions = [...new Set(entry.adapter_versions.map(semver))].sort();
    if (versions.length !== entry.adapter_versions.length || !["enabled", "disabled"].includes(entry.status)) throw new TypeError("process binding policy document is invalid");
    return deepFreeze({
      policy_id: policyId,
      release_id: identifier(entry.release_id),
      agent_kind: agentKind(entry.agent_kind),
      adapter_id: uuid(entry.adapter_id),
      adapter_versions: versions,
      status: entry.status
    });
  }).sort((left, right) => left.policy_id.localeCompare(right.policy_id));
  return Object.freeze(policies);
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) throw new TypeError("process binding policy document is invalid");
}
function identifier(value) { if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError("process binding policy document is invalid"); return value; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new TypeError("process binding policy document is invalid"); return value.toLowerCase(); }
function semver(value) { if (typeof value !== "string" || !SEMVER.test(value)) throw new TypeError("process binding policy document is invalid"); return value; }
function agentKind(value) { if (!AGENT_KINDS.has(value)) throw new TypeError("process binding policy document is invalid"); return value; }
function positiveInteger(value) { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError("process binding policy document is invalid"); return value; }
function deepFreeze(value) { Object.freeze(value); for (const nested of Object.values(value)) if (nested && typeof nested === "object" && !Object.isFrozen(nested)) deepFreeze(nested); return value; }
