import {
  sha256,
  validateMaintenanceJob,
  validateMaintenanceResult,
  validatePatchProposal
} from "../../../../packages/maintenance-contracts/src/index.mjs";

export const VERIFICATION_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "maintenance.verification.invalid_input",
  INDEPENDENT_EVIDENCE_REQUIRED: "maintenance.verification.independent_evidence_required"
});

export class MaintenanceVerificationError extends Error {
  constructor(code, message) { super(message); this.name = "MaintenanceVerificationError"; this.code = code; }
}

const fail = (code, message) => { throw new MaintenanceVerificationError(code, message); };
const DIGEST = /^[0-9a-f]{64}$/u;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const LAYERS = Object.freeze(["syntax", "repository", "agent", "conformance", "security", "authority_delta"]);
const STATUSES = new Set(["passed", "failed", "not_run", "not_proven"]);

function timestamp(value) { if (typeof value !== "string" || !TS.test(value) || Number.isNaN(Date.parse(value))) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "createdAt is invalid"); return value; }
function digest(value, label) { if (typeof value !== "string" || !DIGEST.test(value)) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, `${label} is invalid`); return value; }
function validateEvidence(evidence = {}) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "evidence must be an object");
  if (Object.keys(evidence).some((key) => !LAYERS.includes(key))) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "evidence contains an unknown layer");
  const normalized = {};
  for (const layer of LAYERS) {
    const value = evidence[layer] ?? { status: layer === "conformance" ? "not_proven" : "not_run" };
    if (!value || typeof value !== "object" || Array.isArray(value) || !STATUSES.has(value.status)) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, `${layer} evidence is invalid`);
    if (Object.keys(value).some((key) => !["status", "evidence_digest"].includes(key))) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, `${layer} evidence has an unknown field`);
    if (value.evidence_digest !== undefined) digest(value.evidence_digest, `${layer}.evidence_digest`);
    normalized[layer] = Object.freeze({ status: value.status, ...(value.evidence_digest === undefined ? {} : { evidence_digest: value.evidence_digest }) });
  }
  return Object.freeze(normalized);
}

/**
 * Aggregate independent verification evidence without executing commands or
 * contacting a provider. Missing layers remain not_run/not_proven. Passing
 * agent-generated tests cannot satisfy the repository verification layer.
 */
export function verifyMaintenancePatch({ job, proposal, evidence = {}, createdAt = new Date().toISOString() } = {}) {
  try { validateMaintenanceJob(job); validatePatchProposal(proposal); }
  catch { fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "verification bindings are invalid"); }
  if (job.job_id !== proposal.job_id || job.organization_id !== proposal.organization_id) fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "job and proposal bindings do not match");
  const layers = validateEvidence(evidence);
  const required = ["syntax", "repository", "security", "authority_delta"];
  if (proposal.conformance.length > 0) required.push("conformance");
  if (layers.repository.status !== "passed" && layers.agent.status === "passed") fail(VERIFICATION_ERROR_CODES.INDEPENDENT_EVIDENCE_REQUIRED, "agent-generated tests cannot be the sole proof");
  const requiredStatuses = required.map((layer) => layers[layer].status);
  const status = requiredStatuses.includes("failed") || layers.agent.status === "failed" ? "failed" : requiredStatuses.some((value) => value === "not_proven") ? "partial" : requiredStatuses.some((value) => value === "not_run") ? "not_run" : "passed";
  const verificationStatus = status;
  const uncertainty = required.filter((layer) => !["passed"].includes(layers[layer].status)).map((layer) => `${layer}:${layers[layer].status}`);
  const created = timestamp(createdAt);
  const resultDigest = sha256({ schema_version: 1, job_id: job.job_id, proposal_id: proposal.proposal_id, patch_digest: proposal.patch_digest, layers });
  const result = {
    schema_version: 1, kind: "agentpass.maintenance.result", result_id: `result-${resultDigest.slice(0, 32)}`,
    job_id: job.job_id, organization_id: job.organization_id, source_commit: proposal.base_commit,
    patch_digest: proposal.patch_digest, changed_paths: proposal.changed_paths, evidence: { layers, result_digest: resultDigest, uncertainty },
    status: status === "passed" ? "passed" : status === "failed" ? "failed" : "uncertain", verification_status: verificationStatus,
    created_at: created
  };
  try { validateMaintenanceResult(result); } catch { fail(VERIFICATION_ERROR_CODES.INVALID_INPUT, "generated verification result failed contract validation"); }
  return Object.freeze(result);
}

export const evaluateMaintenanceVerification = verifyMaintenancePatch;
