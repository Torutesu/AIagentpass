import {
  sha256,
  validateAdvisory,
  validateMaintenanceJob,
  validateMaintenancePlan,
  validateMaintenancePolicy,
  validateRepositorySnapshot,
  validatePatchProposal
} from "../../../../packages/maintenance-contracts/src/index.mjs";

export const PATCH_AGENT_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "maintenance.patch_agent.invalid_input",
  AUTHORITY_DENIED: "maintenance.patch_agent.authority_denied",
  PATH_DENIED: "maintenance.patch_agent.path_denied",
  SECRET_REJECTED: "maintenance.patch_agent.secret_rejected",
  EXECUTABLE_REJECTED: "maintenance.patch_agent.executable_rejected",
  LIMIT_EXCEEDED: "maintenance.patch_agent.limit_exceeded"
});

export class PatchAgentError extends Error {
  constructor(code, message) { super(message); this.name = "PatchAgentError"; this.code = code; }
}

const fail = (code, message) => { throw new PatchAgentError(code, message); };
const DIGEST = /^[0-9a-f]{64}$/u;
const ABSOLUTE_PATH = /^\/(?:[^\0\n\r\\]+)$/u;
const TEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const MAX_FILES = 100;
const MAX_DIFF_BYTES = 512 * 1024;
const MAX_FILE_DIFF_BYTES = 256 * 1024;
const MAX_TESTS = 64;
const MAX_CONFORMANCE = 32;
const TEST_KINDS = new Set(["syntax", "typecheck", "unit", "integration", "security", "secret_scan", "repository"]);
const DENIED_PATH = /(?:^|\/)(?:\.github\/workflows(?:\/|$)|codeowners(?:\.|$)|\.env(?:\.|$)|(?:.*(?:secret|credential|token|private[-_]?key|access[-_]?key).*)$)/iu;
const DENIED_DIRECTORY = /(?:^|\/)(?:auth(?:orization|entication)?|billing|deployment|infrastructure|migrations?)(?:\/|$)/iu;
const EXECUTABLE_PATH = /(?:^|\/)(?:bin|scripts?)(?:\/|$)|\.(?:exe|dylib|dll|so|dmg|pkg|app|sh|bash|zsh|fish|command|ps1|bat|cmd|wasm)$/iu;
const SECRET_CONTENT = /-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:^|[^A-Za-z])(gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})(?:$|[^A-Za-z0-9_-])|\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|access[_-]?token|private[_-]?key|authorization)\s*[:=]/iu;
const FORBIDDEN_FIELDS = new Set(["command", "commands", "script", "shell", "argv", "executable", "network", "token", "credential", "secret"]);

function object(value, label) { if (!value || typeof value !== "object" || Array.isArray(value)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `${label} must be an object`); return value; }
function path(value, label) {
  if (typeof value !== "string" || !ABSOLUTE_PATH.test(value) || value.includes("..") || value.includes("%2e") || value.includes("%2E")) fail(PATCH_AGENT_ERROR_CODES.PATH_DENIED, `${label} is not an exact safe path`);
  if (DENIED_PATH.test(value) || DENIED_DIRECTORY.test(value)) fail(PATCH_AGENT_ERROR_CODES.PATH_DENIED, `${label} is sensitive and denied`);
  if (EXECUTABLE_PATH.test(value)) fail(PATCH_AGENT_ERROR_CODES.EXECUTABLE_REJECTED, `${label} is executable and denied`);
  return value;
}
function digest(value, label) { if (typeof value !== "string" || !DIGEST.test(value)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `${label} is invalid`); return value; }
function rejectForbiddenFields(value, label) { for (const key of Object.keys(value)) if (FORBIDDEN_FIELDS.has(key)) fail(PATCH_AGENT_ERROR_CODES.EXECUTABLE_REJECTED, `${label}.${key} is not an allowed capability`); }
function ensureNoSecret(value, label) { if (SECRET_CONTENT.test(value)) fail(PATCH_AGENT_ERROR_CODES.SECRET_REJECTED, `${label} contains secret material`); }
function timestamp(value) { const date = new Date(value); if (!Number.isFinite(date.getTime())) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "created_at is invalid"); return date.toISOString(); }

function validateTest(item, index) {
  const value = object(item, `tests[${index}]`); rejectForbiddenFields(value, `tests[${index}]`);
  const allowed = new Set(["id", "kind", "required", "status"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `tests[${index}] contains an unknown field`);
  if (typeof value.id !== "string" || !TEST_ID.test(value.id)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `tests[${index}].id is invalid`);
  if (!TEST_KINDS.has(value.kind)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `tests[${index}].kind is invalid`);
  if (value.required !== undefined && typeof value.required !== "boolean") fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `tests[${index}].required is invalid`);
  if (value.status !== undefined && value.status !== "not_run") fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `tests[${index}].status must be not_run`);
  return Object.freeze({ id: value.id, kind: value.kind, required: value.required !== false, status: "not_run" });
}

function validateConformance(item, index) {
  const value = object(item, `conformance[${index}]`); rejectForbiddenFields(value, `conformance[${index}]`);
  const allowed = new Set(["id", "target_origin", "required"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `conformance[${index}] contains an unknown field`);
  if (typeof value.id !== "string" || !TEST_ID.test(value.id)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `conformance[${index}].id is invalid`);
  if (typeof value.target_origin !== "string" || !/^https:\/\/[^/\s]+$/u.test(value.target_origin)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `conformance[${index}].target_origin is invalid`);
  if (value.required !== undefined && typeof value.required !== "boolean") fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `conformance[${index}].required is invalid`);
  return Object.freeze({ id: value.id, target_origin: value.target_origin, required: value.required !== false, status: "not_proven" });
}

function validateChange(item, index, allowedPaths) {
  const value = object(item, `changes[${index}]`); rejectForbiddenFields(value, `changes[${index}]`);
  const allowed = new Set(["path", "operation", "before_digest", "after_digest", "content", "diff"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `changes[${index}] contains an unknown field`);
  const changedPath = path(value.path, `changes[${index}].path`);
  if (!allowedPaths.has(changedPath)) fail(PATCH_AGENT_ERROR_CODES.PATH_DENIED, `${changedPath} is outside the planned files`);
  if (!["add", "modify", "delete"].includes(value.operation)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, `changes[${index}].operation is invalid`);
  if (typeof value.diff !== "string" || value.diff.length === 0 || Buffer.byteLength(value.diff, "utf8") > MAX_FILE_DIFF_BYTES) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, `changes[${index}].diff is invalid or too large`);
  ensureNoSecret(value.diff, `changes[${index}].diff`);
  if (value.content !== undefined) {
    if (typeof value.content !== "string" || Buffer.byteLength(value.content, "utf8") > MAX_FILE_DIFF_BYTES) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, `changes[${index}].content is invalid or too large`);
    ensureNoSecret(value.content, `changes[${index}].content`);
    if (value.operation === "delete") fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "delete changes cannot carry content");
    const actual = sha256(value.content);
    if (value.after_digest !== undefined && value.after_digest !== actual) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "after_digest does not match content");
    value.after_digest = actual;
  }
  if (value.before_digest !== undefined) digest(value.before_digest, `changes[${index}].before_digest`);
  if (value.after_digest !== undefined) digest(value.after_digest, `changes[${index}].after_digest`);
  if (value.operation === "delete" && value.after_digest !== undefined) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "delete changes cannot carry after_digest");
  return Object.freeze({ path: changedPath, operation: value.operation, before_digest: value.before_digest ?? null, after_digest: value.after_digest ?? null, diff: value.diff });
}

/**
 * Build a content-addressed patch proposal from untrusted structured output.
 * This function has no process, filesystem, model, network, or GitHub access.
 * It returns a proposal whose test/conformance status is explicitly not-run.
 */
export function createPatchProposal({ job, plan, advisory, snapshot, policy, changes, tests, conformance = [], createdAt = undefined } = {}) {
  try { validateMaintenancePlan(plan); validateAdvisory(advisory); validateRepositorySnapshot(snapshot); validateMaintenancePolicy(policy); if (job !== undefined) validateMaintenanceJob(job); }
  catch { fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "maintenance inputs are invalid"); }
  if (policy.mode !== "draft_pr" || !plan.authority?.operations?.includes("write_patch")) fail(PATCH_AGENT_ERROR_CODES.AUTHORITY_DENIED, "plan does not authorize patch proposals");
  if (plan.organization_id !== snapshot.organization_id || plan.repository_id !== snapshot.repository_id || plan.advisory_id !== advisory.advisory_id || plan.base_commit !== snapshot.base_commit) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "patch bindings do not match");
  if (job !== undefined && (job.organization_id !== plan.organization_id || job.repository_id !== plan.repository_id || job.plan_id !== plan.plan_id || job.advisory_id !== advisory.advisory_id)) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "job bindings do not match");
  if (!Array.isArray(changes) || changes.length === 0 || changes.length > Math.min(MAX_FILES, policy.max_files)) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, "changes are empty or exceed the policy limit");
  const allowedPaths = new Set(plan.files);
  const normalizedChanges = changes.map((item, index) => validateChange(item, index, allowedPaths));
  if (new Set(normalizedChanges.map((item) => item.path)).size !== normalizedChanges.length) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "changed paths must be unique");
  const diffBytes = normalizedChanges.reduce((total, item) => total + Buffer.byteLength(item.diff, "utf8"), 0);
  if (diffBytes > MAX_DIFF_BYTES) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, "patch diff exceeds the bounded limit");
  const normalizedTests = (tests ?? [{ id: "repository.tests", kind: "repository", required: true }]).map(validateTest);
  if (normalizedTests.length > MAX_TESTS || new Set(normalizedTests.map((item) => item.id)).size !== normalizedTests.length) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, "tests are duplicated or exceed the bounded limit");
  if (!Array.isArray(conformance) || conformance.length > MAX_CONFORMANCE || new Set(conformance.map((item) => item.id)).size !== conformance.length) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, "conformance plan is duplicated or too large");
  const normalizedConformance = conformance.map(validateConformance);
  const changedPaths = normalizedChanges.map((item) => item.path).sort();
  const patchMaterial = { schema_version: 1, base_commit: snapshot.base_commit, changes: normalizedChanges.map(({ content: _content, ...item }) => item) };
  const patchDigest = sha256(patchMaterial);
  const diffDigest = sha256({ schema_version: 1, diffs: normalizedChanges.map((item) => ({ path: item.path, diff: item.diff })) });
  const created = timestamp(createdAt ?? new Date().toISOString());
  const identity = sha256({ plan_id: plan.plan_id, advisory_id: advisory.advisory_id, base_commit: snapshot.base_commit, patch_digest: patchDigest, diff_digest: diffDigest });
  const proposal = {
    schema_version: 1, kind: "agentpass.maintenance.patch-proposal", proposal_id: `proposal-${identity.slice(0, 32)}`,
    organization_id: plan.organization_id, app_id: plan.app_id, repository_id: plan.repository_id, job_id: job?.job_id ?? `job-${sha256(plan.plan_id).slice(0, 32)}`,
    plan_id: plan.plan_id, advisory_id: advisory.advisory_id, base_commit: snapshot.base_commit, branch: plan.branch,
    changed_paths: changedPaths, patch_digest: patchDigest, diff_digest: diffDigest, changes: normalizedChanges,
    tests: normalizedTests, conformance: normalizedConformance, verification_status: "not_run",
    uncertainty: ["live LLM execution not_proven", "GitHub connector execution not_proven", "tests and provider conformance not_run"], created_at: created,
    authority: Object.freeze({ operations: ["read_source", "write_patch"], shell: false, credentials: false, network: false })
  };
  try { validatePatchProposal(proposal); } catch { fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "generated patch proposal failed contract validation"); }
  return Object.freeze(proposal);
}

export const proposeBoundedPatch = createPatchProposal;
export const createMaintenancePatchAgent = () => Object.freeze({ propose: createPatchProposal });

/** Compatibility adapter for the original fixture-facing proposal shape. It
 * accepts only a bounded command label (never executes it) and keeps the
 * result explicitly not_proven. New callers should use createPatchProposal. */
export function proposeMaintenancePatch({ advisory, snapshot, policy, files, testCommands = [] } = {}) {
  if (!advisory || typeof advisory !== "object" || !snapshot || typeof snapshot !== "object" || !policy || typeof policy !== "object" || !Array.isArray(files) || files.length === 0 || files.length > 32) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "maintenance patch input is invalid");
  const normalized = files.map((item, index) => {
    object(item, `files[${index}]`); rejectForbiddenFields(item, `files[${index}]`);
    if (typeof item.path !== "string" || !/^(?!\.)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u.test(item.path) || DENIED_PATH.test(item.path) || DENIED_DIRECTORY.test(item.path)) fail(PATCH_AGENT_ERROR_CODES.PATH_DENIED, `files[${index}].path is denied`);
    if (EXECUTABLE_PATH.test(item.path)) fail(PATCH_AGENT_ERROR_CODES.EXECUTABLE_REJECTED, `files[${index}].path is executable`);
    digest(item.before_digest, `files[${index}].before_digest`); digest(item.after_digest, `files[${index}].after_digest`);
    if (typeof item.patch !== "string" || item.patch.length === 0 || Buffer.byteLength(item.patch, "utf8") > MAX_FILE_DIFF_BYTES) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, `files[${index}].patch is invalid`);
    ensureNoSecret(item.patch, `files[${index}].patch`);
    return Object.freeze({ path: item.path, before_digest: item.before_digest, after_digest: item.after_digest, patch: item.patch });
  }).sort((left, right) => left.path.localeCompare(right.path));
  if (new Set(normalized.map((item) => item.path)).size !== normalized.length) fail(PATCH_AGENT_ERROR_CODES.INVALID_INPUT, "files must be unique");
  if (!Array.isArray(testCommands) || testCommands.length > MAX_TESTS) fail(PATCH_AGENT_ERROR_CODES.LIMIT_EXCEEDED, "test command plan is too large");
  const commands = [...new Set(testCommands)].map((value) => {
    if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[;&|`$<>\0\n\r]/u.test(value)) fail(PATCH_AGENT_ERROR_CODES.EXECUTABLE_REJECTED, "test command is not a bounded label");
    return value;
  });
  const patchDigest = sha256({ schema_version: 1, advisory, snapshot, policy, files: normalized, test_commands: commands });
  return Object.freeze({ version: 1, status: "proposed", patch_digest: patchDigest, advisory_id: advisory.advisory_id, source_commit: snapshot.base_commit, policy_generation: policy.generation, files: normalized, test_commands: commands, external_qualification: "not_proven" });
}
