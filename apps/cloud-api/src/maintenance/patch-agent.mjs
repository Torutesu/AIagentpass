import crypto from "node:crypto";

const MAX_FILES = 32;
const MAX_PATCH_BYTES = 256 * 1024;
const SAFE_PATH = /^(?!\.)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;
const SECRET = /(private[_-]?key|api[_-]?key|access[_-]?token|secret|password|authorization)/iu;

export function proposeMaintenancePatch({ advisory, snapshot, policy, files, testCommands = [] } = {}) {
  if (!advisory || !snapshot || !policy || !Array.isArray(files) || files.length === 0 || files.length > MAX_FILES) throw new TypeError("maintenance patch input is invalid");
  const normalized = files.map((file) => {
    if (!file || typeof file !== "object" || typeof file.path !== "string" || !SAFE_PATH.test(file.path) || SECRET.test(file.path)
      || typeof file.before_digest !== "string" || !/^[0-9a-f]{64}$/u.test(file.before_digest)
      || typeof file.after_digest !== "string" || !/^[0-9a-f]{64}$/u.test(file.after_digest)
      || typeof file.patch !== "string" || Buffer.byteLength(file.patch, "utf8") > MAX_PATCH_BYTES) throw new TypeError("maintenance patch file is invalid");
    if (SECRET.test(file.patch) || /(^|\n)\+\+\+\s+(?:\/dev|\.\.)/u.test(file.patch)) throw new TypeError("maintenance patch contains unsafe material");
    return Object.freeze({ path: file.path, before_digest: file.before_digest, after_digest: file.after_digest, patch: file.patch });
  }).sort((a, b) => a.path.localeCompare(b.path));
  const commands = [...new Set(testCommands)].map((value) => {
    if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[;&|`$<>]/u.test(value)) throw new TypeError("maintenance test command is invalid");
    return value;
  });
  const digest = crypto.createHash("sha256").update(JSON.stringify({ advisory, snapshot, policy, files: normalized, test_commands: commands })).digest("hex");
  return Object.freeze({ version: 1, status: "proposed", patch_digest: digest, advisory_id: advisory.advisory_id, source_commit: snapshot.base_commit, policy_generation: policy.generation, files: normalized, test_commands: commands, external_qualification: "not_proven" });
}
