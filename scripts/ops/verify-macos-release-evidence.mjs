import { readFile } from "node:fs/promises";

const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TEAM = /^[A-Z0-9]{10}$/u;
const REQUIRED = ["signing", "notarization", "stapling", "gatekeeper"];

function emit(value, code, message) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
  if (message) process.stderr.write(`${message}\n`);
  process.exitCode = code;
}

function unknown(reason) {
  return { status: "unknown", reason };
}

function reject(reason, details = []) {
  return { status: "failed", reason, details };
}

function validate(value, candidateCommit, candidateDigest) {
  if (!value || value.schema_version !== 1 || !value.candidate || typeof value.candidate !== "object") {
    return reject("evidence_schema_invalid");
  }
  const failures = [];
  if (!COMMIT.test(value.candidate.commit_sha ?? "")) failures.push("candidate_commit_invalid");
  if (!DIGEST.test(value.candidate.artifact_digest ?? "")) failures.push("candidate_digest_invalid");
  if (candidateCommit !== undefined && value.candidate.commit_sha !== candidateCommit) failures.push("candidate_commit_mismatch");
  if (candidateDigest !== undefined && value.candidate.artifact_digest !== candidateDigest) failures.push("candidate_digest_mismatch");
  if (typeof value.package?.name !== "string" || !/^[A-Za-z0-9._-]+\.pkg$/u.test(value.package.name)) failures.push("package_name_invalid");
  if (value.package?.artifact_digest !== value.candidate.artifact_digest) failures.push("package_digest_mismatch");
  if (value.signing?.status !== "verified") failures.push("codesign_not_verified");
  if (typeof value.signing?.identity !== "string" || !value.signing.identity.startsWith("Developer ID Application:")) failures.push("developer_id_identity_invalid");
  if (!TEAM.test(value.signing?.team_id ?? "")) failures.push("team_id_invalid");
  if (typeof value.signing?.bundle_id !== "string" || !/^[a-z][A-Za-z0-9.-]+$/u.test(value.signing.bundle_id)) failures.push("bundle_id_invalid");
  if (value.notarization?.status !== "accepted" || typeof value.notarization.ticket_id !== "string" || value.notarization.ticket_id.length < 8) failures.push("notarization_not_accepted");
  if (value.stapling?.status !== "verified") failures.push("stapling_not_verified");
  if (value.gatekeeper?.status !== "accepted") failures.push("gatekeeper_not_accepted");
  for (const name of REQUIRED) if (!value[name] || typeof value[name] !== "object") failures.push(`${name}_evidence_missing`);
  return failures.length === 0 ? { status: "passed", candidate: value.candidate, package: value.package, signing: value.signing, notarization: value.notarization, stapling: value.stapling, gatekeeper: value.gatekeeper } : reject("evidence_rejected", failures);
}

async function main() {
  const [path, ...args] = process.argv.slice(2);
  const commitIndex = args.indexOf("--candidate-commit-sha");
  const digestIndex = args.indexOf("--candidate-artifact-digest");
  const candidateCommit = commitIndex >= 0 ? args[commitIndex + 1] : undefined;
  const candidateDigest = digestIndex >= 0 ? args[digestIndex + 1] : undefined;
  if (!path || (commitIndex >= 0 && !candidateCommit) || (digestIndex >= 0 && !candidateDigest)) {
    emit(unknown("evidence_path_or_binding_missing"), 2, "macOS release evidence is unknown");
    return;
  }
  let value;
  try { value = JSON.parse(await readFile(path, "utf8")); }
  catch (error) {
    if (error?.code === "ENOENT") { emit(unknown("evidence_file_missing"), 2, "macOS release evidence is unknown"); return; }
    emit(reject("evidence_json_invalid"), 1, "macOS release evidence is invalid");
    return;
  }
  const report = validate(value, candidateCommit, candidateDigest);
  emit(report, report.status === "passed" ? 0 : report.status === "unknown" ? 2 : 1, report.status === "passed" ? undefined : `macOS release evidence ${report.status}`);
}

main().catch(() => emit(reject("verification_error"), 1, "macOS release evidence verification failed"));
