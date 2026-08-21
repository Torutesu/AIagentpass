import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";

const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FILE_SHA256 = /^[0-9a-f]{64}$/u;
const VALID_STATUSES = new Set(["passed", "failed", "unknown"]);
const REQUIRED_CHECKS = [
  "native_audit_delivery",
  "cloud_production_deploy",
  "real_postgresql",
  "developer_id_notarization",
  "hardware_qualification",
];

function output(value, exitCode, message) {
  console.log(JSON.stringify(value));
  if (message) console.error(message);
  process.exitCode = exitCode;
}

function checkReport(status, reason) {
  return reason ? { status, reason } : { status };
}

function parseOptions(args) {
  const options = { evidencePath: args[0] };
  for (let index = 1; index < args.length; index += 1) {
    if (args[index] === "--candidate-commit-sha") options.candidateCommitSha = args[++index];
    else if (args[index] === "--candidate-artifact-digest") options.candidateArtifactDigest = args[++index];
    else options.invalidOption = true;
  }
  return options;
}

function emptyChecks(reason = "evidence_missing") {
  return Object.fromEntries(REQUIRED_CHECKS.map((name) => [name, checkReport("unknown", reason)]));
}

function overallStatus(checks, candidateIssues) {
  if (candidateIssues.some((issue) => issue.severity === "failed")) return "failed";
  const statuses = REQUIRED_CHECKS.map((name) => checks[name].status);
  if (statuses.includes("failed")) return "failed";
  if (statuses.includes("unknown")) return "unknown";
  return "passed";
}

function exitCode(status) {
  return status === "passed" ? 0 : status === "failed" ? 1 : 2;
}

function summarizeCandidate(candidate, options) {
  const candidateIssues = [];
  const commitSha = candidate?.commit_sha;
  const artifactDigest = candidate?.artifact_digest;

  if (commitSha === undefined || artifactDigest === undefined) {
    candidateIssues.push({ severity: "unknown", reason: "candidate_binding_missing" });
  } else {
    if (!COMMIT_SHA.test(commitSha)) candidateIssues.push({ severity: "failed", reason: "candidate_commit_sha_invalid" });
    if (!SHA256_DIGEST.test(artifactDigest)) candidateIssues.push({ severity: "failed", reason: "candidate_artifact_digest_invalid" });
  }
  if (options.candidateCommitSha !== undefined && options.candidateCommitSha !== commitSha) {
    candidateIssues.push({ severity: "failed", reason: "candidate_commit_sha_mismatch" });
  }
  if (options.candidateArtifactDigest !== undefined && options.candidateArtifactDigest !== artifactDigest) {
    candidateIssues.push({ severity: "failed", reason: "candidate_artifact_digest_mismatch" });
  }
  return { candidateIssues, commitSha, artifactDigest };
}

async function validateEvidenceFile(root, reference, expectedDigest) {
  if (typeof reference !== "string" || reference.length === 0 || reference.startsWith("/") || reference.split(/[\\/]+/u).some((part) => part === ".." || part === "")) return "evidence_ref_invalid";
  const path = resolve(root, reference);
  if (path !== root && !path.startsWith(`${root}${sep}`)) return "evidence_ref_outside_root";
  let stat;
  try { stat = await lstat(path); } catch (error) { return error?.code === "ENOENT" ? "evidence_file_missing" : "evidence_file_unreadable"; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > 16 * 1024 * 1024) return "evidence_file_unsafe";
  const digest = createHash("sha256").update(await readFile(path)).digest("hex");
  return digest === expectedDigest ? undefined : "evidence_digest_mismatch";
}

async function validateChecks(rawChecks, candidateSummary, evidenceRoot) {
  const checks = {};
  for (const name of REQUIRED_CHECKS) {
    const raw = rawChecks?.[name];
    if (!raw || typeof raw !== "object") {
      checks[name] = checkReport("unknown", "check_evidence_missing");
      continue;
    }
    if (!VALID_STATUSES.has(raw.status)) {
      checks[name] = checkReport("failed", "check_status_invalid");
      continue;
    }
    if (raw.status !== "passed") {
      checks[name] = checkReport(raw.status, raw.status === "failed" ? "producer_reported_failure" : "producer_reported_unknown");
      continue;
    }
    if (typeof raw.evidence_ref !== "string" || raw.evidence_ref.length === 0 || !FILE_SHA256.test(raw.evidence_sha256 ?? "")) {
      checks[name] = checkReport("failed", "evidence_ref_missing");
      continue;
    }
    const evidenceFailure = await validateEvidenceFile(evidenceRoot, raw.evidence_ref, raw.evidence_sha256);
    if (evidenceFailure) {
      checks[name] = checkReport("failed", evidenceFailure);
      continue;
    }
    if (raw.commit_sha !== candidateSummary.commitSha) {
      checks[name] = checkReport("failed", "check_commit_sha_mismatch");
      continue;
    }
    if (raw.artifact_digest !== candidateSummary.artifactDigest) {
      checks[name] = checkReport("failed", "check_artifact_digest_mismatch");
      continue;
    }
    if (!COMMIT_SHA.test(raw.commit_sha) || !SHA256_DIGEST.test(raw.artifact_digest)) {
      checks[name] = checkReport("failed", "check_binding_invalid");
      continue;
    }
    checks[name] = checkReport("passed");
  }
  return checks;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  if (options.invalidOption || !options.evidencePath) {
    output({ status: "unknown", checks: emptyChecks("evidence_path_or_option_missing") }, 2, "release preflight unknown: evidence path is required");
    return;
  }

  let evidence;
  try {
    evidence = JSON.parse(await readFile(options.evidencePath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      output({ status: "unknown", checks: emptyChecks() }, 2, "release preflight unknown: evidence file was not found");
      return;
    }
    output({ status: "failed", reason: "evidence_json_invalid", checks: emptyChecks("evidence_json_invalid") }, 1, "release preflight failed: evidence JSON is invalid");
    return;
  }

  if (evidence?.schema_version !== 1 || !evidence?.candidate || typeof evidence.candidate !== "object") {
    output({ status: "failed", reason: "evidence_schema_invalid", checks: emptyChecks("evidence_schema_invalid") }, 1, "release preflight failed: evidence schema is invalid");
    return;
  }

  const candidateSummary = summarizeCandidate(evidence.candidate, options);
  const checks = await validateChecks(evidence.checks, candidateSummary, dirname(resolve(options.evidencePath)));
  const status = overallStatus(checks, candidateSummary.candidateIssues);
  const report = {
    status,
    schema_version: 1,
    candidate: {
      commit_sha: candidateSummary.commitSha ?? null,
      artifact_digest: candidateSummary.artifactDigest ?? null,
    },
    checks,
  };
  const message = status === "passed"
    ? undefined
    : `release preflight ${status}: all five production gates must be passed for promotion`;
  output(report, exitCode(status), message);
}

main().catch(() => {
  output({ status: "failed", reason: "verification_error" }, 1, "release preflight failed: verification failed");
});
