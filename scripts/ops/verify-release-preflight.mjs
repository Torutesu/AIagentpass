import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { verifyPostgresGateEvidence } from "../qualification/aggregate-postgres-external.mjs";

const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FILE_SHA256 = /^[0-9a-f]{64}$/u;
const VALID_STATUSES = new Set(["passed", "failed", "unknown"]);
const REQUIRED_CHECKS = [
  "native_audit_delivery",
  "cloud_production_deploy",
  "real_postgresql",
  "developer_id_signing",
  "apple_notarization",
  "hardware_qualification",
  "external_qualification_provenance",
];
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DEVELOPER_ID_INSTALLER = /^Developer ID Installer: [^\r\n()]+ \([A-Z0-9]{10}\)$/u;
const CHECK_REQUIREMENTS = Object.freeze({
  real_postgresql: Object.freeze(["source_tree", "ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id", "qualification_job_name"]),
  developer_id_signing: Object.freeze(["team_id", "signature_identity", "signature_verified"]),
  apple_notarization: Object.freeze(["notary_submission_id", "stapled", "stapler_verified", "gatekeeper_verified"]),
  external_qualification_provenance: Object.freeze(["source_tree", "ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id", "qualification_job_name"]),
});
const EXTERNAL_PROVENANCE_KIND = "agentpass-external-qualification-artifact-provenance";
const EXTERNAL_PROVENANCE_KEYS = [
  "artifacts", "canonical_ci_run_attempt", "canonical_ci_run_id", "evidence_sha256", "kind",
  "provenance_job_id", "provenance_job_name", "repository", "run_attempt", "run_id", "schema_version",
  "source_commit", "source_tree",
];
const EXTERNAL_ARTIFACT_KEYS = [
  "archive_bytes", "archive_sha256", "artifact_id", "digest", "evidence_members", "job", "job_id",
  "job_name", "name", "run_attempt", "run_id", "source_commit", "source_tree",
];
const EXTERNAL_ARTIFACT_JOBS = ["kms", "platform-auth", "webauthn", "postgres-authority-16", "postgres-authority-17", "postgres-gate"];

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
  const start = args[0] === "--verify-result" ? 2 : 1;
  if (args[0] === "--verify-result") options.resultPath = args[1];
  for (let index = start; index < args.length; index += 1) {
    if (args[index] === "--candidate-commit-sha") options.candidateCommitSha = args[++index];
    else if (args[index] === "--candidate-tree-sha") options.candidateTreeSha = args[++index];
    else if (args[index] === "--candidate-artifact-digest") options.candidateArtifactDigest = args[++index];
    else options.invalidOption = true;
  }
  return options;
}

export function assertPreflightResult(result, {
  expectedCommit,
  expectedTree,
  expectedArtifactDigest,
} = {}) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("release preflight result is not an object");
  if (result.schema_version !== 1 || result.status !== "passed") throw new Error("release preflight result is not a passed v1 result");
  if (!COMMIT_SHA.test(result.candidate?.commit_sha ?? "") || result.candidate.commit_sha !== expectedCommit) throw new Error("release preflight result source commit is mismatched");
  if (!COMMIT_SHA.test(result.candidate?.tree_sha ?? "") || result.candidate.tree_sha !== expectedTree) throw new Error("release preflight result source tree is mismatched");
  if (!SHA256_DIGEST.test(result.candidate?.artifact_digest ?? "") || result.candidate.artifact_digest !== expectedArtifactDigest) throw new Error("release preflight result artifact digest is mismatched");
  if (!FILE_SHA256.test(result.evidence_sha256 ?? "")) throw new Error("release preflight result evidence digest is missing");
  const actualChecks = result.checks && typeof result.checks === "object" && !Array.isArray(result.checks)
    ? Object.keys(result.checks).sort()
    : [];
  const expectedChecks = [...REQUIRED_CHECKS].sort();
  if (JSON.stringify(actualChecks) !== JSON.stringify(expectedChecks)) throw new Error("release preflight result check inventory is not exactly seven gates");
  for (const name of REQUIRED_CHECKS) {
    if (result.checks[name]?.status !== "passed") throw new Error(`release preflight gate is not passed: ${name}`);
  }
  return result;
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
  const treeSha = candidate?.tree_sha;
  const artifactDigest = candidate?.artifact_digest;

  if (commitSha === undefined || treeSha === undefined || artifactDigest === undefined) {
    candidateIssues.push({ severity: "unknown", reason: "candidate_binding_missing" });
  } else {
    if (!COMMIT_SHA.test(commitSha)) candidateIssues.push({ severity: "failed", reason: "candidate_commit_sha_invalid" });
    if (!COMMIT_SHA.test(treeSha)) candidateIssues.push({ severity: "failed", reason: "candidate_tree_sha_invalid" });
    if (!SHA256_DIGEST.test(artifactDigest)) candidateIssues.push({ severity: "failed", reason: "candidate_artifact_digest_invalid" });
  }
  if (options.candidateCommitSha !== undefined && options.candidateCommitSha !== commitSha) {
    candidateIssues.push({ severity: "failed", reason: "candidate_commit_sha_mismatch" });
  }
  if (options.candidateTreeSha !== undefined && options.candidateTreeSha !== treeSha) {
    candidateIssues.push({ severity: "failed", reason: "candidate_tree_sha_mismatch" });
  }
  if (options.candidateArtifactDigest !== undefined && options.candidateArtifactDigest !== artifactDigest) {
    candidateIssues.push({ severity: "failed", reason: "candidate_artifact_digest_mismatch" });
  }
  return { candidateIssues, commitSha, treeSha, artifactDigest };
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

async function validateIndependentVerification(raw, evidenceRoot) {
  if (raw.evidence_origin !== "protected_external" || raw.execution_mode !== "protected_external"
    || raw.verifier_kind !== "independent_protected_verifier" || raw.verifier_status !== "verified") return "independent_verification_missing";
  if (typeof raw.verification_ref !== "string" || raw.verification_ref === raw.evidence_ref || !FILE_SHA256.test(raw.verification_sha256 ?? "")) return "verification_ref_missing";
  return validateEvidenceFile(evidenceRoot, raw.verification_ref, raw.verification_sha256);
}

async function validatePostgresGateEvidence(raw, candidateSummary, evidenceRoot) {
  if (raw.status !== "passed") return undefined;
  let report;
  try { report = JSON.parse(await readFile(resolve(evidenceRoot, raw.evidence_ref), "utf8")); }
  catch { return "postgresql_gate_json_invalid"; }
  try {
    verifyPostgresGateEvidence(report, {
      sourceCommit: candidateSummary.commitSha,
      sourceTree: raw.source_tree,
      releaseArtifactSha256: candidateSummary.artifactDigest?.slice("sha256:".length),
      runId: raw.qualification_run_id,
      runAttempt: raw.qualification_run_attempt,
      jobId: raw.qualification_job_id,
      ciRunId: raw.ci_run_id,
      ciRunAttempt: raw.ci_run_attempt,
      qualificationJobName: raw.qualification_job_name
    });
  } catch { return "postgresql_gate_contract_invalid"; }
  return undefined;
}

async function validateExternalProvenanceVerification(raw, candidateSummary, evidenceRoot) {
  let report;
  try { report = JSON.parse(await readFile(resolve(evidenceRoot, raw.verification_ref), "utf8")); }
  catch { return "external_provenance_json_invalid"; }
  if (!report || typeof report !== "object" || Array.isArray(report)
    || JSON.stringify(Object.keys(report).sort()) !== JSON.stringify(EXTERNAL_PROVENANCE_KEYS.slice().sort())
    || report.schema_version !== 1
    || report.kind !== EXTERNAL_PROVENANCE_KIND
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(report.repository ?? "")
    || report.source_commit !== candidateSummary.commitSha
    || report.source_tree !== raw.source_tree
    || report.run_id !== raw.qualification_run_id
    || report.run_attempt !== raw.qualification_run_attempt
    || report.canonical_ci_run_id !== raw.ci_run_id
    || report.canonical_ci_run_attempt !== raw.ci_run_attempt
    || report.provenance_job_id !== raw.qualification_job_id
    || report.provenance_job_name !== raw.qualification_job_name
    || !FILE_SHA256.test(report.evidence_sha256 ?? "")
    || !Array.isArray(report.artifacts)
    || report.artifacts.length !== EXTERNAL_ARTIFACT_JOBS.length) return "external_provenance_contract_invalid";

  const seenJobs = new Set();
  const seenArtifactIds = new Set();
  for (const [index, artifact] of report.artifacts.entries()) {
    if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)
      || JSON.stringify(Object.keys(artifact).sort()) !== JSON.stringify(EXTERNAL_ARTIFACT_KEYS.slice().sort())
      || !EXTERNAL_ARTIFACT_JOBS.includes(artifact.job)
      || seenJobs.has(artifact.job)
      || artifact.job_name !== artifact.job
      || !RUN_ID.test(String(artifact.job_id))
      || !RUN_ID.test(String(artifact.artifact_id))
      || seenArtifactIds.has(String(artifact.artifact_id))
      || !SHA256_DIGEST.test(artifact.digest ?? "")
      || !FILE_SHA256.test(artifact.archive_sha256 ?? "")
      || !Number.isSafeInteger(artifact.archive_bytes) || artifact.archive_bytes < 1
      || !Array.isArray(artifact.evidence_members) || artifact.evidence_members.length < 1
      || artifact.evidence_members.some((member) => typeof member !== "string" || member.length === 0)
      || artifact.run_id !== raw.qualification_run_id
      || artifact.run_attempt !== raw.qualification_run_attempt
      || artifact.source_commit !== candidateSummary.commitSha
      || artifact.source_tree !== raw.source_tree
      || !/^external-[A-Za-z0-9_-]+-[0-9a-f]{40}-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}$/u.test(artifact.name ?? "")) {
      return `external_provenance_artifact_${index}_invalid`;
    }
    seenJobs.add(artifact.job);
    seenArtifactIds.add(String(artifact.artifact_id));
  }
  if (seenJobs.size !== EXTERNAL_ARTIFACT_JOBS.length) return "external_provenance_artifact_inventory_invalid";
  const { evidence_sha256: _evidenceSha256, ...payload } = report;
  const expectedEvidenceSha256 = createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
  return report.evidence_sha256 === expectedEvidenceSha256 ? undefined : "external_provenance_digest_mismatch";
}

function validateCheckSpecificFields(name, raw) {
  for (const field of CHECK_REQUIREMENTS[name] ?? []) {
    if (!(field in raw)) return "check_specific_binding_missing";
  }
  if (name === "developer_id_signing"
    && (typeof raw.team_id !== "string" || !/^[A-Z0-9]{10}$/u.test(raw.team_id)
      || !DEVELOPER_ID_INSTALLER.test(raw.signature_identity ?? "")
      || !raw.signature_identity.endsWith(`(${raw.team_id})`)
      || raw.signature_verified !== true)) return "developer_id_binding_invalid";
  if (name === "apple_notarization"
    && (typeof raw.notary_submission_id !== "string" || !UUID.test(raw.notary_submission_id)
      || raw.stapled !== true || raw.stapler_verified !== true || raw.gatekeeper_verified !== true)) return "notarization_binding_invalid";
  if (name === "external_qualification_provenance"
    && ["ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id"].some((key) => typeof raw[key] !== "string" || !RUN_ID.test(raw[key]))) return "external_qualification_binding_invalid";
  if (["real_postgresql", "external_qualification_provenance"].includes(name) && !COMMIT_SHA.test(raw.source_tree ?? "")) return "source_tree_binding_invalid";
  if (name === "external_qualification_provenance" && raw.ci_run_id === raw.qualification_run_id) return "external_qualification_runs_not_distinct";
  return undefined;
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
    const verificationFailure = await validateIndependentVerification(raw, evidenceRoot);
    if (verificationFailure) {
      checks[name] = checkReport("failed", verificationFailure);
      continue;
    }
    const specificFailure = validateCheckSpecificFields(name, raw);
    if (specificFailure) {
      checks[name] = checkReport("failed", specificFailure);
      continue;
    }
    if (name === "external_qualification_provenance") {
      const provenanceFailure = await validateExternalProvenanceVerification(raw, candidateSummary, evidenceRoot);
      if (provenanceFailure) {
        checks[name] = checkReport("failed", provenanceFailure);
        continue;
      }
    }
    if (name === "real_postgresql") {
      const postgresFailure = await validatePostgresGateEvidence(raw, candidateSummary, evidenceRoot);
      if (postgresFailure) {
        checks[name] = checkReport("failed", postgresFailure);
        continue;
      }
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
  if (options.resultPath) {
    let result;
    try {
      result = JSON.parse(await readFile(options.resultPath, "utf8"));
      assertPreflightResult(result, {
        expectedCommit: options.candidateCommitSha,
        expectedTree: options.candidateTreeSha,
        expectedArtifactDigest: options.candidateArtifactDigest,
      });
    } catch (error) {
      output({ status: "failed", reason: "preflight_result_invalid" }, 1, `release preflight result failed: ${error?.message ?? "invalid result"}`);
      return;
    }
    output({ status: "passed", result }, 0);
    return;
  }
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

  const actualChecks = evidence.checks && typeof evidence.checks === "object" && !Array.isArray(evidence.checks)
    ? Object.keys(evidence.checks).sort()
    : [];
  if (actualChecks.length !== REQUIRED_CHECKS.length || actualChecks.some((name, index) => name !== [...REQUIRED_CHECKS].sort()[index])) {
    output({ status: "failed", reason: "check_inventory_invalid", checks: emptyChecks("check_inventory_invalid") }, 1, "release preflight failed: check inventory is invalid");
    return;
  }

  const candidateSummary = summarizeCandidate(evidence.candidate, options);
  const checks = await validateChecks(evidence.checks, candidateSummary, dirname(resolve(options.evidencePath)));
  const status = overallStatus(checks, candidateSummary.candidateIssues);
  const report = {
    status,
    schema_version: 1,
    evidence_sha256: createHash("sha256").update(await readFile(options.evidencePath)).digest("hex"),
    candidate: {
      commit_sha: candidateSummary.commitSha ?? null,
      tree_sha: candidateSummary.treeSha ?? null,
      artifact_digest: candidateSummary.artifactDigest ?? null,
    },
    checks,
  };
  const message = status === "passed"
    ? undefined
    : `release preflight ${status}: all seven production gates must be passed for promotion`;
  output(report, exitCode(status), message);
}

main().catch(() => {
  output({ status: "failed", reason: "verification_error" }, 1, "release preflight failed: verification failed");
});
