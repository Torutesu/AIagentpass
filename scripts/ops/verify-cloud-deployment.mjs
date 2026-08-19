import { readFile } from "node:fs/promises";

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;

function report(value, exitCode, message) {
  console.log(JSON.stringify(value));
  if (message) console.error(message);
  process.exitCode = exitCode;
}

function unknown(reason) {
  return {
    status: "unknown",
    reason,
  };
}

function validate(evidence) {
  const failures = [];
  if (evidence?.status !== "verified") failures.push("status_not_verified");
  if (evidence?.environment !== "production") failures.push("environment_not_production");
  if (evidence?.service !== "agentpass-cloud-api") failures.push("service_mismatch");
  if (typeof evidence?.revision !== "string" || evidence.revision.length === 0) failures.push("revision_missing");
  if (!COMMIT_SHA.test(evidence?.commit_sha ?? "")) failures.push("commit_sha_invalid");
  if (!SHA256_DIGEST.test(evidence?.artifact_digest ?? "")) failures.push("artifact_digest_invalid");
  if (evidence?.health?.status !== "ready") failures.push("health_not_ready");
  if (typeof evidence?.health?.url !== "string" || !evidence.health.url.startsWith("https://")) failures.push("health_url_invalid");
  if (typeof evidence?.health?.checked_at !== "string" || Number.isNaN(Date.parse(evidence.health.checked_at))) failures.push("health_timestamp_invalid");
  return failures;
}

async function main() {
  const evidencePath = process.argv[2];
  if (!evidencePath) {
    report(unknown("evidence_path_missing"), 2, "evidence unknown: path was not provided");
    return;
  }

  let evidence;
  try {
    evidence = JSON.parse(await readFile(evidencePath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      report(unknown("evidence_file_missing"), 2, "evidence unknown: file was not found");
      return;
    }
    report({ status: "failed", reason: "evidence_json_invalid" }, 1, "evidence rejected: JSON could not be read");
    return;
  }

  const failures = validate(evidence);
  if (failures.length > 0) {
    report({ status: "failed", reason: "evidence_rejected", checks: failures }, 1, "evidence rejected: production deployment evidence is invalid");
    return;
  }

  report({
    status: "verified",
    environment: "production",
    service: evidence.service,
    revision: evidence.revision,
    commit_sha: evidence.commit_sha,
    artifact_digest: evidence.artifact_digest,
    health: {
      status: "ready",
      url: evidence.health.url,
      checked_at: evidence.health.checked_at,
    },
  }, 0);
}

main().catch(() => {
  report({ status: "failed", reason: "verification_error" }, 1, "evidence rejected: verification failed");
});
