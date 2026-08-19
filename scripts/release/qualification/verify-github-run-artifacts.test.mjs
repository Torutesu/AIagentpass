import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { validateArtifact, validateQualificationMetadata, validateSuccessfulJobs, validateWorkflowRun, verifyDownloadedArtifactDigest } from "./verify-github-run-artifacts.mjs";

const repository = "Torutesu/AIagentpass";
const sourceSha = "0123456789abcdef0123456789abcdef01234567";
const cloudRunId = "1001";
const macosRunId = "1002";
const digest = (character) => `sha256:${character.repeat(64)}`;

function run({ id, name, path, sha = sourceSha }) {
  return {
    id: Number(id),
    name,
    path,
    event: "workflow_dispatch",
    status: "completed",
    conclusion: "success",
    head_branch: "main",
    head_sha: sha,
    repository: { full_name: repository },
    head_repository: { full_name: repository }
  };
}

function job(id, name, runId) {
  return { id, name, run_id: Number(runId), status: "completed", conclusion: "success", completed_at: "2026-08-20T00:00:00Z" };
}

function artifact(id, name, runId, character) {
  return {
    id,
    name,
    digest: digest(character),
    size_in_bytes: 42,
    expired: false,
    created_at: "2026-08-20T00:00:00Z",
    updated_at: "2026-08-20T00:00:00Z",
    workflow_run: { id: Number(runId) },
    archive_download_url: `https://api.github.com/repos/${repository}/actions/artifacts/${id}/zip`
  };
}

function metadata() {
  return {
    repository,
    sourceSha,
    cloud: {
      runId: cloudRunId,
      run: run({ id: cloudRunId, name: "Cloud production qualification", path: ".github/workflows/cloud-production-qualification.yml" }),
      jobs: { total_count: 1, jobs: [job(2001, "qualify", cloudRunId)] },
      artifacts: { total_count: 1, artifacts: [artifact(3001, `cloud-production-qualification-${sourceSha}`, cloudRunId, "a")] }
    },
    macos: {
      runId: macosRunId,
      run: run({ id: macosRunId, name: "macOS hardware qualification evidence", path: ".github/workflows/macos-hardware-qualification.yml" }),
      jobs: { total_count: 2, jobs: [job(2002, "arm64", macosRunId), job(2003, "x86_64", macosRunId)] },
      artifacts: { total_count: 2, artifacts: [
        artifact(3002, `macos-hardware-qualification-arm64-${sourceSha}`, macosRunId, "b"),
        artifact(3003, `macos-hardware-qualification-x86_64-${sourceSha}`, macosRunId, "c")
      ] }
    }
  };
}

test("accepts successful exact Cloud and macOS qualification identities", () => {
  const value = metadata();
  const result = validateQualificationMetadata(value);
  assert.equal(result.source_sha, sourceSha);
  assert.equal(result.cloud.artifact.digest, digest("a"));
  assert.deepEqual(result.macos.jobs.map((item) => item.name), ["arm64", "x86_64"]);
});

test("rejects a qualification run from a different source SHA", () => {
  const value = metadata();
  value.cloud.run.head_sha = "f".repeat(40);
  assert.throws(() => validateQualificationMetadata(value), /source SHA/u);
});

test("rejects an incomplete or unsuccessful required job", () => {
  const value = metadata();
  value.macos.jobs.jobs[1].conclusion = "failure";
  assert.throws(() => validateQualificationMetadata(value), /not successful/u);
  const missing = metadata();
  missing.macos.jobs.jobs.pop();
  missing.macos.jobs.total_count = 1;
  assert.throws(() => validateQualificationMetadata(missing), /missing or duplicated/u);
});

test("rejects expired, duplicated, or non-canonical artifacts", () => {
  const value = metadata();
  value.cloud.artifacts.artifacts[0].expired = true;
  assert.throws(() => validateQualificationMetadata(value), /live and bound/u);
  const duplicate = metadata();
  duplicate.cloud.artifacts.artifacts.push({ ...duplicate.cloud.artifacts.artifacts[0], id: 3004 });
  duplicate.cloud.artifacts.total_count = 2;
  assert.throws(() => validateQualificationMetadata(duplicate), /missing or duplicated/u);
  const wrongUrl = metadata();
  wrongUrl.cloud.artifacts.artifacts[0].archive_download_url = "https://example.invalid/archive.zip";
  assert.throws(() => validateQualificationMetadata(wrongUrl), /canonical/u);
});

test("requires complete GitHub API collections and full artifact digests", () => {
  const value = metadata();
  value.cloud.artifacts.total_count = 2;
  assert.throws(() => validateQualificationMetadata(value), /incomplete or paginated/u);
  const invalidDigest = metadata();
  invalidDigest.cloud.artifacts.artifacts[0].digest = "latest";
  assert.throws(() => validateQualificationMetadata(invalidDigest), /digest is invalid/u);
});

test("checks the downloaded archive bytes against GitHub's artifact digest", () => {
  const bytes = Buffer.from("retained qualification evidence");
  const expected = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  assert.equal(verifyDownloadedArtifactDigest(bytes, expected), expected);
  assert.throws(() => verifyDownloadedArtifactDigest(bytes, digest("f")), /downloaded qualification artifact digest mismatch/u);
});

test("job and artifact validators bind IDs to the selected workflow run", () => {
  const value = metadata();
  assert.throws(() => validateWorkflowRun(value.cloud.run, {
    repository,
    runId: "9999",
    sourceSha,
    workflow: { name: "Cloud production qualification", path: ".github/workflows/cloud-production-qualification.yml" }
  }), /does not match/u);
  assert.throws(() => validateSuccessfulJobs(value.cloud.jobs, {
    runId: "9999",
    workflow: { jobs: ["qualify"] }
  }), /not successful/u);
  assert.throws(() => validateArtifact(value.cloud.artifacts, {
    repository,
    runId: "9999",
    name: `cloud-production-qualification-${sourceSha}`,
    outputName: "cloud-production-qualification"
  }), /live and bound/u);
});
