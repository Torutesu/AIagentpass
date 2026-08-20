import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createSignedQualificationBundle, verifySignedQualificationBundle } from "./qualification-bundle.mjs";
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

function canonical(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function bundleFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-qualification-bundle-"));
  const candidate = path.join(directory, "candidate");
  const qualification = path.join(directory, "qualification");
  const output = path.join(directory, "output");
  fs.mkdirSync(candidate, { mode: 0o700 });
  fs.mkdirSync(output, { mode: 0o700 });
  fs.mkdirSync(qualification, { mode: 0o700 });
  const packageName = "AgentPass-v1.2.3-macos-universal.pkg";
  const packageBytes = Buffer.from("signed package bytes");
  const packagePath = path.join(candidate, packageName);
  fs.writeFileSync(packagePath, packageBytes, { mode: 0o600 });
  const sourceSha = "a".repeat(40);
  const productSha = createHash("sha256").update(packageBytes).digest("hex");
  const manifestPath = path.join(candidate, "AgentPass-v1.2.3.release-manifest.json");
  fs.writeFileSync(manifestPath, canonical({
    schema_version: 4,
    product: "AgentPass",
    source: { commit: sourceSha, tree: "b".repeat(40), tag: "v1.2.3" },
    artifacts: [{ role: "product", name: packageName, bytes: packageBytes.length, sha256: productSha }]
  }), { mode: 0o600 });
  const runIds = {
    release_run_id: "1001",
    qualification_run_id: "1002",
    cloud_qualification_run_id: "1003",
    macos_qualification_run_id: "1004",
    ci_run_id: "1005"
  };
  const retained = [
    ["cloud-production-qualification", `cloud-production-qualification-${sourceSha}`],
    ["macos-hardware-qualification-arm64", `macos-hardware-qualification-arm64-${sourceSha}`],
    ["macos-hardware-qualification-x86_64", `macos-hardware-qualification-x86_64-${sourceSha}`]
  ];
  const records = [];
  for (const [index, [directoryName, artifactName]] of retained.entries()) {
    const laneDirectory = path.join(qualification, directoryName);
    fs.mkdirSync(laneDirectory, { mode: 0o700 });
    const archiveBytes = Buffer.from(`archive-${directoryName}`);
    const archiveSha = createHash("sha256").update(archiveBytes).digest("hex");
    const runId = index === 0 ? runIds.cloud_qualification_run_id : runIds.macos_qualification_run_id;
    fs.writeFileSync(path.join(laneDirectory, "artifact.zip"), archiveBytes, { mode: 0o600 });
    fs.writeFileSync(path.join(laneDirectory, "artifact-metadata.json"), canonical({
      id: String(3001 + index), name: artifactName, digest: `sha256:${archiveSha}`, size_in_bytes: archiveBytes.length,
      outputName: directoryName, archive_download_url: `https://api.github.com/repos/${repository}/actions/artifacts/${3001 + index}/zip`
    }), { mode: 0o600 });
    fs.writeFileSync(path.join(laneDirectory, "workflow-run.json"), canonical({
      id: Number(runId), repository: { full_name: repository }, head_repository: { full_name: repository }, head_sha: sourceSha,
      status: "completed", conclusion: "success"
    }), { mode: 0o600 });
    fs.writeFileSync(path.join(laneDirectory, "workflow-jobs.json"), canonical({ jobs: [] }), { mode: 0o600 });
    const metadataBytes = canonical({
      id: String(3001 + index), name: artifactName, digest: `sha256:${archiveSha}`, size_in_bytes: archiveBytes.length,
      outputName: directoryName, archive_download_url: `https://api.github.com/repos/${repository}/actions/artifacts/${3001 + index}/zip`
    });
    const workflowRunBytes = canonical({
      id: Number(runId), repository: { full_name: repository }, head_repository: { full_name: repository }, head_sha: sourceSha,
      status: "completed", conclusion: "success"
    });
    const workflowJobsBytes = canonical({ jobs: [] });
    records.push({
      name: artifactName, digest: `sha256:${archiveSha}`, run_id: runId, source_sha: sourceSha, archive: "artifact.zip",
      metadata_sha256: createHash("sha256").update(metadataBytes).digest("hex"),
      workflow_run_sha256: createHash("sha256").update(workflowRunBytes).digest("hex"),
      workflow_jobs_sha256: createHash("sha256").update(workflowJobsBytes).digest("hex")
    });
  }
  const verification = {
    schema_version: 1,
    repository,
    source_sha: sourceSha,
    cloud: records[0],
    macos: { run_id: runIds.macos_qualification_run_id, source_sha: sourceSha, artifacts: records.slice(1) }
  };
  fs.writeFileSync(path.join(qualification, "qualification-verification.json"), canonical(verification), { mode: 0o600 });
  const summaryPath = path.join(directory, "qualification-summary.json");
  const dispatchBindingPath = path.join(directory, "qualification-dispatch-binding.json");
  const summaryBytes = canonical({ ok: true, qualified: true, production: true });
  fs.writeFileSync(summaryPath, summaryBytes, { mode: 0o600 });
  fs.writeFileSync(dispatchBindingPath, canonical({
    schema_version: 1, release_run_id: runIds.release_run_id, qualification_run_id: runIds.qualification_run_id,
    candidate_artifact_name: "notarized-release-candidate", qualification_summary_sha256: createHash("sha256").update(summaryBytes).digest("hex")
  }), { mode: 0o600 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPath = path.join(directory, "bundle-private.pem");
  const publicKeyPath = path.join(directory, "bundle-public.pem");
  fs.writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  const fingerprint = `SHA256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  return { directory, manifestPath, packagePath, qualification, summaryPath, dispatchBindingPath, privateKeyPath, publicKeyPath, fingerprint, sourceSha, runIds };
}

function bundleOptions(fixture) {
  return {
    repository,
    sourceSha: fixture.sourceSha,
    releaseTag: "v1.2.3",
    candidateArtifactName: "notarized-release-candidate",
    candidateArtifactDigest: digest("d"),
    manifestPath: fixture.manifestPath,
    packagePath: fixture.packagePath,
    summaryPath: fixture.summaryPath,
    dispatchBindingPath: fixture.dispatchBindingPath,
    qualificationRoot: fixture.qualification,
    ...fixture.runIds
  };
}

test("creates and verifies a detached qualification bundle bound to source, candidate, package, manifest, retained evidence, and every run ID", () => {
  const fixture = bundleFixture();
  const bundlePath = path.join(fixture.directory, "qualification-bundle.json");
  const signaturePath = path.join(fixture.directory, "qualification-bundle.sig");
  const options = { ...bundleOptions(fixture), outputPath: bundlePath, signaturePath, privateKeyPath: fixture.privateKeyPath };
  const created = createSignedQualificationBundle(options);
  assert.equal(created.source_sha, fixture.sourceSha);
  assert.equal(created.retained_artifacts.length, 3);
  assert.deepEqual(created.retained_artifacts.map((item) => item.run_id), [fixture.runIds.cloud_qualification_run_id, fixture.runIds.macos_qualification_run_id, fixture.runIds.macos_qualification_run_id]);
  assert.deepEqual(verifySignedQualificationBundle({
    ...bundleOptions(fixture), bundlePath, signaturePath, publicKeyPath: fixture.publicKeyPath, expectedFingerprint: fixture.fingerprint
  }), { ok: true, bundle_sha256: createHash("sha256").update(fs.readFileSync(bundlePath)).digest("hex"), signature_verified: true });
});

test("rejects a signed qualification bundle when a selected run ID or retained archive changes", () => {
  const fixture = bundleFixture();
  const bundlePath = path.join(fixture.directory, "qualification-bundle.json");
  const signaturePath = path.join(fixture.directory, "qualification-bundle.sig");
  createSignedQualificationBundle({ ...bundleOptions(fixture), outputPath: bundlePath, signaturePath, privateKeyPath: fixture.privateKeyPath });
  assert.throws(() => verifySignedQualificationBundle({
    ...bundleOptions(fixture), qualification_run_id: "9999", bundlePath, signaturePath, publicKeyPath: fixture.publicKeyPath, expectedFingerprint: fixture.fingerprint
  }), /run IDs/u);
  const originalManifest = fs.readFileSync(fixture.manifestPath);
  const substitutedManifest = JSON.parse(originalManifest);
  substitutedManifest.source.commit = "f".repeat(40);
  fs.writeFileSync(fixture.manifestPath, canonical(substitutedManifest), { mode: 0o600 });
  assert.throws(() => verifySignedQualificationBundle({
    ...bundleOptions(fixture), bundlePath, signaturePath, publicKeyPath: fixture.publicKeyPath, expectedFingerprint: fixture.fingerprint
  }), /source/u);
  fs.writeFileSync(fixture.manifestPath, originalManifest, { mode: 0o600 });
  fs.appendFileSync(path.join(fixture.qualification, "cloud-production-qualification", "artifact.zip"), "mutation");
  assert.throws(() => verifySignedQualificationBundle({
    ...bundleOptions(fixture), bundlePath, signaturePath, publicKeyPath: fixture.publicKeyPath, expectedFingerprint: fixture.fingerprint
  }), /digest mismatch/u);
});
