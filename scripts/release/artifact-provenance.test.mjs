import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { EXTERNAL_QUALIFICATION_GATES } from "./ci-preflight.mjs";
import { verifyExternalChildEvidence, verifyGithubArtifactArchive } from "./artifact-provenance.mjs";

const sourceCommit = "a".repeat(40);
const sourceTree = "b".repeat(40);
const releaseArtifactSha256 = "c".repeat(64);
const digest = (value) => createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value), "utf8").digest("hex");

test("recomputes the GitHub artifact archive digest and rejects archive/source substitutions", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-artifact-provenance-"));
  const archive = path.join(root, "artifact.zip");
  const bytes = Buffer.from("actual archive bytes\n");
  fs.writeFileSync(archive, bytes, { mode: 0o600 });
  const metadata = {
    artifact_id: "101",
    name: "notarized-release-candidate",
    digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    run_id: "202",
    run_attempt: "1",
    head_sha: sourceCommit,
    source_tree: sourceTree
  };
  assert.equal(verifyGithubArtifactArchive({ metadata, archivePath: archive, expectedName: metadata.name, expectedRunId: metadata.run_id, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree }).archive_sha256, metadata.digest.slice("sha256:".length));
  fs.writeFileSync(archive, "tampered archive bytes\n");
  assert.throws(() => verifyGithubArtifactArchive({ metadata, archivePath: archive, expectedName: metadata.name, expectedRunId: metadata.run_id, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree }), /archive digest mismatch/u);
  assert.throws(() => verifyGithubArtifactArchive({ metadata: { ...metadata, source_tree: "d".repeat(40) }, archivePath: archive, expectedName: metadata.name, expectedRunId: metadata.run_id, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree }), /archive digest mismatch|source tree is mismatched/u);
});

function aggregateAndChildren() {
  const children = [];
  const gates = {};
  for (const [gate, contract] of Object.entries(EXTERNAL_QUALIFICATION_GATES)) {
    gates[gate] = {
      status: "passed",
      qualified: true,
      reason: null,
      execution: { run_id: "303", run_attempt: "1", job_id: "404" },
      required_checks: [...contract.required_checks],
      checks: contract.required_checks.map((checkId) => {
        const evidence = { gate, check_id: checkId, observation: "positive", source_commit: sourceCommit, source_tree: sourceTree };
        const evidenceSha256 = digest(evidence);
        children.push({ gate, check_id: checkId, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: "303", run_attempt: "1", job_id: "404", evidence });
        return { check_id: checkId, status: "passed", expected: { type: "boolean", value: true }, observed: { type: "boolean", value: true }, evidence_sha256: evidenceSha256 };
      })
    };
  }
  return {
    aggregate: { schema_version: 1, kind: "agentpass-external-qualification", status: "passed", qualified: true, reason: null, release: {}, gates },
    children: { schema_version: 1, kind: "agentpass-external-qualification-child-evidence", source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, children }
  };
}

test("recomputes every aggregate check evidence_sha256 from the exact child bundle", () => {
  const fixture = aggregateAndChildren();
  const result = verifyExternalChildEvidence({ aggregate: fixture.aggregate, childEvidence: fixture.children, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree, expectedReleaseArtifactSha256: releaseArtifactSha256 });
  assert.deepEqual(result, { status: "passed", children: 25, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256 });
});

test("rejects child evidence digest, source, duplicate, and inventory substitutions", () => {
  const fixture = aggregateAndChildren();
  const tamperedDigest = structuredClone(fixture.children);
  tamperedDigest.children[0].evidence = { ...tamperedDigest.children[0].evidence, observation: "tampered" };
  assert.throws(() => verifyExternalChildEvidence({ aggregate: fixture.aggregate, childEvidence: tamperedDigest, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree, expectedReleaseArtifactSha256: releaseArtifactSha256 }), /digest mismatch/u);
  const tamperedSource = structuredClone(fixture.children);
  tamperedSource.children[0].source_tree = "d".repeat(40);
  assert.throws(() => verifyExternalChildEvidence({ aggregate: fixture.aggregate, childEvidence: tamperedSource, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree, expectedReleaseArtifactSha256: releaseArtifactSha256 }), /source\/artifact binding/u);
  const duplicate = structuredClone(fixture.children);
  duplicate.children.push(structuredClone(duplicate.children[0]));
  assert.throws(() => verifyExternalChildEvidence({ aggregate: fixture.aggregate, childEvidence: duplicate, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree, expectedReleaseArtifactSha256: releaseArtifactSha256 }), /duplicated/u);
  const missing = structuredClone(fixture.children);
  missing.children.pop();
  assert.throws(() => verifyExternalChildEvidence({ aggregate: fixture.aggregate, childEvidence: missing, expectedSourceCommit: sourceCommit, expectedSourceTree: sourceTree, expectedReleaseArtifactSha256: releaseArtifactSha256 }), /inventory is incomplete/u);
});

test("rejects child evidence whose execution is not the aggregate gate execution", () => {
  const fixture = aggregateAndChildren();
  for (const field of ["run_id", "run_attempt", "job_id"]) {
    const tampered = structuredClone(fixture.children);
    tampered.children[0][field] = field === "job_id" ? "405" : field === "run_attempt" ? "2" : "304";
    assert.throws(() => verifyExternalChildEvidence({
      aggregate: fixture.aggregate,
      childEvidence: tampered,
      expectedSourceCommit: sourceCommit,
      expectedSourceTree: sourceTree,
      expectedReleaseArtifactSha256: releaseArtifactSha256
    }), /execution binding is mismatched/u);
  }
});
