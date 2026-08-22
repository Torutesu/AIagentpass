import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  PRODUCTION_READINESS_GATE_KIND,
  REQUIRED_PRODUCTION_EVIDENCE_ROWS,
  ProductionReadinessGateError,
  productionReadinessEvidenceSHA256,
  verifyProductionReadinessGate
} from "./production-readiness-gate.mjs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const NOW = Date.parse("2026-08-22T00:00:00.000Z");
const SHA = (value) => crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
const sourceCommit = "a".repeat(40);
const sourceTree = "b".repeat(40);
const artifact = SHA("c");
const candidateId = `release-pkg-sha256-v1-${artifact}`;
const script = path.resolve(import.meta.dirname, "production-readiness-gate.mjs");
const repoRoot = path.resolve(import.meta.dirname, "../..");
const packageJsonPath = path.join(repoRoot, "package.json");

function baseGate() {
  const evidence = REQUIRED_PRODUCTION_EVIDENCE_ROWS.map((required, index) => ({
    artifact_sha256: artifact,
    candidate_id: candidateId,
    expires_at: "2026-08-30T00:00:00.000Z",
    kind: required.kind,
    name: `evidence-${index}`,
    produced_at: "2026-08-21T00:00:00.000Z",
    provenance: {
      environment: "production",
      execution_class: "protected_external",
      runner_class: index === 7 || index === 8 ? "physical_hardware" : "protected_runner",
      source: "external"
    },
    qualified: true,
    run: { job_id: `job-${index}`, run_attempt: "1", run_id: String(index + 1) },
    sha256: SHA(String(index + 1)),
    slot: required.slot,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    status: "passed"
  }));
  return {
    candidate: { artifact_sha256: artifact, candidate_id: candidateId, source_commit: sourceCommit, source_tree: sourceTree },
    evidence,
    kind: PRODUCTION_READINESS_GATE_KIND,
    reviewer: {
      artifact_sha256: artifact,
      candidate_id: candidateId,
      evidence_sha256: productionReadinessEvidenceSHA256(evidence),
      expires_at: "2026-08-30T00:00:00.000Z",
      id: "external-reviewer-1",
      independent: true,
      report_sha256: SHA("d"),
      reviewed_at: "2026-08-21T12:00:00.000Z",
      source_commit: sourceCommit,
      source_tree: sourceTree
    },
    schema_version: 1
  };
}

function assertReason(value, reason) {
  assert.throws(() => verifyProductionReadinessGate(value, { now: NOW }), (error) => {
    assert.equal(error instanceof ProductionReadinessGateError, true);
    assert.equal(error.code, reason);
    return true;
  });
}

test("accepts a complete production-bound gate and returns only a safe summary", () => {
  const result = verifyProductionReadinessGate(baseGate(), { now: NOW });
  assert.equal(result.production_ready, true);
  assert.equal(result.status, "passed");
  assert.equal(result.evidence_count, REQUIRED_PRODUCTION_EVIDENCE_ROWS.length);
  assert.equal(Object.hasOwn(result, "evidence"), false);
  assert.equal(Object.hasOwn(result, "report_sha256"), false);
});

test("requires the fixed inventory and rejects missing or duplicate rows", () => {
  const missing = baseGate();
  missing.evidence.pop();
  assertReason(missing, "missing_or_duplicate_row");
  const duplicate = baseGate();
  duplicate.evidence[1].slot = duplicate.evidence[0].slot;
  assertReason(duplicate, "missing_or_duplicate_row");
});

for (const status of ["open", "not_proven", "not_run", "failed", "skipped"]) {
  test(`rejects terminal status ${status}`, () => {
    const gate = baseGate();
    gate.evidence[0].status = status;
    assertReason(gate, "evidence_not_passed");
  });
}

test("rejects duplicate evidence names, digests, and run tuples", () => {
  const name = baseGate(); name.evidence[1].name = name.evidence[0].name; assertReason(name, "duplicate_row");
  const digest = baseGate(); digest.evidence[1].sha256 = digest.evidence[0].sha256; assertReason(digest, "duplicate_row");
  const run = baseGate(); run.evidence[1].run = { ...run.evidence[0].run }; assertReason(run, "duplicate_row");
});

test("rejects candidate, source, tree, and artifact substitutions", () => {
  for (const field of ["candidate_id", "artifact_sha256", "source_commit", "source_tree"]) {
    const gate = baseGate();
    gate.evidence[0][field] = field === "candidate_id" ? `release-pkg-sha256-v1-${SHA("e")}` : field === "artifact_sha256" ? SHA("e") : field === "source_commit" ? "e".repeat(40) : "f".repeat(40);
    assertReason(gate, "binding_mismatch");
  }
});

test("rejects expired and overlong evidence and review windows", () => {
  const evidenceExpired = baseGate(); evidenceExpired.evidence[0].expires_at = "2026-08-21T00:00:00.000Z"; assertReason(evidenceExpired, "evidence_expired");
  const evidenceLong = baseGate(); evidenceLong.evidence[0].expires_at = "2026-09-22T00:00:00.000Z"; assertReason(evidenceLong, "evidence_expired");
  const reviewExpired = baseGate(); reviewExpired.reviewer.expires_at = "2026-08-21T00:00:00.000Z"; assertReason(reviewExpired, "review_expired");
});

test("requires protected external provenance and rejects local/static/mock/fixture/sandbox evidence", () => {
  for (const marker of ["local", "static", "mock", "fixture", "sandbox"]) {
    const gate = baseGate(); gate.evidence[0].name = marker; assertReason(gate, "non_production_evidence");
  }
  const local = baseGate(); local.evidence[0].provenance.environment = "local"; assertReason(local, "production_provenance_required");
  const staticEvidence = baseGate(); staticEvidence.evidence[0].provenance.execution_class = "static"; assertReason(staticEvidence, "production_provenance_required");
});

test("requires a genuinely separate, current reviewer bound to all evidence", () => {
  const notIndependent = baseGate(); notIndependent.reviewer.independent = false; assertReason(notIndependent, "independent_review_required");
  const selfReview = baseGate(); selfReview.reviewer.id = "job-0"; assertReason(selfReview, "independent_review_required");
  const wrongEvidence = baseGate(); wrongEvidence.reviewer.evidence_sha256 = SHA("e"); assertReason(wrongEvidence, "review_binding_mismatch");
  const wrongCandidate = baseGate(); wrongCandidate.reviewer.source_tree = "f".repeat(40); assertReason(wrongCandidate, "binding_mismatch");
});

test("rejects unknown fields and duplicate JSON object keys before validation", () => {
  const unknown = baseGate(); unknown.unexpected = true; assertReason(unknown, "unknown_field");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-readiness-"));
  try {
    const canonical = canonicalJson(baseGate());
    const duplicate = canonical.replace('"kind":"agentpass.production-readiness-gate"', '"kind":"agentpass.production-readiness-gate","kind":"agentpass.production-readiness-gate"');
    const file = path.join(temp, "duplicate.json"); fs.writeFileSync(file, duplicate);
    const child = spawnSync(process.execPath, [script, "verify", file], { encoding: "utf8" });
    assert.notEqual(child.status, 0);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr, '{"reason":"duplicate_field","status":"not_proven"}\n');
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("CLI accepts only canonical JSON and returns production_ready true on success", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-readiness-"));
  try {
    const file = path.join(temp, "gate.json"); fs.writeFileSync(file, canonicalJson(baseGate()));
    const child = spawnSync(process.execPath, [script, "verify", file], { encoding: "utf8" });
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout);
    assert.equal(result.production_ready, true);
    assert.equal(child.stderr, "");
    fs.writeFileSync(file, `${canonicalJson(baseGate())}\n`);
    const noncanonical = spawnSync(process.execPath, [script, "verify", file], { encoding: "utf8" });
    assert.notEqual(noncanonical.status, 0);
    assert.equal(noncanonical.stdout, "");
    assert.equal(noncanonical.stderr, '{"reason":"noncanonical_json","status":"not_proven"}\n');
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("npm release:readiness forwards the evidence path and fails closed", () => {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
  assert.equal(packageJson.scripts["release:readiness"], "node scripts/release/production-readiness-gate.mjs verify");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-readiness-npm-"));
  try {
    const file = path.join(temp, "gate.json");
    fs.writeFileSync(file, canonicalJson(baseGate()));
    const ok = spawnSync("npm", ["run", "--silent", "release:readiness", "--", file], { cwd: repoRoot, encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).production_ready, true);

    fs.writeFileSync(file, `${canonicalJson(baseGate())}\n`);
    const rejected = spawnSync("npm", ["run", "--silent", "release:readiness", "--", file], { cwd: repoRoot, encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.equal(rejected.stdout, "");
    assert.match(rejected.stderr, /\{"reason":"noncanonical_json","status":"not_proven"\}/u);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("CLI failure output contains no input values or secret-shaped material", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-readiness-"));
  try {
    const gate = baseGate(); gate.candidate.artifact_sha256 = "SECRET-DO-NOT-ECHO";
    const file = path.join(temp, "secret.json"); fs.writeFileSync(file, canonicalJson(gate));
    const child = spawnSync(process.execPath, [script, "verify", file], { encoding: "utf8" });
    assert.notEqual(child.status, 0);
    assert.equal(child.stdout, "");
    assert.doesNotMatch(child.stderr, /SECRET-DO-NOT-ECHO|source_commit|artifact_sha256|report_sha256/u);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
