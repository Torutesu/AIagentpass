import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  REQUIRED_EVIDENCE_SLOTS,
  releaseEvidenceIndexSHA256,
  readReleaseEvidenceIndex,
  verifyReleaseEvidenceIndex
} from "./release-evidence-index.mjs";

const SOURCE_COMMIT = "a".repeat(40);
const SOURCE_TREE = "b".repeat(40);
const ARTIFACT_SHA256 = "c".repeat(64);
const MANIFEST_SHA256 = "d".repeat(64);
const CANDIDATE_ID = `release-pkg-sha256-v1-${ARTIFACT_SHA256}`;
const NOW = new Date("2099-08-20T12:00:00.000Z");

function sha(seed) { return crypto.createHash("sha256").update(seed).digest("hex"); }

function candidate() {
  return {
    artifact_name: "AgentPass-v1.2.3-macos-universal.pkg",
    artifact_sha256: ARTIFACT_SHA256,
    candidate_id: CANDIDATE_ID,
    release_manifest_sha256: MANIFEST_SHA256,
    source_commit: SOURCE_COMMIT,
    source_tree: SOURCE_TREE
  };
}

function baseIndex() {
  const evidence = REQUIRED_EVIDENCE_SLOTS.map(({ kind, slot }, index) => ({
    artifact_sha256: ARTIFACT_SHA256,
    candidate_id: CANDIDATE_ID,
    expires_at: "2099-08-25T12:00:00.000Z",
    kind,
    name: `${String(index + 1).padStart(2, "0")}-${slot}.json`,
    produced_at: "2099-08-20T10:00:00.000Z",
    qualified: true,
    run: { job_id: String(3000 + index), run_attempt: "1", run_id: String(4000 + index) },
    sha256: sha(`evidence-${index}`),
    slot,
    source_commit: SOURCE_COMMIT,
    source_tree: SOURCE_TREE,
    status: "passed"
  }));
  return {
    schema_version: 1,
    kind: "agentpass.release-evidence-index",
    candidate: candidate(),
    evidence,
    reviewer: {
      artifact_sha256: ARTIFACT_SHA256,
      candidate_id: CANDIDATE_ID,
      evidence_sha256: sha256Canonical(evidence),
      expires_at: "2099-08-28T12:00:00.000Z",
      id: "independent-reviewer@example.test",
      independent: true,
      report_sha256: sha("review-report"),
      reviewed_at: "2099-08-20T11:00:00.000Z",
      source_commit: SOURCE_COMMIT,
      source_tree: SOURCE_TREE
    }
  };
}

function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

test("release evidence index binds every required lane and reviewer to one candidate", () => {
  const value = baseIndex();
  const normalized = verifyReleaseEvidenceIndex(value, { expectedCandidate: candidate(), now: NOW });
  assert.equal(normalized.evidence.length, 11);
  assert.deepEqual(normalized.evidence.map((item) => `${item.kind}:${item.slot}`), REQUIRED_EVIDENCE_SLOTS.map((item) => `${item.kind}:${item.slot}`));
  assert.match(releaseEvidenceIndexSHA256(normalized), /^[0-9a-f]{64}$/u);
});

test("candidate/source/tree/artifact substitution is rejected in every lane", () => {
  for (let index = 0; index < baseIndex().evidence.length; index += 1) {
    const value = baseIndex();
    value.evidence[index].source_tree = "9".repeat(40);
    value.reviewer.evidence_sha256 = sha256Canonical(value.evidence);
    assert.throws(() => verifyReleaseEvidenceIndex(value, { expectedCandidate: candidate(), now: NOW }), /candidate_binding_mismatch/u);
  }
});

test("missing and duplicate slots are rejected fail-closed", () => {
  const missing = baseIndex();
  missing.evidence.pop();
  assert.throws(() => verifyReleaseEvidenceIndex(missing, { expectedCandidate: candidate(), now: NOW }), /missing_or_duplicate_evidence/u);
  const duplicate = baseIndex();
  duplicate.evidence[10].slot = duplicate.evidence[9].slot;
  duplicate.evidence[10].kind = duplicate.evidence[9].kind;
  duplicate.reviewer.evidence_sha256 = sha256Canonical(duplicate.evidence);
  assert.throws(() => verifyReleaseEvidenceIndex(duplicate, { expectedCandidate: candidate(), now: NOW }), /missing_or_duplicate_evidence/u);
});

test("duplicate evidence digest and duplicate run tuple are rejected", () => {
  const digestDuplicate = baseIndex();
  digestDuplicate.evidence[1].sha256 = digestDuplicate.evidence[0].sha256;
  digestDuplicate.reviewer.evidence_sha256 = sha256Canonical(digestDuplicate.evidence);
  assert.throws(() => verifyReleaseEvidenceIndex(digestDuplicate, { expectedCandidate: candidate(), now: NOW }), /duplicate_evidence/u);
  const runDuplicate = baseIndex();
  runDuplicate.evidence[1].run = { ...runDuplicate.evidence[0].run };
  runDuplicate.reviewer.evidence_sha256 = sha256Canonical(runDuplicate.evidence);
  assert.throws(() => verifyReleaseEvidenceIndex(runDuplicate, { expectedCandidate: candidate(), now: NOW }), /duplicate_run/u);
});

test("not_proven, not_run, failed, or unqualified evidence is never accepted", () => {
  for (const mutation of [
    (value) => { value.evidence[0].status = "not_proven"; },
    (value) => { value.evidence[0].qualified = false; },
    (value) => { value.evidence[0].name = "local-fixture.json"; },
    (value) => { value.evidence[0].status = "failed"; }
  ]) {
    const value = baseIndex();
    mutation(value);
    value.reviewer.evidence_sha256 = sha256Canonical(value.evidence);
    assert.throws(() => verifyReleaseEvidenceIndex(value, { expectedCandidate: candidate(), now: NOW }), /not_proven/u);
  }
});

test("expired, future, and overlong evidence/review windows are rejected", () => {
  for (const mutation of [
    (value) => { value.evidence[0].expires_at = "2099-08-20T11:59:59.000Z"; },
    (value) => { value.evidence[0].produced_at = "2099-08-20T12:00:01.000Z"; },
    (value) => { value.evidence[0].expires_at = "2099-09-20T10:00:00.000Z"; },
    (value) => { value.reviewer.expires_at = "2099-09-20T11:00:00.000Z"; }
  ]) {
    const value = baseIndex();
    mutation(value);
    value.reviewer.evidence_sha256 = sha256Canonical(value.evidence);
    assert.throws(() => verifyReleaseEvidenceIndex(value, { expectedCandidate: candidate(), now: NOW }), /expired|timestamp|expiry_window/u);
  }
});

test("reviewer cannot cover a partial or substituted evidence inventory", () => {
  const value = baseIndex();
  value.reviewer.evidence_sha256 = sha("partial-review");
  assert.throws(() => verifyReleaseEvidenceIndex(value, { expectedCandidate: candidate(), now: NOW }), /review_binding_mismatch/u);
  const substituted = baseIndex();
  substituted.reviewer.candidate_id = `release-pkg-sha256-v1-${"9".repeat(64)}`;
  assert.throws(() => verifyReleaseEvidenceIndex(substituted, { expectedCandidate: candidate(), now: NOW }), /candidate_binding_mismatch/u);
});

test("exact schemas reject extra fields and candidate expectation mismatches", () => {
  const extra = baseIndex();
  extra.evidence[0].extra = true;
  extra.reviewer.evidence_sha256 = sha256Canonical(extra.evidence);
  assert.throws(() => verifyReleaseEvidenceIndex(extra, { expectedCandidate: candidate(), now: NOW }), /invalid_schema/u);
  const mismatch = baseIndex();
  const expected = { ...candidate(), source_commit: "e".repeat(40) };
  assert.throws(() => verifyReleaseEvidenceIndex(mismatch, { expectedCandidate: expected, now: NOW }), /candidate_binding_mismatch/u);
});

test("canonical file reader rejects duplicate or noncanonical JSON", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-evidence-"));
  try {
    const file = path.join(directory, "index.json");
    const value = baseIndex();
    fs.writeFileSync(file, `${canonicalJson(value).slice(0, -1)},\"kind\":\"agentpass.release-evidence-index\"}\n`);
    assert.throws(() => readReleaseEvidenceIndex(file), /duplicate_field|noncanonical_json|invalid_json/u);
    fs.writeFileSync(file, JSON.stringify(value));
    assert.throws(() => readReleaseEvidenceIndex(file), /noncanonical_json/u);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
