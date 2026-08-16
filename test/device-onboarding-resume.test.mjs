import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  DEVICE_ONBOARDING_RESUME_SOURCE,
  DEVICE_ONBOARDING_RESUME_STATES,
  DeviceOnboardingResumeError,
  DeviceOnboardingResumeStore
} from "../lib/device-onboarding-resume.mjs";

const TIMES = [
  "2026-08-16T00:00:00.000Z", "2026-08-16T00:00:01.000Z", "2026-08-16T00:00:02.000Z",
  "2026-08-16T00:00:03.000Z", "2026-08-16T00:00:04.000Z", "2026-08-16T00:00:05.000Z", "2026-08-16T00:00:06.000Z"
];
const HASHES = Object.fromEntries(["invitation", "delivery", "attempt", "receipt", "authority", "trust", "ack"].map((key, index) => [key, `${index + 1}`.repeat(64)]));

function tempStore(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-resume-"));
  const file = path.join(directory, "resume.json");
  return { directory, file, store: new DeviceOnboardingResumeStore(file, options) };
}

function createThroughUncertain(store) {
  store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
  store.issue_invitation({ invitation_id: "invitation-1", invitation_hash: HASHES.invitation, issued_at: TIMES[1] });
  store.record_delivery({ delivery_id: "delivery-1", delivery_hash: HASHES.delivery, delivered_at: TIMES[2] });
  return store.mark_enrollment_uncertain({ attempt_id: "attempt-1", attempt_hash: HASHES.attempt, uncertain_at: TIMES[3] });
}

function foundResult(binding = {}) {
  return {
    status: "found",
    binding: { source: DEVICE_ONBOARDING_RESUME_SOURCE, release_id: "release-1", organization_id: "org-1", device_id: "device-1", ...binding },
    authority_record_id: "authority-1",
    enrollment_id: "enrollment-1",
    receipt_id: "receipt-1",
    receipt_statement_hash: HASHES.receipt,
    authority_evidence_hash: HASHES.authority,
    observed_at: TIMES[4]
  };
}

test("advances only through the closed monotonic state machine", async () => {
  const { store } = tempStore();
  assert.deepEqual(DEVICE_ONBOARDING_RESUME_STATES, ["prepared", "invitation_issued", "delivered", "enrollment_uncertain", "receipt_verified", "trust_installed", "control_acknowledged", "failed"]);
  assert.equal(store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] }).state, "prepared");
  assert.equal(store.issue_invitation({ invitation_id: "invitation-1", invitation_hash: HASHES.invitation, issued_at: TIMES[1] }).state, "invitation_issued");
  assert.equal(store.record_delivery({ delivery_id: "delivery-1", delivery_hash: HASHES.delivery, delivered_at: TIMES[2] }).state, "delivered");
  assert.equal(store.mark_enrollment_uncertain({ attempt_id: "attempt-1", attempt_hash: HASHES.attempt, uncertain_at: TIMES[3] }).state, "enrollment_uncertain");
  assert.equal((await store.reconcile_enrollment({ lookup: async () => foundResult() })).state, "receipt_verified");
  assert.equal(store.install_trust({ trust_receipt_id: "trust-1", trust_evidence_hash: HASHES.trust, installed_at: TIMES[5] }).state, "trust_installed");
  assert.equal(store.acknowledge_control({ ack_id: "ack-1", ack_evidence_hash: HASHES.ack, acknowledged_at: TIMES[6] }).state, "control_acknowledged");
  assert.throws(() => store.record_delivery({ delivery_id: "delivery-2", delivery_hash: HASHES.delivery, delivered_at: TIMES[6] }), { code: "INVALID_TRANSITION" });
});

test("persists no secret material and denies caller-selected authority", () => {
  const { store, file } = tempStore();
  createThroughUncertain(store);
  const recordText = fs.readFileSync(file, "utf8");
  assert.doesNotMatch(recordText, /credential|nonce|bearer|token|private.?key|signature\s*:/iu);
  assert.doesNotMatch(recordText, /BEGIN [A-Z ]*PRIVATE KEY/iu);
  assert.throws(() => store.create_prepared({ release_id: "r", organization_id: "o", device_id: "d", authority: "caller", created_at: TIMES[0] }), { code: "INVALID_SCHEMA" });
  assert.ok(!Object.keys(store.read()).some((key) => /authority(?!_)/iu.test(key)));
});

test("response loss remains uncertain and only lookup can converge it", async () => {
  const { store } = tempStore();
  createThroughUncertain(store);
  let calls = 0;
  const notFound = await store.reconcile_enrollment({ lookup: async (request) => { calls += 1; assert.equal(request.record.state, "enrollment_uncertain"); return { status: "not_found", binding: request.binding, authority_record_id: null, enrollment_id: null, receipt_id: null, receipt_statement_hash: null, authority_evidence_hash: null, observed_at: TIMES[4] }; } });
  assert.equal(calls, 1);
  assert.equal(notFound.state, "enrollment_uncertain");
  assert.equal((await store.reconcile_enrollment({ lookup: async () => foundResult() })).state, "receipt_verified");
  await assert.rejects(store.reconcile_enrollment({ lookup: async () => foundResult() }), { code: "INVALID_TRANSITION" });
});

test("duplicate enrollment and authority binding conflicts fail closed", async () => {
  const duplicate = tempStore().store;
  createThroughUncertain(duplicate);
  const base = foundResult();
  const duplicateResult = { ...base, status: "duplicate", authority_record_id: null, enrollment_id: null, receipt_id: null, receipt_statement_hash: null, authority_evidence_hash: null };
  assert.equal((await duplicate.reconcile_enrollment({ lookup: async () => duplicateResult })).state, "failed");
  assert.equal(duplicate.read().failure.code, "duplicate_enrollment");

  const conflict = tempStore().store;
  createThroughUncertain(conflict);
  const conflictResult = { ...base, binding: { ...base.binding, organization_id: "other-org" }, status: "conflict", authority_record_id: null, enrollment_id: null, receipt_id: null, receipt_statement_hash: null, authority_evidence_hash: null };
  assert.equal((await conflict.reconcile_enrollment({ lookup: async () => conflictResult })).state, "failed");
  assert.equal(conflict.read().failure.code, "authority_conflict");
});

test("rejects duplicate and unknown fields, downgrade, noncanonical JSON, and tampering", () => {
  const { store, file } = tempStore();
  store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
  assert.throws(() => store.issue_invitation({ invitation_id: "i", invitation_hash: HASHES.invitation, issued_at: TIMES[1], extra: true }), { code: "INVALID_SCHEMA" });
  const original = fs.readFileSync(file, "utf8");
  fs.writeFileSync(file, original.replace(/"version":1/u, '"version":0'));
  assert.throws(() => store.read(), { code: "UNSUPPORTED_VERSION" });
  fs.writeFileSync(file, original);
  fs.writeFileSync(file, original.replace(/^\{/u, '{"format":"device-onboarding-resume.v1",'), "utf8");
  assert.throws(() => store.read(), { code: "INVALID_DOCUMENT" });
  fs.writeFileSync(file, original);
  const journal = JSON.parse(fs.readFileSync(`${file}.journal`, "utf8"));
  journal.entries[0].release_id = "tampered";
  fs.writeFileSync(`${file}.journal`, `${JSON.stringify(journal)}\n`);
  assert.throws(() => store.read(), (error) => ["NONCANONICAL", "TAMPER_DETECTED", "ROLLBACK_DETECTED"].includes(error.code));
  assert.equal(fs.existsSync(`${file}.anchor`), true);
});

test("recovers safely at every atomic commit interruption point", () => {
  for (const stage of ["after_journal", "after_state", "after_anchor"]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), `agentpass-fault-${stage}-`));
    const file = path.join(directory, "resume.json");
    let active = true;
    const crashing = new DeviceOnboardingResumeStore(file, { fault: (point) => { if (active && point === stage) throw new Error(`interrupted:${point}`); } });
    assert.throws(() => crashing.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] }));
    active = false;
    assert.equal(new DeviceOnboardingResumeStore(file).read().state, "prepared");
  }
});

test("recovers a journal-ahead snapshot after interruption during a transition", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recover-transition-"));
  const file = path.join(directory, "resume.json");
  let crash = true;
  const store = new DeviceOnboardingResumeStore(file, { fault: (point) => { if (crash && point === "after_journal") throw new Error("interrupted"); } });
  assert.throws(() => store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] }));
  crash = false;
  const resumed = new DeviceOnboardingResumeStore(file);
  resumed.read();
  assert.equal(resumed.issue_invitation({ invitation_id: "invitation-1", invitation_hash: HASHES.invitation, issued_at: TIMES[1] }).state, "invitation_issued");
});

test("recovers a transition interrupted after each durable replacement", () => {
  for (const stage of ["after_journal", "after_state", "after_anchor"]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), `agentpass-transition-fault-${stage}-`));
    const file = path.join(directory, "resume.json");
    const stable = new DeviceOnboardingResumeStore(file);
    stable.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
    let active = true;
    const crashing = new DeviceOnboardingResumeStore(file, { fault: (point) => { if (active && point === stage) throw new Error(`interrupted:${point}`); } });
    assert.throws(() => crashing.issue_invitation({ invitation_id: "invitation-1", invitation_hash: HASHES.invitation, issued_at: TIMES[1] }));
    active = false;
    assert.equal(new DeviceOnboardingResumeStore(file).read().state, "invitation_issued");
  }
});

test("detects rollback through the independent anchor and validates file safety", () => {
  const { store, file } = tempStore();
  store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
  store.issue_invitation({ invitation_id: "invitation-1", invitation_hash: HASHES.invitation, issued_at: TIMES[1] });
  const current = fs.readFileSync(file, "utf8");
  const anchor = fs.readFileSync(`${file}.anchor`, "utf8");
  fs.writeFileSync(`${file}.anchor`, current);
  assert.throws(() => store.read(), { code: "INVALID_SCHEMA" });
  fs.writeFileSync(`${file}.anchor`, anchor);
  const oldJournal = fs.readFileSync(`${file}.journal`, "utf8");
  fs.writeFileSync(`${file}.journal`, oldJournal.replace(/"head_revision":2/u, '"head_revision":1'));
  assert.throws(() => store.read(), (error) => ["NONCANONICAL", "ROLLBACK_DETECTED", "TAMPER_DETECTED"].includes(error.code));
  fs.writeFileSync(`${file}.journal`, oldJournal);
  fs.unlinkSync(file);
  fs.symlinkSync(path.basename(`${file}.journal`), file);
  assert.throws(() => store.read(), (error) => error.code === "UNSAFE_PATH" || error.code === "DURABILITY_FAILURE");
});

test("serializes instances and refuses unsafe permissions or locks", () => {
  const { store, file } = tempStore();
  const other = new DeviceOnboardingResumeStore(file);
  fs.writeFileSync(`${file}.lock`, `${JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() })}\n`, { mode: 0o600 });
  assert.throws(() => store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] }), { code: "LOCK_HELD" });
  fs.unlinkSync(`${file}.lock`);
  store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
  fs.chmodSync(file, 0o644);
  assert.throws(() => other.read(), { code: "UNSAFE_PATH" });
});

test("lookup exceptions and malformed authority evidence never advance state", async () => {
  const { store } = tempStore();
  createThroughUncertain(store);
  await assert.rejects(store.reconcile_enrollment({ lookup: async () => { throw new Error("network unavailable"); } }), { code: "AUTHORITATIVE_LOOKUP_FAILED" });
  assert.equal(store.read().state, "enrollment_uncertain");
  await assert.rejects(store.reconcile_enrollment({ lookup: async () => ({ status: "found" }) }), { code: "INVALID_SCHEMA" });
  assert.equal(store.read().state, "enrollment_uncertain");
});

test("durable files are strict canonical documents with no duplicate keys", () => {
  const { store, file } = tempStore();
  store.create_prepared({ release_id: "release-1", organization_id: "org-1", device_id: "device-1", resume_id: "resume-1", created_at: TIMES[0] });
  const text = fs.readFileSync(file, "utf8");
  fs.writeFileSync(file, text.replace(/^\{/u, '{"format":"device-onboarding-resume.v1",'), "utf8");
  assert.throws(() => store.read(), (error) => error instanceof DeviceOnboardingResumeError && ["INVALID_DOCUMENT", "NONCANONICAL"].includes(error.code));
  assert.equal(crypto.createHash("sha256").update("public evidence").digest("hex").length, 64);
});
