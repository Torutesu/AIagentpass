import assert from "node:assert/strict";
import test from "node:test";
import { createNativeSetupHandlers } from "../lib/native-setup-handlers.mjs";

const fingerprint = `SHA256:${"A".repeat(43)}`, head = "b".repeat(64), tag = "dev.agentpass.session-approval.g1";
function context(action, from, to) { return { current_state: from, target_state: to, operation_id: `op-${action}`, action: { id: action } }; }
function fakeRunner(initial = 0) {
  let sequence = initial;
  const roles = { session_approval: sequence >= 1 ? (sequence === 1 ? "staged" : "active") : "absent", git_signing: sequence >= 3 ? (sequence === 3 ? "staged" : "active") : "absent", audit_checkpoint: sequence >= 5 ? (sequence === 5 ? "staged" : "active") : "absent" };
  const calls = [];
  const snapshot = () => ({ sequence, lifecycle_head_hash: head, bootstrap_complete: sequence === 6, roles: { ...roles }, fingerprints: Object.fromEntries(Object.entries(roles).map(([role, state]) => [role, state === "absent" ? null : fingerprint])) });
  return { calls, status: snapshot,
    createApproval(applicationTag) { calls.push(["create", applicationTag]); return { application_tag: tag, fingerprint, public_key_base64: Buffer.from("public").toString("base64") }; },
    prepareApproval() { calls.push(["prepare-approval"]); sequence = 1; roles.session_approval = "staged"; return { application_tag: tag, fingerprint, statement_base64: Buffer.from("approval").toString("base64") }; },
    prepareService(role) { calls.push(["prepare", role]); sequence = role === "git_signing" ? 3 : 5; roles[role] = "staged"; return { role, generation: 1, statement_base64: Buffer.from(role).toString("base64") }; },
    sign(_tag, statement) { const role = Buffer.from(statement, "base64").toString() === "approval" ? "session_approval" : Buffer.from(statement, "base64").toString(); calls.push(["sign", role]); return { role, signer_fingerprint: fingerprint, statement_base64: statement }; },
    commitApproval() { calls.push(["commit-approval"]); sequence = 2; roles.session_approval = "active"; return snapshot(); },
    commitService(signed) { calls.push(["commit", signed.role]); sequence = signed.role === "git_signing" ? 4 : 6; roles[signed.role] = "active"; return snapshot(); }
  };
}

test("advances and reconciles every durable native bootstrap boundary", () => {
  const runner = fakeRunner(); const handlers = createNativeSetupHandlers({ runner });
  const started = handlers.start_bootstrap(context("start_bootstrap", "service_registered", "bootstrap_started"));
  assert.equal(started.evidence.proof.sequence, 1);
  const approval = handlers.enroll_approval_key(context("enroll_approval_key", "bootstrap_started", "approval_key_enrolled"));
  assert.equal(approval.evidence.proof.sequence, 2);
  const service = handlers.activate_service_keys(context("activate_service_keys", "approval_key_enrolled", "service_keys_activated"));
  assert.equal(service.evidence.proof.sequence, 6);
  assert.deepEqual(runner.calls.filter(([name]) => name === "commit").map(([, role]) => role), ["git_signing", "audit_checkpoint"]);
});

test("reports already-completed evidence without generating duplicate service keys", () => {
  const runner = fakeRunner(6); const handlers = createNativeSetupHandlers({ runner });
  assert.equal(handlers.start_bootstrap(context("start_bootstrap", "service_registered", "bootstrap_started")).evidence.outcome, "already_completed");
  assert.equal(handlers.enroll_approval_key(context("enroll_approval_key", "bootstrap_started", "approval_key_enrolled")).evidence.outcome, "already_completed");
  assert.equal(handlers.activate_service_keys(context("activate_service_keys", "approval_key_enrolled", "service_keys_activated")).evidence.outcome, "already_completed");
  assert.equal(runner.calls.some(([name]) => name === "prepare" || name === "commit" || name === "sign"), false);
});

test("rejects substituted approval identity and impossible ordering", () => {
  const runner = fakeRunner(1); const handlers = createNativeSetupHandlers({ runner });
  runner.status = () => ({ ...fakeRunner(1).status(), fingerprints: { session_approval: `SHA256:${"C".repeat(43)}`, git_signing: null, audit_checkpoint: null } });
  assert.throws(() => handlers.start_bootstrap(context("start_bootstrap", "service_registered", "bootstrap_started")), { code: "BOOTSTRAP_STATE_MISMATCH" });
  const notStarted = createNativeSetupHandlers({ runner: fakeRunner(0) });
  assert.throws(() => notStarted.enroll_approval_key(context("enroll_approval_key", "bootstrap_started", "approval_key_enrolled")), { code: "BOOTSTRAP_NOT_STARTED" });
});
