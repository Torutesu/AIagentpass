const APPROVAL_TAG = "dev.agentpass.session-approval.g1";
const SERVICE_ROLES = Object.freeze(["git_signing", "audit_checkpoint"]);

export class NativeSetupHandlerError extends Error {
  constructor(code, message) { super(message); this.name = "NativeSetupHandlerError"; this.code = code; }
}

function fail(code, message) { throw new NativeSetupHandlerError(code, message); }
function evidence(context, proof, alreadyCompleted) {
  return { evidence: {
    version: 1,
    from_state: context.current_state,
    to_state: context.target_state,
    action: context.action.id,
    operation_id: context.operation_id,
    outcome: alreadyCompleted ? "already_completed" : "completed",
    proof
  } };
}
function assertApproval(snapshot, approval, minimumSequence) {
  if (!snapshot || snapshot.sequence < minimumSequence || snapshot.sequence > 6 || snapshot.roles?.session_approval === "absent" || snapshot.fingerprints?.session_approval !== approval.fingerprint) {
    fail("BOOTSTRAP_STATE_MISMATCH", "Native approval authority does not match the setup ceremony");
  }
}

/** Bind setup-orchestrator actions to the signed native bootstrap primitives. */
export function createNativeSetupHandlers({ runner, approvalTag = APPROVAL_TAG } = {}) {
  if (!runner || typeof runner.status !== "function") fail("INVALID_RUNNER", "A native bootstrap runner is required");
  return Object.freeze({
    start_bootstrap(context) {
      const approval = runner.createApproval(approvalTag);
      let snapshot = runner.status();
      const already = snapshot.sequence >= 1;
      if (snapshot.sequence === 0) {
        const plan = runner.prepareApproval(approval.public_key_base64);
        if (plan.application_tag !== approvalTag || plan.fingerprint !== approval.fingerprint) fail("BOOTSTRAP_PLAN_MISMATCH", "Native approval plan substituted the enrolled key");
        snapshot = runner.status();
      }
      assertApproval(snapshot, approval, 1);
      return evidence(context, { approval_fingerprint: approval.fingerprint, lifecycle_head: snapshot.lifecycle_head_hash, sequence: snapshot.sequence }, already);
    },

    enroll_approval_key(context) {
      const approval = runner.createApproval(approvalTag);
      let snapshot = runner.status();
      if (snapshot.sequence < 1) fail("BOOTSTRAP_NOT_STARTED", "Native bootstrap has no durable approval staging record");
      const already = snapshot.sequence >= 2;
      if (snapshot.sequence === 1) {
        const plan = runner.prepareApproval(approval.public_key_base64);
        if (plan.application_tag !== approvalTag || plan.fingerprint !== approval.fingerprint) fail("BOOTSTRAP_PLAN_MISMATCH", "Native approval plan substituted the enrolled key");
        const signed = runner.sign(approvalTag, plan.statement_base64);
        if (signed.role !== "session_approval" || signed.signer_fingerprint !== approval.fingerprint || signed.statement_base64 !== plan.statement_base64) fail("BOOTSTRAP_SIGNATURE_MISMATCH", "Native approval signature does not bind the prepared plan");
        snapshot = runner.commitApproval(signed);
      }
      assertApproval(snapshot, approval, 2);
      return evidence(context, { fingerprint: approval.fingerprint, generation: 1, lifecycle_head: snapshot.lifecycle_head_hash, sequence: snapshot.sequence }, already);
    },

    activate_service_keys(context) {
      const approval = runner.createApproval(approvalTag);
      let snapshot = runner.status();
      assertApproval(snapshot, approval, 2);
      const already = snapshot.sequence === 6;
      for (const role of SERVICE_ROLES) {
        const state = snapshot.roles[role];
        if (state === "active") continue;
        if (state !== "absent" && state !== "staged") fail("BOOTSTRAP_STATE_MISMATCH", `Native ${role} authority is not resumable`);
        const plan = runner.prepareService(role);
        if (plan.role !== role || plan.generation !== 1) fail("BOOTSTRAP_PLAN_MISMATCH", `Native ${role} plan is invalid`);
        const signed = runner.sign(approvalTag, plan.statement_base64);
        if (signed.role !== role || signed.signer_fingerprint !== approval.fingerprint || signed.statement_base64 !== plan.statement_base64) fail("BOOTSTRAP_SIGNATURE_MISMATCH", `Native ${role} approval does not bind the prepared plan`);
        snapshot = runner.commitService(signed);
        assertApproval(snapshot, approval, 2);
      }
      if (snapshot.sequence !== 6 || snapshot.bootstrap_complete !== true || SERVICE_ROLES.some((role) => snapshot.roles[role] !== "active")) fail("BOOTSTRAP_INCOMPLETE", "Native service authority bootstrap did not complete");
      return evidence(context, { roles: [...SERVICE_ROLES], generation: 1, lifecycle_head: snapshot.lifecycle_head_hash, sequence: snapshot.sequence }, already);
    }
  });
}

export const NATIVE_SETUP_APPROVAL_TAG = APPROVAL_TAG;
