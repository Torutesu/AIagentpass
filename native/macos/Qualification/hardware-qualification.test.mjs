import assert from "node:assert/strict";
import test from "node:test";
import { validate } from "./hardware-qualification.mjs";

const digest = "a".repeat(64);
const fingerprint = `SHA256:${"A".repeat(43)}`;
const observations = {
  launchd_host_child_identity: { service_label: "dev.agentpass.native-service", host_pid: 10, child_pid: 11, host_identity: { bundle_id: "dev.agentpass.native-agent-host" }, child_identity: { bundle_id: "dev.agentpass.git-sign-xpc" }, identity_match: true },
  nsxpc: { mach_service: "dev.agentpass.agent-host", connection_accepted: true, authorized_client: true, wrong_identity_denied: true },
  crash_restart: { initial_pid: 10, crash_signal: "SIGKILL", restarted_pid: 12, restart_count: 1, state_recovered: true }
};

const base = () => {
  const runner = { schema_version: 1, kind: "agentpass.macos.protected-runner-attestation", runner_id: "runner-arm64-01", architecture: "arm64", hardware_class: "apple_silicon", model_identifier: "Mac15,7", native_execution: true, vm_detected: false, rosetta_detected: false, attested_at: "2026-08-20T00:00:00.000Z" };
  return {
    schema_version: 2,
    kind: "agentpass.macos.hardware-qualification",
    source_commit: "b".repeat(40),
    source_tree: "d".repeat(40),
    release_manifest: { path: "/opt/agentpass/release/release-manifest.json", bytes: 100, sha256: digest, signature_path: "/opt/agentpass/release/release-manifest.sig", signature_sha256: digest, public_key_path: "/opt/agentpass/trust/release-public.pem", public_key_fingerprint: fingerprint, signed: true, source_commit: "b".repeat(40), source_tree: "d".repeat(40), artifact_name: "AgentPass-v1.2.3-macos-universal.pkg", artifact_bytes: 42, artifact_sha256: digest, release_attestation_sha256: digest },
    artifact: { path: "/opt/agentpass/release/AgentPass-v1.2.3-macos-universal.pkg", name: "AgentPass-v1.2.3-macos-universal.pkg", bytes: 42, sha256: digest, signed: true, signing_identity: "Developer ID Installer: AgentPass (ABCDE12345)", team_id: "ABCDE12345" },
    machine: { architecture: "arm64", hardware_class: "apple_silicon", model_identifier: "Mac15,7", os_version: "15.6.1", os_build: "24G90", native_execution: true, vm_detected: false, rosetta_detected: false },
    runner_attestation: { path: "/opt/agentpass/macos/runner-attestation.json", bytes: 200, sha256: digest, signature_path: "/opt/agentpass/macos/runner-attestation.sig", signature_sha256: digest, public_key_path: "/opt/agentpass/macos/runner-attestation.pem", public_key_fingerprint: fingerprint, signed: true, owner_uid: 0, mode: 0o600, ...runner },
    checks: Object.fromEntries(Object.keys(observations).map((name) => [name, { status: "passed", exit_code: 0, stdout_sha256: digest, stderr_sha256: digest, observed: observations[name] }])),
    qualified: true
  };
};

test("accepts a complete P1 report bound to signed release and runner evidence", () => assert.doesNotThrow(() => validate(base())));
test("rejects the previous self-asserted v1 shape", () => { const value = base(); value.schema_version = 1; delete value.source_tree; delete value.release_manifest; delete value.runner_attestation; assert.throws(() => validate(value), /qualified v2|missing or unknown/u); });
test("rejects source or package digest substitutions", () => { const source = base(); source.release_manifest.source_tree = "e".repeat(40); assert.throws(() => validate(source), /release manifest evidence|source/u); const artifact = base(); artifact.artifact.sha256 = "f".repeat(64); assert.throws(() => validate(artifact), /artifact evidence|release manifest|bound/u); });
test("rejects an unsigned or wrong-Team-ID package identity", () => { const value = base(); value.artifact.signed = false; assert.throws(() => validate(value), /artifact evidence/u); const other = base(); other.artifact.team_id = "OTHERTEAM1"; assert.throws(() => validate(other), /Team ID|artifact/u); });
test("rejects VM, Rosetta, or non-native runner evidence", () => { for (const field of ["vm_detected", "rosetta_detected"]) { const value = base(); value.runner_attestation[field] = true; assert.throws(() => validate(value), /runner attestation facts|runner attestation does not bind/u); } const native = base(); native.machine.native_execution = false; assert.throws(() => validate(native), /machine identity/u); });
test("rejects an unprotected or mismatched runner attestation", () => { const owner = base(); owner.runner_attestation.owner_uid = 501; assert.throws(() => validate(owner), /protection/u); const machine = base(); machine.runner_attestation.model_identifier = "Mac14,2"; assert.throws(() => validate(machine), /does not bind/u); });
test("rejects missing or not-run probe evidence", () => { const value = base(); delete value.checks.nsxpc; assert.throws(() => validate(value), /checks|missing/u); const notRun = base(); notRun.checks.crash_restart.status = "not_run"; assert.throws(() => validate(notRun), /crash_restart/u); });
