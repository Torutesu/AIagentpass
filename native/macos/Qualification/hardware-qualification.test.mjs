import assert from "node:assert/strict";
import test from "node:test";
import { validate } from "./hardware-qualification.mjs";

const digest = "a".repeat(64);
const observations = { launchd_host_child_identity: { service_label: "dev.agentpass.native-service", host_pid: 10, child_pid: 11, host_identity: { bundle_id: "dev.agentpass.native-agent-host" }, child_identity: { bundle_id: "dev.agentpass.git-sign-xpc" }, identity_match: true }, nsxpc: { mach_service: "dev.agentpass.agent-host", connection_accepted: true, authorized_client: true, wrong_identity_denied: true }, crash_restart: { initial_pid: 10, crash_signal: "SIGKILL", restarted_pid: 12, restart_count: 1, state_recovered: true } };
const base = () => ({ schema_version: 1, kind: "agentpass.macos.hardware-qualification", source_commit: "b".repeat(40), artifact: { path: "/tmp/release.pkg", bytes: 1, sha256: digest, signed: true, identifier: "dev.agentpass", team_id: "ABCDE12345", cdhashes: ["c".repeat(40)] }, machine: { architecture: "arm64", hardware_class: "apple_silicon", model_identifier: "Mac", os_version: "14.0", os_build: "23A" }, checks: Object.fromEntries(Object.keys(observations).map((name) => [name, { status: "passed", exit_code: 0, stdout_sha256: digest, stderr_sha256: digest, observed: observations[name] }])), qualified: true });

test("accepts a complete passing report", () => assert.doesNotThrow(() => validate(base())));
test("rejects a missing check instead of treating it as skipped", () => { const value = base(); delete value.checks.nsxpc; assert.throws(() => validate(value), /checks|unexpected/u); });
test("rejects not-run and inconsistent architecture evidence", () => { const value = base(); value.checks.crash_restart.status = "not_run"; assert.throws(() => validate(value), /crash_restart/u); const other = base(); other.machine.hardware_class = "intel"; assert.throws(() => validate(other), /machine identity/u); });
test("rejects an artifact without a signed digest identity", () => { const value = base(); value.artifact.signed = false; assert.throws(() => validate(value), /artifact evidence/u); });
test("rejects a probe that reports pass without the required physical facts", () => { const value = base(); value.checks.nsxpc.observed.wrong_identity_denied = false; assert.throws(() => validate(value), /nsxpc observed evidence/u); });
