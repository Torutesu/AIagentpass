import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { NativeBootstrapError, createNativeBootstrapRunner } from "../lib/native-bootstrap-runner.mjs";

const digest = "a".repeat(64);
const keyFingerprint = `SHA256:${"A".repeat(43)}`;
const b64 = (value) => Buffer.from(value).toString("base64");
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function envelope(value) {
  return canonical({ ok: true, stdout_base64: b64(canonical(value)) });
}
function files(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-bootstrap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const client = path.join(root, "client"), service = path.join(root, "service"), config = path.join(root, "config.json");
  fs.writeFileSync(client, "client", { mode: 0o700 }); fs.writeFileSync(service, "service", { mode: 0o700 }); fs.writeFileSync(config, "{}", { mode: 0o600 });
  return { client, service, config, applicationRoot: root, stateRoot: root, expectedOwner: process.getuid() };
}
function snapshot(sequence) {
  const roles = { audit_checkpoint: "absent", git_signing: "absent", session_approval: "absent" };
  if (sequence >= 1) roles.session_approval = sequence === 1 ? "staged" : "active";
  if (sequence >= 3) roles.git_signing = sequence === 3 ? "staged" : "active";
  if (sequence >= 5) roles.audit_checkpoint = sequence === 5 ? "staged" : "active";
  const fingerprints = Object.fromEntries(Object.entries(roles).map(([role, state]) => [role, state === "absent" ? null : keyFingerprint]));
  return { bootstrap_complete: sequence === 6, configuration_pin_update_required: true, fingerprints, lifecycle_head_hash: digest, roles, sequence, version: 1 };
}
function plan(role) {
  return { application_tag: `dev.agentpass.${role}.g1`, configuration_pin_update_required: true, fingerprint: keyFingerprint, generation: 1, lifecycle_head_hash: digest, role, statement_base64: b64(`statement-${role}`), version: 1 };
}

test("runs the resumable native bootstrap protocol with exact privileged handoffs", (t) => {
  const value = files(t); let sequence = 0; let role = "session_approval"; const calls = []; let authentications = 0;
  const run = (call) => {
    calls.push(call);
    const action = call.args[1];
    if (call.args[0] === "bootstrap-approval-create") return { status: 0, stdout: envelope({ application_tag: call.args[1], authorized_key: "ecdsa-sha2-nistp256 AAAA", fingerprint: keyFingerprint, public_key_base64: b64("approval-public-key"), version: 1 }) };
    if (call.args[0] === "bootstrap-sign") return { status: 0, stdout: envelope({ generation: 1, role, signature_base64: b64("signature"), signer_fingerprint: keyFingerprint, signer_public_key_base64: b64("approval-public-key"), statement_base64: call.inputBytes.toString("base64"), version: 1 }) };
    if (action === "status") return { status: 0, stdout: canonical(snapshot(sequence)) };
    if (action === "prepare-approval") { sequence = 1; role = "session_approval"; return { status: 0, stdout: canonical(plan(role)) }; }
    if (action === "commit-approval") { sequence = 2; return { status: 0, stdout: canonical(snapshot(sequence)) }; }
    if (action === "prepare-service") { role = call.input.role; sequence = sequence === 2 ? 3 : 5; return { status: 0, stdout: canonical(plan(role)) }; }
    if (action === "commit-service") { sequence = sequence === 3 ? 4 : 6; return { status: 0, stdout: canonical(snapshot(sequence)) }; }
    throw new Error(`unexpected call ${action}`);
  };
  const runner = createNativeBootstrapRunner({ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner, run, authenticate: () => ({ status: 0, authenticated: ++authentications }) });
  assert.equal(runner.status().sequence, 0);
  const approval = runner.createApproval("dev.agentpass.session-approval.g1");
  const approvalPlan = runner.prepareApproval(approval.public_key_base64);
  assert.equal(runner.commitApproval(runner.sign(approval.application_tag, approvalPlan.statement_base64)).sequence, 2);
  for (const serviceRole of ["git_signing", "audit_checkpoint"]) {
    const servicePlan = runner.prepareService(serviceRole);
    runner.commitService(runner.sign(approval.application_tag, servicePlan.statement_base64));
  }
  assert.deepEqual(runner.status(), snapshot(6));
  assert.equal(calls.filter((call) => call.privileged).length, 8);
  assert.equal(calls.filter((call) => call.inputBytes).length, 3);
  assert.equal(authentications, 1);
});

test("authenticates before privileged JSON is handed to the service", (t) => {
  const value = files(t); let invoked = false;
  const runner = createNativeBootstrapRunner({
    clientPath: value.client,
    servicePath: value.service,
    configPath: value.config,
    applicationRoot: value.applicationRoot,
    stateRoot: value.stateRoot,
    expectedOwner: value.expectedOwner,
    authenticate: () => ({ status: 1 }),
    run: () => { invoked = true; return { status: 0, stdout: canonical(snapshot(0)) }; }
  });
  assert.throws(() => runner.status(), { code: "PRIVILEGE_AUTHENTICATION_FAILED" });
  assert.equal(invoked, false);
});

test("fails closed on unsafe inputs and ambiguous native responses", (t) => {
  const value = files(t);
  const linked = `${value.client}.link`; fs.linkSync(value.client, linked);
  assert.throws(() => createNativeBootstrapRunner({ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner, run() {} }), { code: "UNSAFE_PATH" });
  fs.unlinkSync(linked);
  fs.chmodSync(value.config, 0o644);
  assert.throws(() => createNativeBootstrapRunner({ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner, run() {} }), { code: "UNSAFE_PATH" });
  fs.chmodSync(value.config, 0o600);

  const bad = createNativeBootstrapRunner({ ...{ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner }, run: () => ({ status: 0, stdout: '{"bootstrap_complete":false,"bootstrap_complete":false}' }) });
  assert.throws(() => bad.status(), { code: "INVALID_RESPONSE" });

  const failed = createNativeBootstrapRunner({ ...{ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner }, run: () => ({ status: 1, stdout: "", stderr: "sensitive diagnostics" }) });
  assert.throws(() => failed.status(), (error) => error instanceof NativeBootstrapError && error.code === "NATIVE_FAILURE" && !error.message.includes("sensitive"));
});

test("rejects contradictory bootstrap completion evidence", (t) => {
  const value = files(t);
  const run = () => ({ status: 0, stdout: canonical({ ...snapshot(5), bootstrap_complete: true }) });
  const runner = createNativeBootstrapRunner({ clientPath: value.client, servicePath: value.service, configPath: value.config, applicationRoot: value.applicationRoot, stateRoot: value.stateRoot, expectedOwner: value.expectedOwner, run });
  assert.throws(() => runner.status(), { code: "INVALID_RESPONSE" });
});
