import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SetupFinalizationError,
  TEST_COMMIT_VERIFICATION_MARKER,
  createCompleteSetupHandler,
  createEditorConnectedHandler,
  createSetupFinalizationHandlers,
  createTestCommitVerifiedHandler
} from "../lib/setup-finalization-handlers.mjs";

function context(action, from, to) {
  return { current_state: from, target_state: to, operation_id: `setup:test:1:${action}`, action: { id: action } };
}

function fixture(client = "claude-code") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-finalization-"));
  const project = path.join(root, "project");
  fs.mkdirSync(client === "cursor" ? path.join(project, ".cursor") : project, { recursive: true, mode: 0o700 });
  const target = path.join(project, client === "cursor" ? ".cursor/mcp.json" : ".mcp.json");
  const server = { command: process.execPath, args: ["/opt/agentpass-mcp.mjs"], env: { AGENTPASS_PROJECT_DIR: project } };
  const onboarding = { version: 1, client, target, server_name: "agentpass", server };
  return { root, project, target, server, onboarding };
}

function write(value, document) { fs.writeFileSync(value.target, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 }); }
function validVerifier() { return { commit: "a".repeat(40), verification: TEST_COMMIT_VERIFICATION_MARKER }; }
function codeOf(fn, code) { assert.throws(fn, (error) => error instanceof SetupFinalizationError && error.code === code); }
async function asyncCodeOf(fn, code) { await assert.rejects(fn, (error) => error instanceof SetupFinalizationError && error.code === code); }

test("editor handler accepts only the exact AgentPass-owned Claude Code entry and never writes", async () => {
  const value = fixture();
  try {
    write(value, { name: "project", mcpServers: { other: { command: "other" }, agentpass: value.server } });
    const before = fs.readFileSync(value.target);
    const handler = createEditorConnectedHandler({ onboarding: value.onboarding });
    const result = await handler(context("connect_editor", "device_enrolled", "editor_connected"));
    assert.deepEqual(result.evidence.proof, { client: "claude-code", project: fs.realpathSync(value.project) });
    assert.deepEqual(fs.readFileSync(value.target), before);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("editor handler supports Cursor's exact path and rejects an entry substitution", async () => {
  const value = fixture("cursor");
  try {
    write(value, { mcpServers: { agentpass: { ...value.server, args: ["/tmp/substituted.mjs"] } } });
    const handler = createEditorConnectedHandler({ onboarding: value.onboarding });
    await asyncCodeOf(() => handler(context("connect_editor", "device_enrolled", "editor_connected")), "EDITOR_NOT_CONNECTED");
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("editor handler fails closed for duplicate JSON keys and unsafe descriptors", async () => {
  const value = fixture();
  try {
    fs.writeFileSync(value.target, '{"mcpServers":{"agentpass":{},"agentpass":{}}}\n', { mode: 0o600 });
    const handler = createEditorConnectedHandler({ onboarding: value.onboarding });
    await asyncCodeOf(() => handler(context("connect_editor", "device_enrolled", "editor_connected")), "INVALID_EDITOR_CONFIGURATION");
    const otherTarget = path.join(value.project, "other.json");
    fs.writeFileSync(otherTarget, "{}\n", { mode: 0o600 });
    const unsafe = { ...value.onboarding, target: otherTarget };
    codeOf(() => createEditorConnectedHandler({ onboarding: unsafe }), "INVALID_ONBOARDING_DESCRIPTOR");
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("test commit handler inspects only a caller-supplied full hash and marker", async () => {
  const handler = createTestCommitVerifiedHandler({ verifierResult: validVerifier() });
  const result = await handler(context("verify_test_commit", "editor_connected", "test_commit_verified"));
  assert.deepEqual(result.evidence.proof, validVerifier());
  for (const verifierResult of [
    { commit: "a".repeat(39), verification: TEST_COMMIT_VERIFICATION_MARKER },
    { commit: "a".repeat(40).toUpperCase(), verification: TEST_COMMIT_VERIFICATION_MARKER },
    { commit: "a".repeat(40), verification: "verified" },
    { commit: "a".repeat(40), verification: TEST_COMMIT_VERIFICATION_MARKER, extra: true },
    { commit: "a".repeat(40) }
  ]) codeOf(() => createTestCommitVerifiedHandler({ verifierResult }), "INVALID_VERIFIER_RESULT");
});

test("test commit and completion never invoke git and completion requires prior proof", async () => {
  const original = crypto.createHash;
  let invoked = false;
  crypto.createHash = (...args) => { invoked = true; return original(...args); };
  try {
    const proof = validVerifier();
    const handlers = createSetupFinalizationHandlers({
      onboarding: (() => { const value = fixture(); write(value, { mcpServers: { agentpass: value.server } }); return value.onboarding; })(),
      verifierResult: proof,
      priorVerificationProof: proof
    });
    const verified = await handlers.verify_test_commit(context("verify_test_commit", "editor_connected", "test_commit_verified"));
    const complete = await handlers.complete_setup(context("complete_setup", "test_commit_verified", "complete"));
    assert.equal(verified.evidence.proof.commit, proof.commit);
    assert.deepEqual(complete.evidence.proof, { completion: "test_commit_verified" });
    assert.equal(invoked, false);
    codeOf(() => createCompleteSetupHandler({ priorVerificationProof: undefined }), "INVALID_VERIFIER_RESULT");
  } finally { crypto.createHash = original; }
});
