import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SetupOrchestratorError,
  createSetupOrchestrator
} from "../lib/setup-orchestrator.mjs";
import { SETUP_STATES, createSetupJournal } from "../lib/setup-journal.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-setup-orchestrator-"));
  const directory = path.join(root, "config");
  const journal = createSetupJournal({ directory, clock: () => "2030-01-01T00:00:00.000Z" });
  return { root, directory, journal };
}

function cleanup(value) {
  fs.rmSync(value.root, { recursive: true, force: true });
}

function envelope(context, proof, outcome = "completed") {
  return {
    evidence: {
      version: 1,
      from_state: context.current_state,
      to_state: context.target_state,
      action: context.action.id,
      operation_id: context.operation_id,
      outcome,
      proof
    }
  };
}

const proofs = {
  verify_app: { application: "/Applications/AgentPass.app", verification: "developer_id" },
  initialize_local_config: { directory: "/Users/test/.agentpass", config_version: 4 },
  select_native_bridge: { bridge: "native", client: "/Applications/AgentPass.app/client", manager: "/Applications/AgentPass.app/manager" },
  register_service: { service: "dev.agentpass.native-service", status: "enabled" },
  start_bootstrap: { approval_fingerprint: `SHA256:${"A".repeat(43)}`, lifecycle_head: "b".repeat(64), sequence: 1 },
  enroll_approval_key: { fingerprint: `SHA256:${"A".repeat(43)}`, generation: 1, lifecycle_head: "b".repeat(64), sequence: 2 },
  activate_service_keys: { roles: ["git_signing", "audit_checkpoint"], generation: 1, lifecycle_head: "a".repeat(64), sequence: 6 }
};

function handlersFor(calls = []) {
  return Object.fromEntries(Object.entries(proofs).map(([action, proof]) => [action, (context) => {
    calls.push(context);
    return envelope(context, proof);
  }]));
}

function codeOf(promise, code) {
  return assert.rejects(promise, (error) => error instanceof SetupOrchestratorError && error.code === code);
}

test("preview is read-only and execute advances exactly one current action", async () => {
  const value = fixture();
  try {
    const calls = [];
    const orchestrator = createSetupOrchestrator({ journal: value.journal, handlers: handlersFor(calls) });
    const before = fs.readFileSync(value.journal.paths.journalPath);
    const preview = await orchestrator.preview();
    assert.equal(preview.dry_run, true);
    assert.equal(preview.action.id, "verify_app");
    assert.equal(preview.action.target_state, "app_verified");
    assert.equal(calls.length, 0);
    assert.deepEqual(fs.readFileSync(value.journal.paths.journalPath), before);

    const result = await orchestrator.execute();
    assert.equal(result.changed, true);
    assert.equal(result.journal.state, "app_verified");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].operation_id, `setup:${result.journal.journal_id}:1:verify_app`);
    assert.equal(value.journal.status().revision, 1);
  } finally { cleanup(value); }
});

test("dispatch is exact and a handler cannot skip or reorder journal states", async () => {
  const value = fixture();
  try {
    const orchestrator = createSetupOrchestrator({ journal: value.journal, handlers: {
      verify_app: (context) => envelope(context, proofs.verify_app)
    } });
    const bad = createSetupOrchestrator({ journal: value.journal, handlers: {
      verify_app: (context) => ({ evidence: { ...envelope(context, proofs.verify_app).evidence, to_state: "service_registered" } })
    } });
    await codeOf(bad.execute(), "EVIDENCE_STATE_MISMATCH");
    assert.equal(value.journal.status().state, "not_started");
    await orchestrator.execute();
    assert.equal(value.journal.status().state, "app_verified");
  } finally { cleanup(value); }
});

test("failure, ambiguous responses, and invalid evidence never transition", async () => {
  for (const [response, expected] of [
    [() => { throw new Error("native unavailable"); }, "HANDLER_FAILED"],
    [() => undefined, "AMBIGUOUS_HANDLER_RESPONSE"],
    [(context) => ({ evidence: { ...envelope(context, proofs.verify_app).evidence, proof: { application: "/x", verification: "valid", extra: true } } }), "INVALID_EVIDENCE"]
  ]) {
    const value = fixture();
    try {
      const orchestrator = createSetupOrchestrator({ journal: value.journal, handlers: { verify_app: response } });
      await codeOf(orchestrator.execute(), expected);
      assert.equal(value.journal.status().state, "not_started");
      assert.equal(value.journal.status().revision, 0);
    } finally { cleanup(value); }
  }
});

test("retries use a stable operation and already-completed evidence is accepted", async () => {
  const value = fixture();
  try {
    let calls = 0;
    const orchestrator = createSetupOrchestrator({ journal: value.journal, handlers: {
      verify_app: (context) => {
        calls += 1;
        assert.equal(context.operation_id, `setup:${value.journal.status().journal_id}:1:verify_app`);
        if (calls === 1) throw new Error("simulated crash after native work");
        return envelope(context, proofs.verify_app, "already_completed");
      }
    } });
    await codeOf(orchestrator.execute(), "HANDLER_FAILED");
    const retry = await orchestrator.execute();
    assert.equal(retry.journal.state, "app_verified");
    assert.equal(retry.changed, true);
    assert.equal(calls, 2);
  } finally { cleanup(value); }
});

test("walks the native setup boundary through service key activation with one call per state", async () => {
  const value = fixture();
  try {
    const calls = [];
    const orchestrator = createSetupOrchestrator({ journal: value.journal, handlers: handlersFor(calls) });
    for (let index = 0; index < 7; index += 1) {
      const result = await orchestrator.execute();
      assert.equal(result.changed, true);
      assert.equal(result.journal.state, SETUP_STATES[index + 1]);
      assert.equal(result.action.target_state, SETUP_STATES[index + 1]);
    }
    assert.equal(value.journal.status().state, "service_keys_activated");
    assert.deepEqual(calls.map((context) => context.action.id), Object.keys(proofs));
    assert.equal(value.journal.status().revision, 7);
  } finally { cleanup(value); }
});

test("missing handlers are reported only on explicit execute", async () => {
  const value = fixture();
  try {
    const orchestrator = createSetupOrchestrator({ journal: value.journal });
    const preview = await orchestrator.preview();
    assert.equal(preview.handler_available, false);
    await codeOf(orchestrator.execute(), "HANDLER_MISSING");
    assert.equal(value.journal.status().state, "not_started");
  } finally { cleanup(value); }
});
