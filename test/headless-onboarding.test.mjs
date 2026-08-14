import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  publicSetupFailure,
  publicSetupResult,
  readHeadlessOnboarding,
  redactDiagnostic
} from "../lib/headless-onboarding.mjs";
import { createSetupJournal, loadSetupJournal } from "../lib/setup-journal.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-headless-onboarding-"));
  const directory = path.join(root, "config");
  return { root, directory };
}

function cleanup(value) {
  fs.rmSync(value.root, { recursive: true, force: true });
}

test("shared status is resumable after a fresh process reads the durable journal", () => {
  const value = fixture();
  try {
    const first = createSetupJournal({ directory: value.directory, clock: () => "2030-01-01T00:00:00.000Z" });
    first.transition("app_verified");

    const result = readHeadlessOnboarding({ journalOptions: { directory: value.directory } });
    assert.equal(result.ok, true);
    assert.equal(result.status.state, "app_verified");
    assert.equal(result.status.revision, 1);
    assert.equal(result.status.next_actions[0].id, "initialize_local_config");
    assert.equal(loadSetupJournal({ directory: value.directory }).status().state, "app_verified");
  } finally { cleanup(value); }
});

test("journal corruption is blocked and never presented as a fresh setup", () => {
  const value = fixture();
  try {
    const journal = createSetupJournal({ directory: value.directory });
    const raw = JSON.parse(fs.readFileSync(journal.paths.journalPath, "utf8"));
    raw.state = "app_verified";
    fs.writeFileSync(journal.paths.journalPath, `${JSON.stringify(raw)}\n`, { mode: 0o600 });
    fs.chmodSync(journal.paths.journalPath, 0o600);

    const result = readHeadlessOnboarding({ journalOptions: { directory: value.directory } });
    assert.equal(result.ok, false);
    assert.equal(result.status, null);
    assert.equal(result.error.error.code, "TAMPERED_JOURNAL");
    assert.equal(result.error.error.message.includes(value.root), false);
    assert.equal(result.error.error.remediation.includes(value.root), false);
  } finally { cleanup(value); }
});

test("public setup output drops evidence and redacts diagnostics", () => {
  const result = publicSetupResult({
    execute: true,
    changed: true,
    action: {
      id: "enroll_device",
      from_state: "service_keys_activated",
      target_state: "device_enrolled",
      operation_id: "setup:secret-journal:8:enroll_device",
      command: "agentpass setup continue"
    },
    evidence: { proof: { credential: "reusable-secret" } },
    journal: {
      version: 1,
      journal_id: "123e4567-e89b-12d3-a456-426614174000",
      revision: 8,
      state: "device_enrolled",
      updated_at: "2030-01-01T00:00:00.000Z",
      setup_complete: false,
      next_actions: [{ id: "connect_editor", target_state: "editor_connected", command: "agentpass setup continue" }],
      history_length: 9
    }
  });
  const serialized = JSON.stringify(result);
  assert.equal(result.ok, true);
  assert.equal(Object.hasOwn(result, "evidence"), false);
  assert.equal(serialized.includes("reusable-secret"), false);
  assert.equal(serialized.includes("operation_id"), false);

  const diagnostic = redactDiagnostic("failed token=super-secret at /Users/alice/Secrets/key.json");
  assert.equal(diagnostic.includes("super-secret"), false);
  assert.equal(diagnostic.includes("/Users/alice"), false);
  assert.equal(redactDiagnostic({ secret: "never" }), "diagnostic_available");
});

test("setup failures have stable machine-readable redacted shape", () => {
  const result = publicSetupFailure(Object.assign(new Error("private key at /Users/alice/key"), { code: "SERVICE_RESTART_FAILED" }), { state: "device_enrolled" });
  assert.deepEqual(result, {
    version: 1,
    ok: false,
    error: {
      code: "SERVICE_RESTART_FAILED",
      message: "The native service could not be restarted safely.",
      remediation: "Run `agentpass setup status` and `agentpass doctor` before retrying."
    },
    state: "device_enrolled",
    onboarding: {
      version: 1,
      initialized: true,
      state: "device_enrolled",
      setup_complete: false,
      next_actions: [],
    }
  });
});
