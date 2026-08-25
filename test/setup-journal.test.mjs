import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SETUP_JOURNAL_ANCHOR_FILENAME,
  SETUP_JOURNAL_FILENAME,
  SETUP_STATES,
  SetupJournalError,
  createSetupJournal,
  loadSetupJournal,
  nextActionsForState,
  readSetupJournal,
  setupJournalPaths
} from "../lib/setup-journal.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-setup-journal-"));
  const directory = path.join(root, "config");
  const clock = () => "2030-01-01T00:00:00.000Z";
  const journal = createSetupJournal({ directory, clock });
  return { root, directory, journal, paths: setupJournalPaths({ directory }), clock };
}

function cleanup(value) {
  fs.rmSync(value.root, { recursive: true, force: true });
}

function assertCode(error, code) {
  assert.ok(error instanceof SetupJournalError);
  assert.equal(error.code, code);
}

function thrown(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("Expected operation to throw");
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

test("creates a user-owned journal and exposes stable machine-readable next actions", () => {
  const value = fixture();
  try {
    const status = value.journal.status();
    assert.equal(status.state, "not_started");
    assert.equal(status.revision, 0);
    assert.equal(status.setup_complete, false);
    assert.deepEqual(status.next_actions, [{
      id: "verify_app",
      target_state: "app_verified",
      command: "agentpass setup continue",
      description: "Verify the signed AgentPass application"
    }]);
    assert.deepEqual(fs.readdirSync(value.directory).sort(), [SETUP_JOURNAL_ANCHOR_FILENAME, SETUP_JOURNAL_FILENAME]);
    assert.equal(fs.statSync(value.directory).mode & 0o777, 0o700);
    assert.equal(fs.statSync(value.paths.journalPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(value.paths.anchorPath).mode & 0o777, 0o600);
    assert.equal(readJson(value.paths.journalPath).state, "not_started");
    assert.equal(readJson(value.paths.anchorPath).tip.state, "not_started");
  } finally { cleanup(value); }
});

test("enforces the explicit state order and makes repeated transitions no-ops", () => {
  const value = fixture();
  try {
    assertCode(thrown(() => value.journal.transition("service_registered")), "INVALID_TRANSITION");
    assertCode(thrown(() => value.journal.transition("unknown_state")), "UNKNOWN_STATE");
    assertCode(thrown(() => value.journal.transition("app_verified", { at: "not-a-timestamp" })), "INVALID_TIME");
  } finally { cleanup(value); }
});

test("walks every state, records metadata, and rerunning a completed state is idempotent", () => {
  const value = fixture();
  try {
    for (let index = 1; index < SETUP_STATES.length; index += 1) {
      const result = value.journal.transition(SETUP_STATES[index], {
        at: `2030-01-01T00:00:${String(index).padStart(2, "0")}.000Z`,
        details: index === 1 ? { platform: "macos", verification: "developer_id" } : {}
      });
      assert.equal(result.changed, true);
      assert.equal(result.state, SETUP_STATES[index]);
      assert.equal(result.revision, index);
    }
    const noOp = value.journal.transition("complete", { details: { ignored: true } });
    assert.equal(noOp.changed, false);
    assert.equal(noOp.revision, SETUP_STATES.length - 1);
    assert.equal(value.journal.status().next_actions.length, 0);
    const raw = value.journal.read();
    assert.deepEqual(raw.history.map((entry) => entry.state), SETUP_STATES);
    assert.deepEqual(raw.history[1].details, { platform: "macos", verification: "developer_id" });
  } finally { cleanup(value); }
});

test("rejects rollback transitions and unsafe transition details", () => {
  const value = fixture();
  try {
    value.journal.transition("app_verified", { at: "2030-01-01T00:00:01.000Z" });
    assertCode(thrown(() => value.journal.transition("not_started")), "ROLLBACK_REJECTED");
    assertCode(thrown(() => value.journal.transition("local_config_initialized", { at: "2029-12-31T23:59:59.000Z" })), "INVALID_TIME");
    assertCode(thrown(() => value.journal.transition("local_config_initialized", { details: { access_token: "never" } })), "INVALID_DETAILS");
    assertCode(thrown(() => value.journal.transition("local_config_initialized", { details: { nested: { value: true } } })), "INVALID_DETAILS");
  } finally { cleanup(value); }
});

test("recovers an anchor-first crash and an already-written-journal crash", () => {
  const anchorFirst = fixture();
  try {
    const initialJournal = fs.readFileSync(anchorFirst.paths.journalPath);
    anchorFirst.journal.transition("app_verified", { at: "2030-01-01T00:00:01.000Z" });
    const candidateAnchor = fs.readFileSync(anchorFirst.paths.anchorPath);
    fs.writeFileSync(anchorFirst.paths.journalPath, initialJournal, { mode: 0o600 });
    fs.chmodSync(anchorFirst.paths.journalPath, 0o600);
    const recovered = loadSetupJournal({ directory: anchorFirst.directory });
    assert.equal(recovered.status().state, "app_verified");
    assert.deepEqual(fs.readFileSync(anchorFirst.paths.anchorPath), candidateAnchor);
  } finally { cleanup(anchorFirst); }

  const journalFirst = fixture();
  try {
    const initialAnchor = fs.readFileSync(journalFirst.paths.anchorPath);
    journalFirst.journal.transition("app_verified", { at: "2030-01-01T00:00:01.000Z" });
    const nextJournal = fs.readFileSync(journalFirst.paths.journalPath);
    fs.writeFileSync(journalFirst.paths.anchorPath, initialAnchor, { mode: 0o600 });
    fs.chmodSync(journalFirst.paths.anchorPath, 0o600);
    const recovered = loadSetupJournal({ directory: journalFirst.directory });
    assert.equal(recovered.status().state, "app_verified");
    assert.deepEqual(fs.readFileSync(journalFirst.paths.journalPath), nextJournal);
    assert.equal(readJson(journalFirst.paths.anchorPath).tip.state, "app_verified");
  } finally { cleanup(journalFirst); }
});

test("fails closed on tampered, unknown, and rolled-back durable state", () => {
  const tampered = fixture();
  try {
    const journal = readJson(tampered.paths.journalPath);
    journal.state = "app_verified";
    writeJson(tampered.paths.journalPath, journal);
    assertCode(thrown(() => loadSetupJournal({ directory: tampered.directory }).status()), "TAMPERED_JOURNAL");
  } finally { cleanup(tampered); }

  const unknown = fixture();
  try {
    const journal = readJson(unknown.paths.journalPath);
    journal.state = "future_state";
    writeJson(unknown.paths.journalPath, journal);
    assertCode(thrown(() => loadSetupJournal({ directory: unknown.directory }).status()), "UNKNOWN_STATE");
  } finally { cleanup(unknown); }

  const rollback = fixture();
  try {
    const initialJournal = fs.readFileSync(rollback.paths.journalPath);
    rollback.journal.transition("app_verified", { at: "2030-01-01T00:00:01.000Z" });
    rollback.journal.transition("local_config_initialized", { at: "2030-01-01T00:00:02.000Z" });
    fs.writeFileSync(rollback.paths.journalPath, initialJournal, { mode: 0o600 });
    fs.chmodSync(rollback.paths.journalPath, 0o600);
    assertCode(thrown(() => loadSetupJournal({ directory: rollback.directory }).status()), "ROLLBACK_DETECTED");
  } finally { cleanup(rollback); }
});

test("refuses symlinked or group/world-accessible journal storage", () => {
  const linked = fixture();
  try {
    const victim = path.join(linked.root, "victim.json");
    fs.writeFileSync(victim, "unchanged\n", { mode: 0o600 });
    fs.unlinkSync(linked.paths.journalPath);
    fs.symlinkSync(victim, linked.paths.journalPath);
    assertCode(thrown(() => loadSetupJournal({ directory: linked.directory }).status()), "TAMPERED_JOURNAL");
    assert.equal(fs.readFileSync(victim, "utf8"), "unchanged\n");
  } finally { cleanup(linked); }

  const permissive = fixture();
  try {
    fs.chmodSync(permissive.paths.anchorPath, 0o644);
    assertCode(thrown(() => loadSetupJournal({ directory: permissive.directory }).status()), "TAMPERED_ANCHOR");
  } finally { cleanup(permissive); }

  const hardlinked = fixture();
  try {
    fs.linkSync(hardlinked.paths.journalPath, path.join(hardlinked.root, "journal-copy.json"));
    assertCode(thrown(() => loadSetupJournal({ directory: hardlinked.directory }).status()), "TAMPERED_JOURNAL");
  } finally { cleanup(hardlinked); }

  const linkedDirectory = fixture();
  try {
    const real = path.join(linkedDirectory.root, "real");
    fs.mkdirSync(real, { mode: 0o700 });
    const alias = path.join(linkedDirectory.root, "alias");
    fs.symlinkSync(real, alias, "dir");
    assertCode(thrown(() => createSetupJournal({ directory: alias })), "UNSAFE_STORAGE");
  } finally { cleanup(linkedDirectory); }
});

test("returns defensive next actions and supports the functional status API", () => {
  const value = fixture();
  try {
    const actions = nextActionsForState("not_started");
    actions[0].command = "mutated";
    assert.equal(nextActionsForState("not_started")[0].command, "agentpass setup continue");
    assert.equal(readSetupJournal({ directory: value.directory }).state, "not_started");
  } finally { cleanup(value); }
});
