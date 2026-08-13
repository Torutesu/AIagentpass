import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  USER_PURGE_CODES,
  executeUserStatePurge,
  planUserStatePurge,
  runUserStatePurge,
} from "../lib/platform-user-purge.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-user-purge-"));
  const home = path.join(root, "home");
  const state = path.join(home, ".agentpass");
  fs.mkdirSync(path.join(state, "sessions"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(state, "config.json"), "{}\n", { mode: 0o600 });
  fs.writeFileSync(path.join(state, "sessions", "one.json"), "{}\n", {
    mode: 0o600,
  });
  fs.writeFileSync(path.join(home, "keep.txt"), "keep", { mode: 0o600 });
  return { root, home, state };
}

const options = (value, extra = {}) => ({
  homeDir: value.home,
  uid: process.getuid(),
  randomBytes: () => Buffer.alloc(16, 0xa5),
  ...extra,
});

test("current-user purge previews, requires explicit confirmation, and preserves unrelated home data", () => {
  const value = fixture();
  try {
    const plan = planUserStatePurge(options(value));
    assert.equal(plan.code, USER_PURGE_CODES.PLAN_READY);
    assert.equal(plan.state, "present");
    assert.throws(() => executeUserStatePurge(plan, options(value)), {
      code: USER_PURGE_CODES.CONFIRMATION_REQUIRED,
    });
    const result = executeUserStatePurge(
      plan,
      options(value, { confirm: "PURGE_USER_STATE" }),
    );
    assert.equal(result.code, USER_PURGE_CODES.COMPLETE);
    assert.equal(fs.existsSync(value.state), false);
    assert.equal(
      fs.readFileSync(path.join(value.home, "keep.txt"), "utf8"),
      "keep",
    );
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test("current-user purge is idempotent when state was absent at preview", () => {
  const value = fixture();
  try {
    fs.rmSync(value.state, { recursive: true });
    const plan = planUserStatePurge(options(value));
    const result = executeUserStatePurge(
      plan,
      options(value, { confirm: "PURGE_USER_STATE" }),
    );
    assert.equal(result.code, USER_PURGE_CODES.NOOP);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test("native current-user purge revokes only its Agent before deleting local state", async () => {
  const value = fixture();
  let revoked = false;
  try {
    const result = await runUserStatePurge({
      ...options(value),
      execute: true,
      confirm: "PURGE_USER_STATE",
      native: { enabled: true },
      agentId: "agent-1",
      requestNative: async (request) => {
        assert.deepEqual(request, {
          operation: "native.session.revoke-agent",
          agent_id: "agent-1",
        });
        assert.equal(fs.existsSync(value.state), true);
        revoked = true;
        return {
          stdout_base64: Buffer.from(
            JSON.stringify({ generation: 1, revoked_sessions: 1 }),
          ).toString("base64"),
        };
      },
    });
    assert.equal(revoked, true);
    assert.equal(result.code, USER_PURGE_CODES.COMPLETE);
    assert.equal(fs.existsSync(value.state), false);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test("current-user purge rejects symlinks, hardlinks, mutation, and quarantine substitution", () => {
  for (const kind of ["symlink", "hardlink"]) {
    const value = fixture();
    try {
      const file = path.join(value.state, "config.json");
      if (kind === "symlink") {
        fs.rmSync(file);
        fs.symlinkSync(path.join(value.home, "keep.txt"), file);
      } else {
        fs.linkSync(file, `${file}.hard`);
      }
      assert.throws(() => planUserStatePurge(options(value)), {
        code: USER_PURGE_CODES.UNSAFE_TARGET,
      });
    } finally {
      fs.rmSync(value.root, { recursive: true, force: true });
    }
  }

  const changed = fixture();
  try {
    const plan = planUserStatePurge(options(changed));
    fs.writeFileSync(path.join(changed.state, "config.json"), "changed\n");
    assert.throws(
      () =>
        executeUserStatePurge(
          plan,
          options(changed, { confirm: "PURGE_USER_STATE" }),
        ),
      { code: USER_PURGE_CODES.UNSAFE_TARGET },
    );
  } finally {
    fs.rmSync(changed.root, { recursive: true, force: true });
  }

  const raced = fixture();
  try {
    const plan = planUserStatePurge(options(raced));
    const racing = Object.create(fs);
    let firstRename = true;
    racing.renameSync = (source, destination) => {
      if (!firstRename) return fs.renameSync(source, destination);
      firstRename = false;
      fs.renameSync(source, `${source}.original`);
      fs.mkdirSync(source, { mode: 0o700 });
      fs.writeFileSync(path.join(source, "replacement"), "must survive", {
        mode: 0o600,
      });
      fs.renameSync(source, destination);
    };
    assert.throws(
      () =>
        executeUserStatePurge(
          plan,
          options(raced, { fs: racing, confirm: "PURGE_USER_STATE" }),
        ),
      { code: USER_PURGE_CODES.UNSAFE_TARGET },
    );
    assert.equal(
      fs.readFileSync(path.join(raced.state, "replacement"), "utf8"),
      "must survive",
    );
  } finally {
    fs.rmSync(raced.root, { recursive: true, force: true });
  }
});

test("agentpass uninstall exposes preview and confirmed current-user purge", () => {
  const value = fixture();
  const cli = path.resolve("bin/agentpass.mjs");
  const run = (args) =>
    spawnSync(
      process.execPath,
      [cli, "uninstall", "--purge-user-state", ...args],
      {
        cwd: path.resolve("."),
        encoding: "utf8",
        env: { ...process.env, HOME: value.home },
      },
    );
  try {
    fs.rmSync(value.state, { recursive: true });
    const initialized = spawnSync(process.execPath, [cli, "init"], {
      cwd: path.resolve("."),
      encoding: "utf8",
      env: { ...process.env, HOME: value.home },
    });
    assert.equal(initialized.status, 0, initialized.stderr);
    const preview = run([]);
    assert.equal(preview.status, 0, preview.stderr);
    assert.equal(JSON.parse(preview.stdout).dryRun, true);
    const denied = run(["--execute"]);
    assert.notEqual(denied.status, 0);
    assert.equal(fs.existsSync(value.state), true);
    const executed = run(["--confirm", "PURGE_USER_STATE", "--execute"]);
    assert.equal(executed.status, 0, executed.stderr);
    assert.equal(JSON.parse(executed.stdout).code, USER_PURGE_CODES.COMPLETE);
    assert.equal(fs.existsSync(value.state), false);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});
