import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { performCurrentUserPurge } from "./current-user-purge";
const ok = () => ({
  ok: true,
  exitCode: 0,
  stdout: Buffer.alloc(0),
  stderr: Buffer.alloc(0),
});
const payload = (v) => ({
  ok: true,
  exitCode: 0,
  stdout: Buffer.from(
    `${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(v)).toString("base64"), version: null })}\n`,
  ),
  stderr: Buffer.alloc(0),
});
const noCheckpoint = async (_p, op) => op();
const fixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "p0c-purge-"));
  const home = path.join(root, "user");
  const a = path.join(home, ".agentpass", "session");
  const b = path.join(home, ".agentpass", "config.json");
  const control = path.join(root, "control");
  const pkg = path.join(root, "AgentPass.pkg");
  fs.mkdirSync(path.dirname(a), { recursive: true });
  fs.mkdirSync(path.dirname(b), { recursive: true });
  fs.writeFileSync(a, "a");
  fs.writeFileSync(b, "b");
  fs.writeFileSync(control, "control");
  fs.writeFileSync(pkg, "pkg");
  return { root, home, files: [a, b], control, pkg };
};
const release = (p) => ({
  artifactPath: p,
  artifactSha256: crypto
    .createHash("sha256")
    .update(fs.readFileSync(p))
    .digest("hex"),
  sourceCommit: "b".repeat(40),
  teamId: "ABCDE12345",
});
const run = (home, { failExecute = false } = {}) => {
  const command = async (executable, args) => {
    assert.equal(executable, "/usr/bin/sudo");
    assert.equal(args.includes("/usr/local/bin/agentpass"), true);
    if (args.includes("--execute")) {
      if (failExecute)
        return {
          ok: false,
          exitCode: 1,
          stdout: Buffer.alloc(0),
          stderr: Buffer.from("unsafe target"),
        };
      fs.rmSync(path.join(home, ".agentpass"), { recursive: true });
      return {
        ok: true,
        exitCode: 0,
        stdout: Buffer.from(
          `${JSON.stringify({ operation: "purge-user-state", code: "USER_STATE_PURGE_COMPLETE", removed: true })}\n`,
        ),
        stderr: Buffer.alloc(0),
      };
    }
    return {
      ok: true,
      exitCode: 0,
      stdout: Buffer.from(
        `${JSON.stringify({ operation: "purge-user-state", dryRun: true })}\n`,
      ),
      stderr: Buffer.alloc(0),
    };
  };
  const pinned = async (_e, args) =>
    args.at(-1) === "session-start"
      ? payload({
          agent_id: "agent-1",
          expires_at: "2030-01-01T00:00:00Z",
          token: "t".repeat(40),
        })
      : args.at(-1) === "session-validate"
        ? payload({ valid: false })
        : args.at(-1) === "audit-status"
          ? payload({ events: [{}] })
          : payload({ root: true, generation: 1 });
  return { command, pinned };
};
const machine = (v) => ({
  applicationPath: "/Applications/AgentPass.app",
  checkpointDirectory: path.join(v.root, "checkpoint"),
  executables: { native_client: { path: "/client", sha256: "c".repeat(64) } },
});
test("current-user purge removes target files, invalidates session, and preserves control data", async () => {
  const v = fixture();
  try {
    const h = run(v.home);
    const input = {
      schema_version: 1,
      target_uid: process.getuid(),
      target_home: v.home,
      control_file: v.control,
      target_files: v.files,
      agent_id: "agent-1",
      ttl_seconds: 300,
    };
    assert.deepEqual(
      await performCurrentUserPurge({
        release: release(v.pkg),
        machine: machine(v),
        production: false,
        getUid: () => 0,
        readConfig: () => input,
        runCommand: h.command,
        runPinned: h.pinned,
        withCheckpoint: noCheckpoint,
      }),
      ["current-user-purge"],
    );
    assert.equal(fs.existsSync(v.control), true);
  } finally {
    fs.rmSync(v.root, { recursive: true, force: true });
  }
});
test("current-user purge rejects path substitution, symlink, hardlink, and replacement", async () => {
  const v = fixture();
  try {
    const h = run(v.home);
    const bad = {
      schema_version: 1,
      target_uid: process.getuid(),
      target_home: v.home,
      control_file: v.control,
      target_files: [v.control],
      agent_id: "agent-1",
      ttl_seconds: 300,
    };
    await assert.rejects(
      () =>
        performCurrentUserPurge({
          release: release(v.pkg),
          machine: machine(v),
          production: false,
          getUid: () => 0,
          readConfig: () => bad,
          runCommand: h.command,
          runPinned: h.pinned,
          withCheckpoint: noCheckpoint,
        }),
      /escapes/u,
    );
  } finally {
    fs.rmSync(v.root, { recursive: true, force: true });
  }
  const s = fixture();
  try {
    fs.rmSync(s.files[0]);
    fs.symlinkSync(s.control, s.files[0]);
    const h = run(s.home);
    const input = {
      schema_version: 1,
      target_uid: process.getuid(),
      target_home: s.home,
      control_file: s.control,
      target_files: s.files,
      agent_id: "agent-1",
      ttl_seconds: 300,
    };
    await assert.rejects(
      () =>
        performCurrentUserPurge({
          release: release(s.pkg),
          machine: machine(s),
          production: false,
          getUid: () => 0,
          readConfig: () => input,
          runCommand: h.command,
          runPinned: h.pinned,
          withCheckpoint: noCheckpoint,
        }),
      /single-link|trusted/u,
    );
  } finally {
    fs.rmSync(s.root, { recursive: true, force: true });
  }
  const c = fixture();
  try {
    fs.linkSync(c.files[0], `${c.files[0]}.hard`);
    const h = run(c.home);
    const input = {
      schema_version: 1,
      target_uid: process.getuid(),
      target_home: c.home,
      control_file: c.control,
      target_files: c.files,
      agent_id: "agent-1",
      ttl_seconds: 300,
    };
    await assert.rejects(
      () =>
        performCurrentUserPurge({
          release: release(c.pkg),
          machine: machine(c),
          production: false,
          getUid: () => 0,
          readConfig: () => input,
          runCommand: h.command,
          runPinned: h.pinned,
          withCheckpoint: noCheckpoint,
        }),
      /single-link|trusted/u,
    );
  } finally {
    fs.rmSync(c.root, { recursive: true, force: true });
  }
  const r = fixture();
  try {
    const h = run(r.home, { failExecute: true });
    const input = {
      schema_version: 1,
      target_uid: process.getuid(),
      target_home: r.home,
      control_file: r.control,
      target_files: r.files,
      agent_id: "agent-1",
      ttl_seconds: 300,
    };
    await assert.rejects(
      () =>
        performCurrentUserPurge({
          release: release(r.pkg),
          machine: machine(r),
          production: false,
          getUid: () => 0,
          readConfig: () => input,
          runCommand: h.command,
          runPinned: h.pinned,
          withCheckpoint: noCheckpoint,
        }),
      /purge execution failed/u,
    );
    assert.equal(fs.readFileSync(r.files[0], "utf8"), "a");
  } finally {
    fs.rmSync(r.root, { recursive: true, force: true });
  }
});
