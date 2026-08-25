import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  classifyClockEffect,
  performSleepWakeNetworkClock,
} from "./sleep-wake-network-clock";

const release = {
  artifactSha256: "a".repeat(64),
  sourceCommit: "b".repeat(40),
  teamId: "ABCDE12345",
};
const successful = (s = "") => ({
  ok: true,
  exitCode: 0,
  signal: null,
  stdout: Buffer.from(s),
  stderr: Buffer.alloc(0),
});
const failed = () => ({
  ok: false,
  exitCode: 1,
  signal: null,
  stdout: Buffer.alloc(0),
  stderr: Buffer.from("denied"),
});
const machine = (d) => ({
  applicationPath: "/Applications/AgentPass.app",
  serviceLabel: "dev.agentpass.native-service",
  checkpointDirectory: d,
  cloudProbeURL: "https://qualification.invalid/probe",
  executables: { native_client: { path: "/client", sha256: "c".repeat(64) } },
});
const outer = (v) =>
  successful(
    `${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(v)).toString("base64"), version: 13 })}\n`,
  );
const fixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "p0c-sleep-"));
  const checkpoint = path.join(root, "checkpoint");
  fs.mkdirSync(checkpoint, { mode: 0o700 });
  return { root, checkpoint };
};
test("clock rollback/forward is detected while monotonic time remains authoritative", () => {
  assert.equal(
    classifyClockEffect({
      beforeWallMs: 10000,
      afterWallMs: 1000,
      beforeMonotonicNs: 1n,
      afterMonotonicNs: 10000000001n,
    }).wall_clock_effect,
    "rollback",
  );
  assert.equal(
    classifyClockEffect({
      beforeWallMs: 10000,
      afterWallMs: 40000,
      beforeMonotonicNs: 1n,
      afterMonotonicNs: 10000000001n,
    }).wall_clock_effect,
    "forward",
  );
  assert.throws(
    () =>
      classifyClockEffect({
        beforeWallMs: 1,
        afterWallMs: 2,
        beforeMonotonicNs: 2n,
        afterMonotonicNs: 1n,
      }),
    /monotonic/u,
  );
});
test("sleep/wake retries after a real marker, recovers network/control, and denies stale authority", async () => {
  const f = fixture();
  let after = false,
    validate = 0;
  const run = async (c, a) => {
    if (c === "/usr/sbin/sysctl") return successful("{ sec = 1, usec = 2 }\n");
    if (c === "/bin/date")
      return successful(after ? "1000000100\n" : "1000000000\n");
    if (c === "/usr/bin/perl")
      return successful(after ? "20000000000\n" : "10000000000\n");
    if (c === "/usr/bin/pmset" && a[0] === "sleepnow") return successful();
    if (c === "/usr/bin/pmset") return successful("Sleep\nWake\n");
    if (c === "/sbin/ifconfig") return successful("en0: status: active\n");
    if (c === "/usr/bin/curl")
      return a.includes("5") && !a.includes("15") ? failed() : successful("ok");
    throw Error(c);
  };
  const pin = async (_e, a) => {
    if (a.at(-1) === "control-status")
      return outer({ control_operational: true, control_expired: false });
    if (a.at(-1) === "control-refresh")
      return outer({ control_operational: true, control_expired: false });
    if (a.at(-1) === "control-validate")
      return outer({ valid: validate++ !== 0 });
    throw Error(a.join(" "));
  };
  try {
    await assert.rejects(
      () =>
        performSleepWakeNetworkClock({
          release,
          machine: machine(f.checkpoint),
          production: false,
          getUid: () => 0,
          runCommand: run,
          runPinned: pin,
          withCheckpoint: async (_p, o) => o(),
        }),
      /pending/u,
    );
    after = true;
    assert.deepEqual(
      await performSleepWakeNetworkClock({
        release,
        machine: machine(f.checkpoint),
        production: false,
        getUid: () => 0,
        runCommand: run,
        runPinned: pin,
        withCheckpoint: async (_p, o) => o(),
      }),
      ["sleep-wake-recovery", "network-clock-failure"],
    );
    assert.equal(
      fs.existsSync(path.join(f.checkpoint, "sleep-wake-network-clock.json")),
      false,
    );
  } finally {
    fs.rmSync(f.root, { recursive: true, force: true });
  }
});
test("sleep/wake fails closed for non-root, tampered marker, and unsafe time mutation", async () => {
  const f = fixture();
  try {
    await assert.rejects(
      () =>
        performSleepWakeNetworkClock({
          release,
          machine: machine(f.checkpoint),
          production: false,
          getUid: () => 501,
        }),
      /root/u,
    );
    fs.writeFileSync(
      path.join(f.checkpoint, "sleep-wake-network-clock.json"),
      "{}\n",
      { mode: 0o600 },
    );
    await assert.rejects(
      () =>
        performSleepWakeNetworkClock({
          release,
          machine: machine(f.checkpoint),
          production: false,
          getUid: () => 0,
          withCheckpoint: async (_p, o) => o(),
        }),
      /marker/u,
    );
    const s = fs.readFileSync(
      new URL("./sleep-wake-network-clock", import.meta.url),
      "utf8",
    );
    assert.match(s, /sleepnow/u);
    assert.doesNotMatch(s, /date\s+(-s|--set)/u);
  } finally {
    fs.rmSync(f.root, { recursive: true, force: true });
  }
});
