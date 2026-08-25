import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { performUpgradePreservesState } from "./upgrade-preserves-state";
const base = {
  artifactSha256: "a".repeat(64),
  sourceCommit: "b".repeat(40),
  teamId: "ABCDE12345",
  codeIdentities: [
    {
      path: "AgentPass.app",
      bundle_id: "dev.agentpass",
      team_id: "ABCDE12345",
      code_directory_hash: "current",
    },
  ],
};
const fp = `SHA256:${"A".repeat(43)}`;
const make = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "p0c-upgrade-")),
    checkpoint = path.join(root, "checkpoint");
  fs.mkdirSync(checkpoint, { mode: 0o700 });
  const prev = path.join(root, "previous.pkg"),
    cfg = path.join(root, "previous.json"),
    current = path.join(root, "current.pkg");
  fs.writeFileSync(prev, "previous", { mode: 0o600 });
  fs.writeFileSync(current, "current", { mode: 0o600 });
  const body = {
    schema_version: 1,
    artifact_sha256: "c".repeat(64),
    key_fingerprint: fp,
    notarization_ticket_sha256: "d".repeat(64),
    package_id: "dev.agentpass.installer",
    package_sha256: crypto
      .createHash("sha256")
      .update("previous")
      .digest("hex"),
    source_commit: "e".repeat(40),
    team_id: "ABCDE12345",
  };
  body.config_sha256 = crypto
    .createHash("sha256")
    .update(Buffer.from(`${JSON.stringify(body, null, 2)}\n`))
    .digest("hex");
  fs.writeFileSync(cfg, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(
    path.join(checkpoint, "candidate-checkpoint.json"),
    "old\n",
    { mode: 0o600 },
  );
  return { root, checkpoint, prev, cfg, current };
};
const machine = (d) => ({
  applicationPath: "/Applications/AgentPass.app",
  serviceConfigPath:
    "/Library/Application Support/AgentPass/native-service.json",
  checkpointDirectory: d,
  executables: { native_service: { path: "/service", sha256: "f".repeat(64) } },
});
const ok = (s = "") => ({
  ok: true,
  exitCode: 0,
  signal: null,
  stdout: Buffer.from(s),
  stderr: Buffer.alloc(0),
});
const nat = (v) =>
  ok(
    `${JSON.stringify({ error: null, ok: true, public_key: null, stdout_base64: Buffer.from(JSON.stringify(v)).toString("base64"), version: 13 })}\n`,
  );
test("upgrade installs exact current package and preserves key/audit/checkpoint state", async () => {
  const f = make(),
    release = {
      ...base,
      artifactPath: f.current,
      artifactSha256: crypto
        .createHash("sha256")
        .update("current")
        .digest("hex"),
    };
  let entries = 2;
  const run = async (c, a) => {
    if (c === "/usr/sbin/installer")
      fs.writeFileSync(
        path.join(f.checkpoint, "candidate-checkpoint.json"),
        "new\n",
        { mode: 0o600 },
      );
    return ok("verified\n");
  };
  const pin = async (_e, a) => {
    if (a[1] === "qualify")
      return nat({
        private_exportable: false,
        secure_enclave: true,
        public_key_fingerprint: fp,
      });
    if (a[1] === "key")
      return nat({
        fingerprint: fp,
        public_key_pem:
          "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n",
      });
    if (a[1] === "audit-status")
      return nat({ valid: true, entries: entries++ });
    throw Error("unexpected native action");
  };
  try {
    assert.deepEqual(
      await performUpgradePreservesState({
        release,
        machine: machine(f.checkpoint),
        production: false,
        getUid: () => 0,
        previousPackagePath: f.prev,
        previousConfigPath: f.cfg,
        runCommand: run,
        runPinned: pin,
        withCheckpoint: async (_p, o) => o(),
        readCodeIdentity: () => ({
          bundle_id: "dev.agentpass",
          team_id: "ABCDE12345",
          code_directory_hash: "current",
        }),
        verifyCheckpoint: () => true,
      }),
      ["upgrade-preserves-state"],
    );
    assert.equal(
      fs.existsSync(path.join(f.checkpoint, "upgrade-preserves-state.json")),
      false,
    );
  } finally {
    fs.rmSync(f.root, { recursive: true, force: true });
  }
});
test("upgrade refuses rootless, rollback, and non-fixed production inputs", async () => {
  const f = make(),
    release = {
      ...base,
      artifactPath: f.current,
      artifactSha256: crypto
        .createHash("sha256")
        .update("current")
        .digest("hex"),
    };
  try {
    await assert.rejects(
      () =>
        performUpgradePreservesState({
          release,
          machine: machine(f.checkpoint),
          production: false,
          getUid: () => 501,
        }),
      /root/u,
    );
    await assert.rejects(
      () =>
        performUpgradePreservesState({
          release: {
            ...release,
            artifactSha256: "c".repeat(64),
            sourceCommit: "e".repeat(40),
          },
          machine: machine(f.checkpoint),
          production: false,
          getUid: () => 0,
          previousPackagePath: f.prev,
          previousConfigPath: f.cfg,
          withCheckpoint: async (_p, o) => o(),
        }),
      /distinct/u,
    );
    await assert.rejects(
      () =>
        performUpgradePreservesState({
          release,
          machine: machine(f.checkpoint),
          production: true,
          getUid: () => 0,
          previousPackagePath: f.prev,
          previousConfigPath: f.cfg,
          withCheckpoint: async (_p, o) => o(),
        }),
      /fixed protected paths/u,
    );
    const s = fs.readFileSync(
      new URL("./upgrade-preserves-state", import.meta.url),
      "utf8",
    );
    assert.match(s, /\/usr\/sbin\/installer/u);
    assert.match(s, /stapler/u);
    assert.doesNotMatch(s, /shell\s*:\s*true|rm\s+-rf|git\s+checkout/iu);
  } finally {
    fs.rmSync(f.root, { recursive: true, force: true });
  }
});
test("upgrade resume revalidates and binds the original candidate checkpoint", async () => {
  const f = make();
  const release = { ...base, artifactPath: f.current, artifactSha256: crypto.createHash("sha256").update("current").digest("hex") };
  const marker = path.join(f.checkpoint, "upgrade-preserves-state.json");
  fs.writeFileSync(marker, `${JSON.stringify({ schema_version: 1, phase: "upgrade-started", artifact_sha256: release.artifactSha256, source_commit: release.sourceCommit, team_id: release.teamId, previous_package_sha256: crypto.createHash("sha256").update("previous").digest("hex"), checkpoint_sha256: "f".repeat(64), key_fingerprint: fp, pre_audit_entries: 2, pre_audit_sha256: "d".repeat(64) }, null, 2)}\n`, { mode: 0o600 });
  try {
    let verified = false;
    await assert.rejects(() => performUpgradePreservesState({ release, machine: machine(f.checkpoint), production: false, getUid: () => 0, previousPackagePath: f.prev, previousConfigPath: f.cfg, marker, verifyCheckpoint: () => { verified = true; } }), /checkpoint binding mismatch/u);
    assert.equal(verified, true);
  } finally {
    fs.rmSync(f.root, { recursive: true, force: true });
  }
});
