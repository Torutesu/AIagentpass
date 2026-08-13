import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";

import {
  buildP0BQualificationReport,
  canonicalJson,
  digestArtifactFile,
  digestArtifactTree,
  parseP0BQualificationReport,
  P0B_REQUIRED_COMMAND_IDS,
  P0B_REQUIRED_GATE_IDS,
  resolveSourceCommit,
  serializeP0BQualificationReport,
  writeP0BQualificationReport
} from "./report.mjs";

const repositoryRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../..");
let fixtureDirectory;
let verifiedArtifact;

before(async () => {
  fixtureDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-fixture-"));
  const artifactFile = path.join(fixtureDirectory, "console-dist");
  await fs.writeFile(artifactFile, "verified fixture artifact", { mode: 0o600 });
  verifiedArtifact = await digestArtifactFile(artifactFile, { name: "console-dist", kind: "build" });
});

after(async () => {
  await fs.rm(fixtureDirectory, { recursive: true, force: true });
});

const baseInput = () => ({
  source_commit: "0123456789abcdef0123456789abcdef01234567",
  started_at: "2026-08-13T01:02:03.000Z",
  completed_at: "2026-08-13T01:04:05.000Z",
  commands: [{
    id: "browser-e2e",
    argv: ["node", "apps/web-console/e2e/p0-b-browser.spec.ts", "--project=chromium"],
    cwd: "/workspace/ai-coding-agent-claude-code-cursor",
    result: {
      status: "passed",
      exit_code: 0,
      signal: null,
      duration_ms: 1200,
      stdout: "secret-looking test output is hashed and never serialized",
      stderr: ""
    }
  }],
  postgres: {
    image: "postgres:17-alpine",
    image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    container_id: "0123456789abcdef0123456789abcdef",
    container_started_at: "2026-08-13T01:00:00.000Z",
    server_version: "17.5"
  },
  browser: { name: "Chromium", version: "140.0.7339.1", engine: "Playwright" },
  artifacts: [verifiedArtifact],
  gates: [{ id: P0B_REQUIRED_GATE_IDS[0], status: "passed", evidence_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
});

test("builds a provenance-bound canonical report with digested command output", () => {
  const report = buildP0BQualificationReport(baseInput());
  const bytes = serializeP0BQualificationReport(report);
  const text = bytes.toString("utf8");
  assert.equal(report.overall.status, "passed");
  assert.equal(text.endsWith("\n"), true);
  assert.equal(text.includes("secret-looking test output"), false);
  assert.equal(text.includes('"stdout"'), false);
  assert.equal(parseP0BQualificationReport(bytes).report_digest, report.report_digest);
  assert.equal(canonicalJson({ b: 1, a: [true, null] }), '{"a":[true,null],"b":1}');
});

test("a skipped gate is converted to a failed gate and can never qualify", () => {
  const input = baseInput();
  input.gates[0] = { id: "browser-flow", status: "skipped", reason: "operator_not_present" };
  const report = buildP0BQualificationReport(input);
  assert.equal(report.overall.status, "failed");
  assert.deepEqual(report.overall.failed_gates, ["browser-flow"]);
  assert.deepEqual(report.gates[0], { id: "browser-flow", status: "failed", evidence_sha256: null, reason: "gate_skipped" });
  assert.equal(JSON.stringify(report).includes('"status":"skipped"'), false);
});

test("rejects secret-bearing commands and PostgreSQL URLs with userinfo", () => {
  const password = baseInput();
  password.commands[0].argv = ["curl", "--password=do-not-record"];
  assert.throws(() => buildP0BQualificationReport(password), { code: "unsafe_string" });

  const key = baseInput();
  key.commands[0].argv = ["agentpass", "--key=do-not-record"];
  assert.throws(() => buildP0BQualificationReport(key), { code: "unsafe_string" });

  const userinfo = baseInput();
  userinfo.commands[0].argv = ["node", "postgresql://user:password@localhost/db"];
  assert.throws(() => buildP0BQualificationReport(userinfo), { code: "unsafe_string" });

  const extra = baseInput();
  extra.gates[0].cookie = "never accepted";
  assert.throws(() => buildP0BQualificationReport(extra), { code: "unknown_field" });
});

test("requires the canonical command and gate ids in canonical order", () => {
  assert.deepEqual(P0B_REQUIRED_COMMAND_IDS, ["browser-e2e"]);
  assert.deepEqual(P0B_REQUIRED_GATE_IDS, ["browser-flow"]);

  const command = baseInput();
  command.commands[0].id = "renamed-browser-e2e";
  assert.throws(() => buildP0BQualificationReport(command), { code: "invalid_command_ids" });

  const gate = baseInput();
  gate.gates[0].id = "renamed-browser-flow";
  assert.throws(() => buildP0BQualificationReport(gate), { code: "invalid_gate_ids" });

  const missing = baseInput();
  missing.gates = [];
  assert.throws(() => buildP0BQualificationReport(missing), { code: "invalid_gate_ids" });
});

test("optionally binds supplied source commit to the repository HEAD", () => {
  const input = baseInput();
  input.source_commit = resolveSourceCommit(repositoryRoot);
  assert.equal(buildP0BQualificationReport(input, { repositoryRoot }).source_commit, input.source_commit);

  const mismatch = baseInput();
  assert.throws(() => buildP0BQualificationReport(mismatch, { repositoryRoot }), { code: "source_commit_mismatch" });
});

test("rejects caller-supplied artifact metadata and accepts only digested descriptors", () => {
  const input = baseInput();
  input.artifacts = [{
    name: verifiedArtifact.name,
    kind: verifiedArtifact.kind,
    sha256: verifiedArtifact.sha256,
    bytes: verifiedArtifact.bytes
  }];
  assert.throws(() => buildP0BQualificationReport(input), { code: "untrusted_artifact" });

  const cloned = baseInput();
  cloned.artifacts = [structuredClone(verifiedArtifact)];
  assert.throws(() => buildP0BQualificationReport(cloned), { code: "untrusted_artifact" });
});

test("artifact digest helper binds bytes without exposing the artifact path", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-"));
  const artifact = path.join(directory, "candidate.pkg");
  try {
    await fs.writeFile(artifact, "candidate bytes", { mode: 0o600 });
    const digest = await digestArtifactFile(artifact, { name: "candidate-pkg", kind: "installer" });
    assert.equal(digest.name, "candidate-pkg");
    assert.equal(digest.kind, "installer");
    assert.equal(digest.bytes, 15);
    assert.equal(Object.hasOwn(digest, "path"), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("artifact tree digest is deterministic, path-aware, mode-aware, and provenance-bound", async () => {
  const first = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-"));
  const second = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-"));
  try {
    for (const directory of [first, second]) {
      await fs.mkdir(path.join(directory, "assets"));
      await fs.writeFile(path.join(directory, "assets", "app.js"), "same bytes", { mode: 0o644 });
      await fs.writeFile(path.join(directory, "index.html"), "entry", { mode: 0o644 });
    }
    const firstDigest = await digestArtifactTree(first, { name: "console-dist", kind: "build", maxFiles: 4, maxBytes: 1024 });
    const secondDigest = await digestArtifactTree(second, { name: "console-dist", kind: "build", maxFiles: 4, maxBytes: 1024 });
    assert.deepEqual(secondDigest, firstDigest);
    assert.equal(JSON.stringify(firstDigest).includes(first), false);
    assert.equal(JSON.stringify(firstDigest).includes("same bytes"), false);
    assert.doesNotThrow(() => buildP0BQualificationReport({ ...baseInput(), artifacts: [firstDigest] }));

    await fs.chmod(path.join(second, "assets", "app.js"), 0o755);
    const modeDigest = await digestArtifactTree(second, { name: "console-dist", kind: "build" });
    assert.notEqual(modeDigest.sha256, firstDigest.sha256);
  } finally {
    await fs.rm(first, { recursive: true, force: true });
    await fs.rm(second, { recursive: true, force: true });
  }
});

test("artifact tree canonicalizes ordering but rejects duplicate and case-conflicting names", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-names-"));
  try {
    await fs.mkdir(path.join(directory, "z").normalize("NFC"));
    await fs.writeFile(path.join(directory, "z", "file.txt"), "x");
    const ordered = await digestArtifactTree(directory, { name: "tree", kind: "build" });
    await fs.rename(path.join(directory, "z"), path.join(directory, "a"));
    await fs.mkdir(path.join(directory, "z"));
    await fs.writeFile(path.join(directory, "z", "file.txt"), "x");
    const reordered = await digestArtifactTree(directory, { name: "tree", kind: "build" });
    assert.notEqual(ordered.sha256, reordered.sha256, "changing a canonical path must change the digest");

    try {
      await fs.writeFile(path.join(directory, "Z"), "case collision");
      await assert.rejects(() => digestArtifactTree(directory), { code: "case_conflicting_artifact_entry" });
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "EISDIR") throw error;
      t.diagnostic("case-conflicting names cannot coexist on this filesystem");
    }

    const unicodeDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-unicode-"));
    try {
      await fs.writeFile(path.join(unicodeDirectory, "e\u0301.txt"), "one");
      try {
        await fs.writeFile(path.join(unicodeDirectory, "é.txt"), "two");
        const entries = await fs.readdir(unicodeDirectory);
        if (entries.length === 2) {
          await assert.rejects(() => digestArtifactTree(unicodeDirectory), { code: "duplicate_artifact_entry" });
        } else {
          t.diagnostic("Unicode-normalization-conflicting names alias on this filesystem");
        }
      } catch (error) {
        if (error?.code !== "EEXIST" && error?.code !== "EISDIR") throw error;
        t.diagnostic("Unicode-normalization-conflicting names cannot coexist on this filesystem");
      }
    } finally {
      await fs.rm(unicodeDirectory, { recursive: true, force: true });
    }
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("artifact tree rejects symlinks, hardlinks, non-regular entries, and unsafe permissions", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-unsafe-"));
  try {
    await fs.writeFile(path.join(directory, "real.txt"), "real", { mode: 0o644 });
    await fs.symlink("real.txt", path.join(directory, "link.txt"));
    await assert.rejects(() => digestArtifactTree(directory), { code: "unsafe_artifact_entry" });
    await fs.unlink(path.join(directory, "link.txt"));

    await fs.link(path.join(directory, "real.txt"), path.join(directory, "hardlink.txt"));
    await assert.rejects(() => digestArtifactTree(directory), { code: "unsafe_artifact_entry" });
    await fs.unlink(path.join(directory, "hardlink.txt"));

    if (process.platform !== "win32") {
      const { spawn } = await import("node:child_process");
      const fifo = path.join(directory, "pipe");
      await new Promise((resolve, reject) => {
        const child = spawn("mkfifo", [fifo], { stdio: "ignore" });
        child.once("error", reject);
        child.once("exit", (code) => code === 0 ? resolve() : reject(new Error("mkfifo failed")));
      });
      await assert.rejects(() => digestArtifactTree(directory), { code: "unsafe_artifact_entry" });
      await fs.unlink(fifo);
    } else {
      t.skip("non-regular FIFO entries are not available on Windows");
    }

    await fs.chmod(path.join(directory, "real.txt"), 0o666);
    await assert.rejects(() => digestArtifactTree(directory), { code: "unsafe_artifact_file" });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("artifact tree enforces file and byte bounds without exposing local paths", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-limits-"));
  try {
    await fs.writeFile(path.join(directory, "one.txt"), "1234");
    await fs.writeFile(path.join(directory, "two.txt"), "5678");
    await assert.rejects(() => digestArtifactTree(directory, { maxFiles: 1 }), { code: "artifact_too_many_files" });
    await assert.rejects(() => digestArtifactTree(directory, { maxBytes: 7 }), { code: "artifact_too_large" });
    await assert.rejects(() => digestArtifactTree(directory, { maxFiles: 0 }), { code: "invalid_artifact_limit" });
    await assert.rejects(() => digestArtifactTree(directory, { maxBytes: 0 }), { code: "invalid_artifact_limit" });
    await assert.rejects(() => digestArtifactTree(path.join(directory, "missing")), { code: "artifact_tree_read_failed" });
    await assert.rejects(() => digestArtifactTree(path.join(directory, "one.txt")), { code: "unsafe_artifact_tree" });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("artifact tree detects a file replaced or changed between stat and read", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-tree-race-"));
  const target = path.join(directory, "race.txt");
  const originalOpen = fs.open;
  try {
    await fs.writeFile(target, "stable", { mode: 0o644 });
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      const originalStat = handle.stat.bind(handle);
      let statCalls = 0;
      handle.stat = async (...statArgs) => {
        const stat = await originalStat(...statArgs);
        statCalls += 1;
        if (statCalls === 1 && args[0] === target) await fs.appendFile(target, "changed");
        return stat;
      };
      return handle;
    };
    await assert.rejects(() => digestArtifactTree(directory), { code: "artifact_changed" });
  } finally {
    fs.open = originalOpen;
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("writes canonical reports atomically with owner-only permissions", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-qualification-write-"));
  const output = path.join(directory, "qualification.json");
  try {
    const report = buildP0BQualificationReport(baseInput());
    await writeP0BQualificationReport(output, report);
    const stat = await fs.stat(output);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.deepEqual(parseP0BQualificationReport(await fs.readFile(output)), report);
    const files = await fs.readdir(directory);
    assert.deepEqual(files, ["qualification.json"]);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("tampering with provenance or conclusion invalidates the report digest", () => {
  const report = buildP0BQualificationReport(baseInput());
  const tampered = structuredClone(report);
  tampered.source_commit = "fedcba9876543210fedcba9876543210fedcba98";
  assert.throws(() => serializeP0BQualificationReport(tampered), { code: "invalid_report_digest" });
});
