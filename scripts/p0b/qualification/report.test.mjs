import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";

import {
  buildP0BQualificationReport,
  canonicalJson,
  digestArtifactFile,
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
