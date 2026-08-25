import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildP0BQualificationReport, digestArtifactFile, resolveSourceCommit, writeP0BQualificationReport } from "./report.mjs";
import { verifyQualificationReport } from "./verify.mjs";

test("verifies a passing canonical report bound to the current clean source", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-verify-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const artifactFile = path.join(directory, "artifact");
  const reportFile = path.join(directory, "report.json");
  const repository = path.join(directory, "repository");
  await fs.mkdir(repository);
  execFileSync("git", ["init", "--quiet"], { cwd: repository, stdio: "ignore" });
  await fs.writeFile(path.join(repository, "source"), "source");
  execFileSync("git", ["add", "source"], { cwd: repository, stdio: "ignore" });
  execFileSync("git", ["-c", "user.name=AgentPass", "-c", "user.email=agentpass@example.invalid", "commit", "--quiet", "-m", "source"], { cwd: repository, stdio: "ignore" });
  await fs.writeFile(artifactFile, "build", { mode: 0o600 });
  const artifact = await digestArtifactFile(artifactFile, { name: "console-dist", kind: "build" });
  const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const result = { status: "passed", exit_code: 0, signal: null, duration_ms: 1, stdout_sha256: empty, stdout_bytes: 0, stderr_sha256: empty, stderr_bytes: 0, reason: null };
  const report = buildP0BQualificationReport({
    source_commit: resolveSourceCommit(repository),
    started_at: "2026-08-13T00:00:00.000Z",
    completed_at: "2026-08-13T00:00:01.000Z",
    commands: ["console-build", "browser-e2e", "process-e2e"].map((id) => ({ id, argv: ["node", "test"], cwd: "repository", result })),
    postgres: { image: "postgres:17-alpine", image_digest: `sha256:${"a".repeat(64)}`, container_id: "b".repeat(64), container_started_at: "2026-08-13T00:00:00.000Z", server_version: "17.5" },
    browser: { name: "Chromium", version: "140.0.0.0", engine: "Playwright" },
    artifacts: [artifact],
    gates: ["build-integrity", "browser-flow", "process-flow"].map((id) => ({ id, status: "passed", evidence_sha256: "c".repeat(64) }))
  });
  await writeP0BQualificationReport(reportFile, report);
  assert.deepEqual(await verifyQualificationReport(reportFile, { repositoryRoot: repository }), {
    report_digest: report.report_digest,
    source_commit: report.source_commit
  });
});
