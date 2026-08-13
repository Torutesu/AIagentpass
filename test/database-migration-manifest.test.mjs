import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { canonicalJson, generateDatabaseMigrationManifest } from "../scripts/release/generate-database-migration-manifest.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", shell: false }).trim();
}

function repository(files) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-migrations-"));
  git(directory, ["init", "--quiet"]);
  git(directory, ["config", "user.email", "test@example.com"]);
  git(directory, ["config", "user.name", "AgentPass Test"]);
  git(directory, ["config", "commit.gpgsign", "false"]);
  fs.mkdirSync(path.join(directory, "contracts", "postgres"), { recursive: true });
  for (const [name, contents] of Object.entries(files)) fs.writeFileSync(path.join(directory, "contracts", "postgres", name), contents);
  git(directory, ["add", "contracts/postgres"]);
  git(directory, ["commit", "--quiet", "-m", "migration fixture"]);
  return { directory, commit: git(directory, ["rev-parse", "HEAD"]) };
}

function cleanup(directory) {
  fs.rmSync(directory, { recursive: true, force: true });
}

test("generates a canonical manifest from committed Git bytes, ignoring dirty worktree changes", () => {
  const value = repository({ "0001_control.sql": "BEGIN;\nCREATE TABLE control (id integer);\nCOMMIT;\n", "0002_agent.sql": "BEGIN;\nCREATE TABLE agent (id integer);\nCOMMIT;\n" });
  try {
    const dirtyPath = path.join(value.directory, "contracts", "postgres", "0001_control.sql");
    fs.writeFileSync(dirtyPath, "BEGIN;\nTHIS IS DIRTY WORKTREE CONTENT;\nCOMMIT;\n");
    const output = path.join(value.directory, "manifest.json");
    const result = generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit: value.commit, outputPath: output });
    const parsed = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(result.source_commit, value.commit);
    assert.match(result.source_tree, /^[0-9a-f]{40}$/u);
    assert.deepEqual(parsed.migrations.map((item) => item.name), ["0001_control.sql", "0002_agent.sql"]);
    assert.equal(parsed.migrations[0].bytes, Buffer.byteLength("BEGIN;\nCREATE TABLE control (id integer);\nCOMMIT;\n"));
    assert.equal(fs.readFileSync(output, "utf8"), `${canonicalJson(parsed)}\n`);
    assert.equal(parsed.source_tree, git(value.directory, ["rev-parse", `${value.commit}^{tree}`]));
  } finally { cleanup(value.directory); }
});

test("requires the exact contiguous migration set expected by the runner", () => {
  const value = repository({ "0001_control.sql": "BEGIN; COMMIT;\n", "0003_gap.sql": "BEGIN; COMMIT;\n" });
  try {
    assert.throws(() => generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit: value.commit, outputPath: path.join(value.directory, "manifest.json") }), /contiguous from 1/);
  } finally { cleanup(value.directory); }
});

test("uses an explicit full commit and refuses output replacement", () => {
  const value = repository({ "0001_control.sql": "BEGIN; COMMIT;\n" });
  try {
    const output = path.join(value.directory, "manifest.json");
    generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit: value.commit, outputPath: output });
    const before = fs.readFileSync(output);
    assert.throws(() => generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit: value.commit, outputPath: output }), /cannot write migration manifest/);
    assert.deepEqual(fs.readFileSync(output), before);
    assert.throws(() => generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit: "HEAD", outputPath: path.join(value.directory, "other.json") }), /full lowercase 40-character/);
  } finally { cleanup(value.directory); }
});

test("rejects a migration tree entry that is not a regular committed blob", () => {
  const value = repository({ "0001_control.sql": "BEGIN; COMMIT;\n" });
  try {
    const link = path.join(value.directory, "contracts", "postgres", "0002_link.sql");
    fs.symlinkSync("0001_control.sql", link);
    git(value.directory, ["add", "contracts/postgres/0002_link.sql"]);
    git(value.directory, ["commit", "--quiet", "-m", "symlink migration"]);
    const commit = git(value.directory, ["rev-parse", "HEAD"]);
    assert.throws(() => generateDatabaseMigrationManifest({ repositoryRoot: value.directory, commit, outputPath: path.join(value.directory, "manifest.json") }), /regular committed blob/);
  } finally { cleanup(value.directory); }
});
