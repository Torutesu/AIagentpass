import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { deriveDeploymentIdentity } from "../scripts/release/derive-deployment-identity.mjs";

const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", shell: false }).trim();
const makeRepo = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-deployment-identity-"));
  git(root, ["init", "--quiet"]); git(root, ["config", "user.email", "test@example.com"]); git(root, ["config", "user.name", "AgentPass Test"]);
  fs.mkdirSync(path.join(root, "contracts", "postgres"), { recursive: true });
  fs.writeFileSync(path.join(root, "contracts", "catalog-v1.json"), '{"catalog_version":1}\n');
  fs.writeFileSync(path.join(root, "contracts", "postgres", "0001_control.sql"), "BEGIN;\nCOMMIT;\n");
  git(root, ["add", "."]); git(root, ["commit", "--quiet", "-m", "identity"]);
  return root;
};

test("derives catalog and migration digests from the exact source binding", () => {
  const root = makeRepo();
  try {
    const commit = git(root, ["rev-parse", "HEAD"]);
    const tree = git(root, ["rev-parse", "HEAD^{tree}"]);
    const manifest = { schema_version: 1, source_commit: commit, source_tree: tree, migrations: [{ name: "0001_control.sql", bytes: 16, sha256: "a".repeat(64) }] };
    const manifestPath = path.join(root, "migration.json");
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    fs.writeFileSync(manifestPath, manifestBytes, { mode: 0o600 });
    const result = deriveDeploymentIdentity({ repositoryRoot: root, commit, migrationManifestPath: manifestPath });
    assert.equal(result.schema_digest, crypto.createHash("sha256").update(manifestBytes).digest("hex"));
    assert.equal(result.catalog_digest, crypto.createHash("sha256").update('{"catalog_version":1}\n').digest("hex"));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("rejects a migration manifest from a different source tree", () => {
  const root = makeRepo();
  try {
    const commit = git(root, ["rev-parse", "HEAD"]);
    const manifestPath = path.join(root, "migration.json");
    fs.writeFileSync(manifestPath, JSON.stringify({ schema_version: 1, source_commit: "0".repeat(40), source_tree: "1".repeat(40), migrations: [{ name: "0001_control.sql", bytes: 1, sha256: "a".repeat(64) }] }));
    assert.throws(() => deriveDeploymentIdentity({ repositoryRoot: root, commit, migrationManifestPath: manifestPath }), /not bound/u);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
