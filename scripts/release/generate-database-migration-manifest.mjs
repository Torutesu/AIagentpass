#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { basename, resolve } from "node:path";

const MIGRATION_FILE = /^(\d{4})_([a-z0-9_]+)\.sql$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_MIGRATIONS = 256;
const MAX_MIGRATION_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

/**
 * Build a migration manifest from committed Git objects.
 *
 * The repository root, commit, and output path are deliberately required.
 * This keeps a dirty worktree, a mutable ref, and an ambient environment from
 * changing the bytes that are attested by the manifest.
 */
export function generateDatabaseMigrationManifest({ repositoryRoot, commit, outputPath } = {}) {
  const root = requireAbsoluteDirectory(repositoryRoot, "repository root");
  const requestedCommit = requireCommit(commit);
  const output = requireAbsolutePath(outputPath, "output path");
  const sourceCommit = gitText(root, ["rev-parse", "--verify", `${requestedCommit}^{commit}`]);
  const sourceTree = gitText(root, ["rev-parse", "--verify", `${sourceCommit}^{tree}`]);
  if (!COMMIT.test(sourceCommit) || !COMMIT.test(sourceTree)) throw new Error("Git source identity is invalid");

  const entries = inventoryMigrations(root, sourceCommit);
  if (entries.length === 0) throw new Error("committed contracts/postgres contains no ordered SQL migrations");
  if (entries.length > MAX_MIGRATIONS) throw new Error("committed migration set is too large");
  for (let index = 0; index < entries.length; index += 1) {
    const expected = index + 1;
    if (entries[index].version !== expected) throw new Error(`migration order must be contiguous from 1; expected ${String(expected).padStart(4, "0")}`);
  }

  const migrations = entries.map(({ name, relativePath, version }) => {
    const bytes = gitBytes(root, ["show", "--no-ext-diff", "--no-textconv", `${sourceCommit}:${relativePath}`]);
    if (bytes.length === 0 || bytes.length > MAX_MIGRATION_BYTES) throw new Error(`migration ${name} has an invalid size`);
    return { name, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), version };
  }).map(({ version: _version, ...entry }) => entry);

  const manifest = {
    schema_version: 1,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    migrations
  };
  const outputBytes = Buffer.from(`${canonicalJson(manifest)}\n`, "utf8");
  if (outputBytes.length > MAX_MANIFEST_BYTES) throw new Error("database migration manifest is too large");
  writeExclusive(output, outputBytes, 0o644);
  return Object.freeze({ ...manifest, output_path: output, bytes: outputBytes.length, sha256: crypto.createHash("sha256").update(outputBytes).digest("hex") });
}

function inventoryMigrations(root, commit) {
  const listing = gitBytes(root, ["ls-tree", "--full-tree", "-r", "-z", commit, "--", "contracts/postgres"]);
  const records = listing.toString("utf8").split("\0").filter(Boolean);
  const migrations = [];
  for (const record of records) {
    const separator = record.indexOf("\t");
    if (separator <= 0) throw new Error("committed migration tree entry is malformed");
    const [mode, type, objectId] = record.slice(0, separator).split(" ");
    const relativePath = record.slice(separator + 1);
    if (!relativePath.startsWith("contracts/postgres/")) throw new Error("committed migration tree escaped contracts/postgres");
    const name = basename(relativePath);
    const match = MIGRATION_FILE.exec(name);
    if (!match) continue;
    if (mode !== "100644" || type !== "blob" || !/^[0-9a-f]{40}$/u.test(objectId)) throw new Error(`migration ${name} is not a regular committed blob`);
    migrations.push({ name, relativePath, version: Number(match[1]) });
  }
  migrations.sort((left, right) => left.name.localeCompare(right.name));
  for (let index = 1; index < migrations.length; index += 1) {
    if (migrations[index - 1].name === migrations[index].name) throw new Error(`duplicate migration basename: ${migrations[index].name}`);
  }
  return migrations;
}

function gitBytes(root, args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: null, maxBuffer: 64 * 1024 * 1024, shell: false, windowsHide: true });
  } catch (error) {
    throw new Error(`Git command failed: ${args[0]}`, { cause: error });
  }
}

function gitText(root, args) {
  return gitBytes(root, args).toString("utf8").trim();
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("manifest contains a non-finite number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("manifest contains an unsupported value");
}

function writeExclusive(output, bytes, mode) {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!Number.isInteger(noFollow)) throw new Error("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try {
    descriptor = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow, mode);
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fs.fsyncSync(descriptor);
  } catch (error) {
    throw new Error(`cannot write migration manifest: ${output}`, { cause: error });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function requireAbsoluteDirectory(value, label) {
  if (typeof value !== "string" || !value || !value.startsWith("/")) throw new Error(`${label} must be an absolute path`);
  let stat;
  try { stat = fs.statSync(value); } catch (error) { throw new Error(`${label} cannot be read`, { cause: error }); }
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory`);
  return resolve(value);
}

function requireAbsolutePath(value, label) {
  if (typeof value !== "string" || !value || !value.startsWith("/")) throw new Error(`${label} must be an absolute path`);
  return resolve(value);
}

function requireCommit(value) {
  if (typeof value !== "string" || !COMMIT.test(value)) throw new Error("commit must be a full lowercase 40-character Git commit id");
  return value;
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!["--repository-root", "--commit", "--output"].includes(name) || value === undefined || value.startsWith("--") || values.has(name)) throw new Error("Usage: generate-database-migration-manifest.mjs --repository-root ROOT --commit COMMIT --output OUTPUT");
    values.set(name, value);
  }
  if (values.size !== 3) throw new Error("Usage: generate-database-migration-manifest.mjs --repository-root ROOT --commit COMMIT --output OUTPUT");
  return values;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const values = parseArguments(process.argv.slice(2));
    const result = generateDatabaseMigrationManifest({ repositoryRoot: values.get("--repository-root"), commit: values.get("--commit"), outputPath: values.get("--output") });
    console.log(JSON.stringify({ ok: true, schema_version: result.schema_version, source_commit: result.source_commit, source_tree: result.source_tree, migration_count: result.migrations.length, output_bytes: result.bytes, output_sha256: result.sha256 }));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "database migration manifest generation failed"}\n`);
    process.exitCode = 1;
  }
}

export { canonicalJson };
