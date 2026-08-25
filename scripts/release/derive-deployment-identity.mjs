#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_CATALOG_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function gitBytes(root, args) {
  try {
    return execFileSync("git", args, {
      cwd: root,
      encoding: null,
      shell: false,
      maxBuffer: Math.max(MAX_CATALOG_BYTES, MAX_MANIFEST_BYTES) + 1024
    });
  } catch (error) {
    throw new Error(`cannot read committed source object: ${args.join(" ")}`, { cause: error });
  }
}

function requireCommit(value) {
  if (typeof value !== "string" || !COMMIT.test(value)) throw new Error("commit must be a full lowercase 40-character Git commit id");
  return value;
}

function readBoundedRegularFile(input, maximum, label) {
  if (typeof input !== "string" || !input.startsWith("/")) throw new Error(`${label} must be an absolute path`);
  const path = resolve(input);
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!Number.isInteger(noFollow)) throw new Error("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_RDONLY | noFollow); } catch (error) { throw new Error(`cannot open ${label}`, { cause: error }); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size === 0n || before.size > BigInt(maximum)) throw new Error(`${label} is not a bounded regular file`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) offset += fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if ([before.dev, before.ino, before.size, before.mtimeNs, before.ctimeNs].join(":") !== [after.dev, after.ino, after.size, after.mtimeNs, after.ctimeNs].join(":")) throw new Error(`${label} changed while reading`);
    return bytes;
  } finally { fs.closeSync(descriptor); }
}

function parseMigrationManifest(bytes, expectedCommit, expectedTree) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (error) { throw new Error("migration manifest is not valid UTF-8 JSON", { cause: error }); }
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schema_version !== 1 || value.source_commit !== expectedCommit || value.source_tree !== expectedTree || !Array.isArray(value.migrations) || value.migrations.length === 0) throw new Error("migration manifest is not bound to the selected source commit and tree");
  if (!value.migrations.every((item) => item && typeof item.name === "string" && Number.isSafeInteger(item.bytes) && item.bytes > 0 && DIGEST.test(item.sha256))) throw new Error("migration manifest contains invalid migration entries");
  return value;
}

/**
 * Derive deployment identity from immutable release inputs.
 *
 * schema_digest is the SHA-256 of the canonical database migration manifest
 * shipped with the candidate. catalog_digest is the SHA-256 of the exact
 * catalog-v1.json Git blob at the candidate source commit. Neither value is
 * accepted from an environment variable or from deployment evidence.
 */
export function deriveDeploymentIdentity({ repositoryRoot, commit, migrationManifestPath } = {}) {
  if (typeof repositoryRoot !== "string" || !repositoryRoot.startsWith("/")) throw new Error("repository root must be an absolute path");
  const root = resolve(repositoryRoot);
  const sourceCommit = requireCommit(commit);
  const sourceTree = gitBytes(root, ["rev-parse", "--verify", `${sourceCommit}^{tree}`]).toString("utf8").trim();
  if (!COMMIT.test(sourceTree)) throw new Error("source tree identity is invalid");
  const catalogBytes = gitBytes(root, ["show", "--no-ext-diff", "--no-textconv", `${sourceCommit}:contracts/catalog-v1.json`]);
  if (catalogBytes.length === 0 || catalogBytes.length > MAX_CATALOG_BYTES) throw new Error("committed contract catalog has an invalid size");
  try { JSON.parse(catalogBytes.toString("utf8")); } catch (error) { throw new Error("committed contract catalog is not valid JSON", { cause: error }); }
  const migrationBytes = readBoundedRegularFile(migrationManifestPath, MAX_MANIFEST_BYTES, "migration manifest");
  parseMigrationManifest(migrationBytes, sourceCommit, sourceTree);
  return Object.freeze({ schema_version: 1, source_commit: sourceCommit, source_tree: sourceTree, schema_digest: sha256(migrationBytes), catalog_digest: sha256(catalogBytes) });
}

function parseArguments(argv) {
  if (argv.length !== 6 || argv[0] !== "--repository-root" || argv[2] !== "--commit" || argv[4] !== "--migration-manifest") throw new Error("Usage: derive-deployment-identity.mjs --repository-root ROOT --commit COMMIT --migration-manifest PATH");
  return { repositoryRoot: argv[1], commit: argv[3], migrationManifestPath: argv[5] };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(`${JSON.stringify(deriveDeploymentIdentity(parseArguments(process.argv.slice(2))), null, 2)}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : "deployment identity derivation failed"}\n`); process.exitCode = 1; }
}
