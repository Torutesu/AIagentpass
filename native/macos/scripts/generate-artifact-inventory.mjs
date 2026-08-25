#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { basename, relative, resolve, sep } from 'node:path';

const [rootArg, artifactArg, outputArg] = process.argv.slice(2);
if (!rootArg || !artifactArg || !outputArg) throw new Error('Usage: generate-artifact-inventory.mjs ROOT ARTIFACT OUTPUT');
const root = resolve(rootArg);
const artifact = resolve(artifactArg);
const output = resolve(outputArg);
const DIGEST = /^[0-9a-f]{64}$/u;
const safeName = (value) => typeof value === 'string' && value.length > 0 && value === basename(value) && /^[0-9A-Za-z][0-9A-Za-z._-]*$/u.test(value);
const fail = (message) => { throw new Error(message); };
const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');

const hashFile = (path, label) => {
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > 16n * 1024n * 1024n * 1024n) fail(`${label} must be a non-empty single-link regular file`);
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (bytes < Number(before.size)) {
      const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, Number(before.size) - bytes), bytes);
      if (!count) fail(`${label} changed while reading`);
      hash.update(buffer.subarray(0, count));
      bytes += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (identity(before) !== identity(after)) fail(`${label} changed while reading`);
    return { bytes, sha256: hash.digest('hex') };
  } finally { fs.closeSync(fd); }
};

const rootStat = fs.lstatSync(root, { bigint: true });
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('inventory root must be a real directory');
if (output.startsWith(`${root}${sep}`) || output === root) fail('inventory output must be outside the inventory root');
const walk = (directory) => {
  const results = [];
  for (const name of fs.readdirSync(directory).sort()) {
    const path = `${directory}${sep}${name}`;
    const stat = fs.lstatSync(path, { bigint: true });
    if (stat.isSymbolicLink()) fail(`inventory refuses symlink: ${path}`);
    if (stat.isDirectory()) results.push(...walk(path));
    else if (stat.isFile()) {
      if (stat.nlink !== 1n) fail(`inventory refuses hard-linked file: ${path}`);
      const relativePath = relative(root, path).split(sep).join('/');
      results.push({ path: relativePath, ...hashFile(path, relativePath) });
    } else fail(`inventory refuses special file: ${path}`);
  }
  return results;
};
const artifactStat = fs.lstatSync(artifact, { bigint: true });
if (artifactStat.isSymbolicLink()) fail('artifact must not be a symlink');
if (!safeName(basename(artifact))) fail('artifact basename is unsafe');
const artifactDescriptor = { name: basename(artifact), ...hashFile(artifact, 'artifact') };
if (!DIGEST.test(artifactDescriptor.sha256)) fail('artifact digest is invalid');
const inventory = {
  schema_version: 1,
  kind: 'agentpass.macos-artifact-inventory',
  artifact: artifactDescriptor,
  root_entries: walk(root)
};
const bytes = Buffer.from(`${JSON.stringify(inventory, null, 2)}\n`, 'utf8');
const outStat = (() => { try { return fs.lstatSync(output, { bigint: true }); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } })();
if (outStat) fail('inventory output already exists');
fs.writeFileSync(output, bytes, { flag: 'wx', mode: 0o644 });
process.stdout.write(`${JSON.stringify({ status: 'written', artifact_sha256: artifactDescriptor.sha256, entry_count: inventory.root_entries.length })}\n`);
