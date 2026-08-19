#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const fail = (message) => { throw new Error(`CI release preflight failed: ${message}`); };

const git = (repoRoot, args) => {
  const result = spawnSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8', shell: false });
  if (result.status !== 0) fail(`git ${args.join(' ')} failed`);
  return result.stdout.trim();
};

const readJSON = (file, label) => {
  let value;
  try { value = JSON.parse(fs.readFileSync(resolve(file), 'utf8')); } catch { fail(`${label} is not valid JSON`); }
  return value;
};

const walkStrings = (value, path = '$') => {
  if (typeof value === 'string') return value === 'not_proven' ? [path] : [];
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => walkStrings(child, `${path}.${key}`));
};

export const assertWorkflowBoundary = ({ eventName, ref, repository, expectedRepository = 'Torutesu/AIagentpass' } = {}) => {
  if (eventName !== 'workflow_dispatch') fail(`event ${eventName || '<missing>'} cannot access release credentials`);
  if (ref !== 'refs/heads/main') fail(`ref ${ref || '<missing>'} is not the protected main ref`);
  if (repository !== expectedRepository) fail(`repository ${repository || '<missing>'} is not canonical`);
};

export const assertCleanCheckout = (repoRoot) => {
  const status = git(repoRoot, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (status) fail(`checkout is dirty:\n${status}`);
};

export const assertCandidateBinding = ({ repoRoot, manifestPath, expectedCommit, expectedTree, sourceRef } = {}) => {
  if (!HEX40.test(expectedCommit || '') || !HEX40.test(expectedTree || '')) fail('expected source commit/tree must be 40-hex identities');
  const manifest = readJSON(manifestPath, 'release manifest');
  if (!manifest.source || manifest.source.commit !== expectedCommit || manifest.source.tree !== expectedTree) fail('candidate source commit/tree differs from the checked source');
  const notProven = walkStrings(manifest);
  if (notProven.length) fail(`candidate manifest contains not_proven at ${notProven.join(', ')}`);
  const source = sourceRef || 'HEAD';
  const head = git(repoRoot, ['rev-parse', `${source}^{commit}`]);
  const tree = git(repoRoot, ['rev-parse', `${source}^{tree}`]);
  if (head !== expectedCommit || tree !== expectedTree) fail('checkout HEAD/tree differs from the expected candidate source');
  const product = Array.isArray(manifest.artifacts) ? manifest.artifacts.filter((item) => item?.role === 'product') : [];
  if (product.length !== 1 || !HEX64.test(product[0].sha256) || manifest.candidate_id !== `release-pkg-sha256-v1-${product[0].sha256}`) fail('candidate_id is not bound to one product digest');
  const artifactPath = resolve(resolve(manifestPath), '..', product[0].name);
  let bytes;
  try { bytes = fs.readFileSync(artifactPath); } catch { fail('manifest-bound product artifact is missing'); }
  if (bytes.length !== product[0].bytes || createHash('sha256').update(bytes).digest('hex') !== product[0].sha256) fail('candidate product digest differs from the signed manifest');
  return { sourceCommit: expectedCommit, sourceTree: expectedTree, artifactSha256: product[0].sha256 };
};

export const assertExternalGates = ({ gateFiles = [], required = {} } = {}) => {
  if (!Array.isArray(gateFiles) || gateFiles.length === 0) fail('no external gate evidence was supplied');
  const documents = gateFiles.map((file) => readJSON(file, `gate evidence ${file}`));
  for (const [index, document] of documents.entries()) {
    const notProven = walkStrings(document);
    if (notProven.length) fail(`gate evidence ${gateFiles[index]} contains not_proven at ${notProven.join(', ')}`);
  }
  for (const [key, wanted] of Object.entries(required)) {
    if (!documents.some((document) => document?.[key] === wanted)) fail(`required external gate ${key}=${wanted} was not proven`);
  }
  return { files: gateFiles.length, required: Object.keys(required) };
};

export const runPreflight = (options) => {
  assertWorkflowBoundary(options);
  assertCleanCheckout(options.repoRoot);
  const binding = assertCandidateBinding(options);
  const gates = options.gateFiles ? assertExternalGates(options) : null;
  return { ok: true, status: 'passed', ...binding, gates };
};

const VALUE_OPTIONS = new Set(['--repo-root', '--manifest', '--expected-commit', '--expected-tree', '--source-ref', '--event-name', '--ref', '--repository', '--gate-file', '--require']);

export const parseArguments = (args) => {
  const values = {};
  const gateFiles = [];
  const required = {};
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    if (!VALUE_OPTIONS.has(name)) fail(`unknown argument ${name}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) fail(`argument ${name} requires a value`);
    index += 1;
    if (name === '--gate-file') gateFiles.push(value);
    else if (name === '--require') {
      const separator = value.indexOf('=');
      if (separator <= 0) fail(`argument ${name} requires key=value`);
      const key = value.slice(0, separator);
      const raw = value.slice(separator + 1);
      required[key] = raw === 'true' ? true : raw === 'false' ? false : raw;
    } else {
      const key = name.slice(2).replace(/-([a-z])/g, (_, character) => character.toUpperCase());
      values[key] = value;
    }
  }
  return { ...values, gateFiles, required };
};

const main = () => {
  try {
    const args = parseArguments(process.argv.slice(2));
    const result = runPreflight({ ...args, repoRoot: resolve(args.repoRoot || process.cwd()) });
    console.log(JSON.stringify(result));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
};

if (import.meta.url === `file://${process.argv[1]}`) main();
