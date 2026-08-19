#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const CI_WORKFLOW_PATH = '.github/workflows/ci.yml';
export const EXACT_CI_LANES = Object.freeze([
  'postgres-authority-16',
  'postgres-authority-17',
  'postgres-integration',
  'browser-e2e',
  'p0b-live-process',
  'test',
]);
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

const assertExactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail(`${label} schema is not exact`);
  }
};

export const assertTerminalResults = ({ results, expectedCommit, expectedTree, workflowPath = CI_WORKFLOW_PATH, workflowTree = expectedTree } = {}) => {
  if (!HEX40.test(expectedCommit || '') || !HEX40.test(expectedTree || '')) fail('terminal results require full source commit/tree identities');
  if (!HEX40.test(workflowTree || '')) fail('terminal results require a full workflow tree identity');
  if (!Array.isArray(results) || results.length !== EXACT_CI_LANES.length) fail(`terminal results must contain exactly ${EXACT_CI_LANES.length} lanes`);
  const seen = new Set();
  for (const result of results) {
    assertExactKeys(result, ['conclusion', 'lane', 'source_commit', 'source_tree', 'status', 'terminal', 'workflow_path', 'workflow_tree'], 'terminal result');
    if (!EXACT_CI_LANES.includes(result.lane) || seen.has(result.lane)) fail('terminal results contain an unknown or duplicate lane');
    seen.add(result.lane);
    if (result.status !== 'completed' || result.conclusion !== 'success' || result.terminal !== true) fail(`lane ${result.lane} is not terminal success`);
    if (result.source_commit !== expectedCommit || result.source_tree !== expectedTree) fail(`lane ${result.lane} is not bound to the exact source SHA/tree`);
    if (result.workflow_path !== workflowPath || result.workflow_tree !== workflowTree) fail(`lane ${result.lane} is not bound to the exact workflow tree`);
  }
  if (seen.size !== EXACT_CI_LANES.length) fail('terminal results are missing a required lane');
  return { lanes: [...EXACT_CI_LANES], sourceCommit: expectedCommit, sourceTree: expectedTree, workflowPath };
};

const laneForJob = (name) => ({
  'PostgreSQL 16 authority qualification': 'postgres-authority-16',
  'PostgreSQL 17 authority qualification': 'postgres-authority-17',
  'postgres-integration': 'postgres-integration',
  'browser-e2e': 'browser-e2e',
  'p0b-live-process': 'p0b-live-process',
  test: 'test',
}[name]);

export const assertGithubCiRun = ({ run, jobs, expectedCommit, expectedTree, workflowTree = expectedTree } = {}) => {
  if (!run || typeof run !== 'object' || Array.isArray(run)) fail('CI run response is not an object');
  if (run.name !== 'CI' || run.path !== CI_WORKFLOW_PATH || run.event !== 'push' || run.status !== 'completed' || run.conclusion !== 'success'
    || run.head_branch !== 'main' || run.head_repository?.full_name !== 'Torutesu/AIagentpass' || run.head_sha !== expectedCommit) {
    fail('CI run is not a successful canonical main run for the expected source SHA');
  }
  if (!jobs || !Array.isArray(jobs.jobs)) fail('CI run job response is not a valid collection');
  const results = jobs.jobs.flatMap((job) => {
    const lane = laneForJob(job?.name);
    return lane ? [{
      lane,
      status: job.status,
      conclusion: job.conclusion,
      terminal: job.status === 'completed' && job.conclusion === 'success',
      source_commit: run.head_sha,
      source_tree: expectedTree,
      workflow_path: run.path,
      workflow_tree: workflowTree,
    }] : [];
  });
  return assertTerminalResults({ results, expectedCommit, expectedTree, workflowTree });
};

export const assertProtectedArtifactSecretScan = ({ artifactPath, expectedSha256 } = {}) => {
  if (!HEX64.test(expectedSha256 || '')) fail('protected artifact secret scan requires the expected digest');
  let bytes;
  try { bytes = fs.readFileSync(resolve(artifactPath)); } catch { fail('protected artifact secret scan artifact is missing'); }
  const actualSha256 = createHash('sha256').update(bytes).digest('hex');
  if (actualSha256 !== expectedSha256) fail('protected artifact secret scan digest is not manifest-bound');
  scanSecretBytes(bytes, resolve(artifactPath));
  return { status: 'passed', findings: [], sha256: actualSha256, bytes: bytes.length };
};

const scanSecretBytes = (bytes, label) => {
  const text = bytes.toString('utf8');
  const markers = [
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/u,
    /(?:^|[^A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9]|$)/u,
    /(?:^|[^A-Za-z0-9])gh[pousr]_[A-Za-z0-9_-]{20,}(?:[^A-Za-z0-9]|$)/u,
    /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}(?:[^A-Za-z0-9]|$)/u,
    /(?:^|[^A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}(?:[^A-Za-z0-9]|$)/u,
    /(?:^|[^A-Za-z0-9])npm_[A-Za-z0-9]{20,}(?:[^A-Za-z0-9]|$)/u,
  ];
  const findings = markers.flatMap((marker, index) => marker.test(text) ? [`${label}:marker-${index + 1}`] : []);
  if (findings.length) fail(`protected artifact secret scan found ${findings.join(', ')}`);
};

export const assertProtectedArtifactDirectory = ({ directory, maximumFiles = 512, maximumFileBytes = 256 * 1024 * 1024 } = {}) => {
  const root = resolve(directory || '');
  let rootStat;
  try { rootStat = fs.lstatSync(root); } catch { fail(`protected artifact directory is unreadable: ${root}`); }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o022) !== 0) fail(`protected artifact root is not private: ${root}`);
  const stack = [root];
  let files = 0;
  let bytesTotal = 0;
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { fail(`protected artifact directory is unreadable: ${current}`); }
    for (const entry of entries) {
      const path = resolve(current, entry.name);
      let stat;
      try { stat = fs.lstatSync(path); } catch { fail(`protected artifact entry disappeared: ${path}`); }
      if (stat.isSymbolicLink()) fail(`protected artifact directory contains a symlink: ${path}`);
      if (stat.isDirectory()) { stack.push(path); continue; }
      if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0) fail(`protected artifact entry is not a private regular file: ${path}`);
      if (++files > maximumFiles || stat.size > maximumFileBytes || (bytesTotal += stat.size) > maximumFiles * maximumFileBytes) fail('protected artifact directory exceeds scan bounds');
      let content;
      try { content = fs.readFileSync(path); } catch { fail(`protected artifact entry is unreadable: ${path}`); }
      scanSecretBytes(content, path);
    }
  }
  if (files === 0) fail(`protected artifact directory is empty: ${root}`);
  return { status: 'passed', files, bytes: bytesTotal };
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
  const secretScan = assertProtectedArtifactSecretScan({ artifactPath, expectedSha256: product[0].sha256 });
  return { sourceCommit: expectedCommit, sourceTree: expectedTree, artifactSha256: product[0].sha256, secretScan };
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
