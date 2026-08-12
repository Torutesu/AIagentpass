#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const args = new Set(process.argv.slice(2));
const root = resolve(process.env.AGENTPASS_REPOSITORY_ROOT || process.cwd());
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version)) throw new Error('package.json has an invalid semantic version');
const plistPaths = [
  'native/macos/Resources/AgentPass-Info.plist',
  'native/macos/Resources/AgentPassNativeService-Info.plist',
  'native/macos/Resources/AgentPassNativeClient-Info.plist'
];
let bundleBuild = null;
for (const path of plistPaths) {
  const text = readFileSync(resolve(root, path), 'utf8');
  const match = text.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/);
  if (!match || match[1] !== pkg.version) throw new Error(`${path} version does not match package.json`);
  const build = text.match(/<key>CFBundleVersion<\/key>\s*<string>([1-9]\d*)<\/string>/)?.[1];
  if (!build) throw new Error(`${path} has an invalid bundle build number`);
  if (bundleBuild && build !== bundleBuild) throw new Error(`${path} bundle build number does not match the other bundles`);
  bundleBuild = build;
}
const tagArg = process.argv.find((value) => value.startsWith('--tag='));
const tag = tagArg?.slice(6) || (process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : '');
if (tag && tag !== `v${pkg.version}`) throw new Error(`tag ${tag} does not match v${pkg.version}`);
if (args.has('--require-tag')) {
  if (!tag) throw new Error('an explicit vX.Y.Z tag is required');
  const status = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
  if (status.trim()) throw new Error('release validation requires a clean worktree');
  const type = execFileSync('git', ['cat-file', '-t', tag], { cwd: root, encoding: 'utf8' }).trim();
  if (type !== 'tag') throw new Error(`${tag} must be an annotated tag`);
  execFileSync('git', ['merge-base', '--is-ancestor', `${tag}^{commit}`, 'origin/main'], { cwd: root });
}
console.log(JSON.stringify({ ok: true, version: pkg.version, bundle_build: bundleBuild, tag: tag || null }));
