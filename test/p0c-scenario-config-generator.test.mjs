import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateScenarioConfig } from '../scripts/release/p0c/generate-scenario-config.mjs';

const fixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-scenario-config-')); const repository = path.join(root, 'repo'); const checkpoints = path.join(root, 'checkpoints'); fs.mkdirSync(repository, { mode: 0o755 }); fs.mkdirSync(checkpoints, { mode: 0o700 });
  const executables = {}; for (const name of ['nativeClient', 'nativeManager', 'nativeService', 'claudeCode', 'cursor', 'qualificationGrantClient']) { const file = path.join(root, name); fs.writeFileSync(file, `#!/bin/sh\n# ${name}\nexit 1\n`, { mode: 0o755 }); fs.chmodSync(file, 0o755); executables[name] = file; }
  return { root, repository, checkpoints, executables, output: path.join(root, 'scenario-config.json') };
};

test('generator snapshots six executable identities into canonical private config', () => {
  const value = fixture(); const result = generateScenarioConfig({ ...value.executables, testRepository: value.repository, cloudProbeURL: 'https://qualification.invalid/v1/probe', checkpointDirectory: value.checkpoints, outputPath: value.output });
  assert.equal(result.output, value.output); const bytes = fs.readFileSync(value.output); const parsed = JSON.parse(bytes);
  assert.ok(bytes.equals(Buffer.from(`${JSON.stringify(parsed, null, 2)}\n`))); assert.equal(parsed.application_path, '/Applications/AgentPass.app'); assert.match(parsed.executables.native_client.sha256, /^[0-9a-f]{64}$/u); assert.equal(parsed.executables.qualification_grant_client.path, '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client'); assert.equal(fs.statSync(value.output).mode & 0o077, 0);
});

test('generator refuses overwrite, writable executables, unsafe directories, and mutable cloud URLs', () => {
  const existing = fixture(); fs.writeFileSync(existing.output, 'preserve'); assert.throws(() => generateScenarioConfig({ ...existing.executables, testRepository: existing.repository, cloudProbeURL: 'https://qualification.invalid/v1/probe', checkpointDirectory: existing.checkpoints, outputPath: existing.output }), /EEXIST/); assert.equal(fs.readFileSync(existing.output, 'utf8'), 'preserve');
  const writable = fixture(); fs.chmodSync(writable.executables.cursor, 0o777); assert.throws(() => generateScenarioConfig({ ...writable.executables, testRepository: writable.repository, cloudProbeURL: 'https://qualification.invalid/v1/probe', checkpointDirectory: writable.checkpoints, outputPath: writable.output }), /unsafe/);
  const insecure = fixture(); assert.throws(() => generateScenarioConfig({ ...insecure.executables, testRepository: insecure.repository, cloudProbeURL: 'http://qualification.invalid/probe', checkpointDirectory: insecure.checkpoints, outputPath: insecure.output }), /identity/);
});
