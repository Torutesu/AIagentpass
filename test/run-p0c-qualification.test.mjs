import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { join } from 'node:path';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { REQUIRED_GATES, REQUIRED_TESTS, collectPhysicalMetadata, runBoundedCommand, runQualification } from '../scripts/release/run-p0c-qualification.mjs';

const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const fixtureMetadata = { architecture: 'arm64', hardwareClass: 'apple_silicon', modelIdentifier: 'Mac15,7', macosVersion: '26.5.2', macosBuild: '25G100', secureEnclave: true };

const makeFixture = () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentpass-p0c-runner-'));
  const drivers = join(dir, 'drivers'); const evidence = join(dir, 'evidence'); mkdirSync(drivers, 0o755); mkdirSync(evidence, 0o700);
  const artifact = Buffer.from('signed notarized production package fixture\n'); const artifactPath = join(dir, 'AgentPass-0.18.0-macos-universal.pkg'); writeFileSync(artifactPath, artifact, { mode: 0o600 });
  const team = 'A1B2C3D4E5';
  const template = {
    schema_version: 2, source_commit: 'a'.repeat(40), dependency_lock_sha256: 'b'.repeat(64), release_manifest_sha256: 'c'.repeat(64), artifact_name: 'AgentPass-0.18.0-macos-universal.pkg', artifact_sha256: digest(artifact), architecture: 'arm64', hardware_class: 'apple_silicon', model_identifier: 'Mac15,7', macos_version: '26.5.2', macos_build: '25G100', secure_enclave: true, team_id: team, nested_code_identities: [{ path: 'AgentPass.app', bundle_id: 'dev.agentpass', team_id: team, code_directory_hash: 'd'.repeat(40) }], notarization: { status: 'accepted_stapled', submission_ids: ['12345678-1234-1234-1234-123456789abc'], evidence: [{ kind: 'notarytool_result', name: 'notary.json', bytes: 1, sha256: 'e'.repeat(64) }, { kind: 'stapler_result', name: 'stapler.txt', bytes: 1, sha256: 'f'.repeat(64) }] }, cloud_image_digest: `sha256:${'1'.repeat(64)}`, database_migration_manifest_sha256: '2'.repeat(64), signer_key_versions: [{ name: 'capability', version: 'cap-2026-08' }], browser_versions: [{ name: 'chromium', version: '151.0.7922.34' }], started_at: '2026-08-13T00:00:00.000Z', completed_at: '2026-08-13T00:00:01.000Z', operator: 'operator@example.com', operator_key_fingerprint: 'SHA256:' + 'A'.repeat(43), qualified: false, tests: [{ name: 'template', status: 'skipped', reason: 'template only', evidence: [] }], gates: [{ name: 'template', status: 'skipped', reason: 'template only', evidence: [] }]
  };
  const templatePath = join(dir, 'production-template.json'); writeFileSync(templatePath, canonical(template), { mode: 0o600 });
  for (const gate of REQUIRED_GATES) { const path = join(drivers, gate); writeFileSync(path, '#!/bin/sh\nexit 0\n', { mode: 0o755 }); chmodSync(path, 0o755); }
  return { dir, drivers, evidence, gateDriverDirectory: drivers, evidenceDirectory: evidence, artifactPath, templatePath, outputPath: join(dir, 'qualification.json'), operator: 'operator@example.com' };
};

const passedCommand = (gate) => {
  const gateIndex = REQUIRED_GATES.indexOf(gate);
  const tests = REQUIRED_TESTS.filter((_, index) => Math.floor(index * REQUIRED_GATES.length / REQUIRED_TESTS.length) === gateIndex).map((name) => ({ name, status: 'passed' }));
  return { exitCode: 0, signal: null, timedOut: false, outputLimit: false, spawnError: false, durationMs: 1, stdout: Buffer.from(canonical({ schema_version: 1, gate, status: 'passed', tests })), stderr: Buffer.from('secret-on-stderr-do-not-persist') };
};

test('injected Linux execution stays unqualified even when every fake gate reports passed', async () => {
  const fixture = makeFixture();
  const result = await runQualification({ ...fixture, platform: 'linux', platformMetadata: fixtureMetadata, runCommand: async (command) => passedCommand(command.split('/').pop()), now: () => new Date('2026-08-13T01:00:00.000Z') });
  assert.equal(result.report.qualified, false);
  assert.deepEqual(result.report.gates.map((item) => item.status), REQUIRED_GATES.map(() => 'passed'));
  assert.deepEqual(result.report.tests.map((item) => item.status), REQUIRED_TESTS.map(() => 'passed'));
  assert.equal(fs.statSync(fixture.outputPath).mode & 0o077, 0);
  for (const entry of fs.readdirSync(fixture.evidence)) { const stat = fs.lstatSync(join(fixture.evidence, entry)); assert.equal(stat.isFile(), true); assert.equal(stat.nlink, 1); assert.equal(stat.mode & 0o077, 0); assert.doesNotMatch(fs.readFileSync(join(fixture.evidence, entry), 'utf8'), /secret-on-stderr/); }
  assert.match(fs.readFileSync(fixture.outputPath, 'utf8'), /"qualified": false/);
});

test('production mode refuses non-darwin before accepting a local or ad-hoc run', async () => {
  const fixture = makeFixture();
  await assert.rejects(() => runQualification({ ...fixture, platform: 'linux', production: true }), /darwin/);
});

test('gate drivers are fixed executable basenames and shell/stdin/inherited environment are denied', async () => {
  const fixture = makeFixture(); const calls = [];
  const result = await runQualification({ ...fixture, platform: 'linux', platformMetadata: fixtureMetadata, runCommand: async (command, args, options) => { calls.push({ command, args, options }); return passedCommand(command.split('/').pop()); } });
  assert.equal(result.report.qualified, false); assert.equal(calls.length, REQUIRED_GATES.length); assert.deepEqual(calls[0].args, []); assert.equal(calls[0].options.shell, false); assert.deepEqual(calls[0].options.stdio, ['ignore', 'pipe', 'pipe']); assert.equal(calls[0].options.cwd, '/'); assert.deepEqual(calls[0].options.env, { HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }); assert.deepEqual(calls.map(({ command }) => command.split('/').pop()), [...REQUIRED_GATES]);
});

test('a missing, writable, symlinked, or extra driver fails closed', async () => {
  for (const mutate of [
    (fixture) => fs.unlinkSync(join(fixture.drivers, REQUIRED_GATES[0])),
    (fixture) => chmodSync(join(fixture.drivers, REQUIRED_GATES[0]), 0o777),
    (fixture) => { fs.unlinkSync(join(fixture.drivers, REQUIRED_GATES[0])); fs.symlinkSync('/bin/true', join(fixture.drivers, REQUIRED_GATES[0])); },
    (fixture) => writeFileSync(join(fixture.drivers, 'unexpected'), 'x')
  ]) {
    const fixture = makeFixture(); mutate(fixture);
    await assert.rejects(() => runQualification({ ...fixture, platform: 'linux', platformMetadata: fixtureMetadata }), /gate-driver directory|gate driver/); assert.equal(fs.existsSync(fixture.outputPath), false);
  }
});

test('failed and timed out gate output can never qualify and raw output is not persisted', async () => {
  const fixture = makeFixture();
  const result = await runQualification({ ...fixture, platform: 'linux', platformMetadata: fixtureMetadata, runCommand: async (command) => { const gate = command.split('/').pop(); if (gate === REQUIRED_GATES[0]) return { exitCode: 1, signal: null, timedOut: false, outputLimit: false, spawnError: false, durationMs: 2, stdout: Buffer.from('raw secret output'), stderr: Buffer.from('raw error') }; if (gate === REQUIRED_GATES[1]) return { exitCode: null, signal: 'SIGKILL', timedOut: true, outputLimit: false, spawnError: false, durationMs: 3, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; return passedCommand(gate); } });
  assert.equal(result.report.qualified, false); assert.equal(result.report.gates[0].status, 'failed'); assert.equal(result.report.gates[1].status, 'failed'); for (const file of fs.readdirSync(fixture.evidence)) assert.doesNotMatch(fs.readFileSync(join(fixture.evidence, file), 'utf8'), /raw secret|raw error/);
});

test('the bounded subprocess runner hashes only bounded prefixes and escalates termination', async () => {
  const outputLimit = await runBoundedCommand(process.execPath, ['-e', 'process.stdout.write("x".repeat(1024))'], { maxOutputBytes: 32, timeoutMs: 1000 });
  assert.equal(outputLimit.outputLimit, true); assert.equal(outputLimit.stdoutBytes, 32); assert.equal(outputLimit.stdout.length, 32); assert.equal(outputLimit.stdoutTruncated, true);
  const timeout = await runBoundedCommand(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { maxOutputBytes: 32, timeoutMs: 30 }); assert.equal(timeout.timedOut, true); assert.notEqual(timeout.signal, null);
});

test('physical metadata collection uses fixed commands and rejects failed metadata', async () => {
  const calls = []; const values = { '/usr/bin/uname': 'arm64\n', '/usr/sbin/sysctl': 'Mac15,7\n', '/usr/bin/sw_vers-productVersion': '26.5.2\n', '/usr/bin/sw_vers-buildVersion': '25G100\n', '/usr/sbin/ioreg': 'AppleSEPManager\n' };
  const metadata = await collectPhysicalMetadata({ runCommand: async (command, args, options) => { calls.push({ command, args, options }); const key = command === '/usr/bin/sw_vers' ? `${command}-${args[0].replace('-', '')}` : command; return { exitCode: 0, signal: null, timedOut: false, outputLimit: false, spawnError: false, stdout: Buffer.from(values[key] ?? ''), stderr: Buffer.alloc(0) }; } });
  assert.deepEqual(metadata, fixtureMetadata); assert.deepEqual(calls.map((item) => [item.command, item.args]), [['/usr/bin/uname', ['-m']], ['/usr/sbin/sysctl', ['-n', 'hw.model']], ['/usr/bin/sw_vers', ['-productVersion']], ['/usr/bin/sw_vers', ['-buildVersion']], ['/usr/sbin/ioreg', ['-rd1', '-c', 'AppleSEPManager']]]);
  await assert.rejects(() => collectPhysicalMetadata({ runCommand: async () => ({ exitCode: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }) }), /physical metadata command failed/);
});

test('exact artifact binding and existing output are refusal conditions', async () => {
  const mismatch = makeFixture(); writeFileSync(mismatch.artifactPath, 'different artifact'); await assert.rejects(() => runQualification({ ...mismatch, platform: 'linux', platformMetadata: fixtureMetadata }), /exact production artifact/);
  const existing = makeFixture(); writeFileSync(existing.outputPath, 'do not overwrite'); await assert.rejects(() => runQualification({ ...existing, platform: 'linux', platformMetadata: fixtureMetadata }), /output path already exists/); assert.equal(fs.readFileSync(existing.outputPath, 'utf8'), 'do not overwrite');
});
