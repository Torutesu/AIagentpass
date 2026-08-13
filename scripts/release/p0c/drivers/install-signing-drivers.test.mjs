import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const driversDirectory = dirname(fileURLToPath(import.meta.url));

const expectedDrivers = {
  'gatekeeper-notarization': {
    gate: 'gatekeeper-notarization',
    tests: ['exact-pkg-install'],
    scenario: 'gatekeeper-notarization',
  },
  'clean-install-launchd-xpc': {
    gate: 'clean-install-launchd-xpc',
    tests: ['launchd-xpc-approval'],
    scenario: 'clean-install-launchd-xpc',
  },
  'secure-enclave-enrollment': {
    gate: 'secure-enclave-enrollment',
    tests: ['secure-enclave-key-creation', 'secure-enclave-nonexportability'],
    scenario: 'secure-enclave-enrollment',
  },
  'cloud-possession-verification': {
    gate: 'cloud-possession-verification',
    tests: ['cloud-possession-proof'],
    scenario: 'cloud-possession-verification',
  },
  'claude-code-unattended-sign': {
    gate: 'claude-code-unattended-sign',
    tests: ['claude-code-unattended-sign'],
    scenario: 'claude-code-unattended-sign',
  },
  'cursor-code-unattended-sign': {
    gate: 'cursor-code-unattended-sign',
    tests: ['cursor-code-unattended-sign'],
    scenario: 'cursor-code-unattended-sign',
  },
  'audit-upload-observation': {
    gate: 'audit-upload-observation',
    tests: ['audit-console-observation'],
    scenario: 'audit-upload-observation',
  },
  'negative-identity-and-entitlement-cases': {
    gate: 'negative-identity-and-entitlement-cases',
    tests: ['unrelated-process-denied'],
    scenario: 'negative-identity-and-entitlement-cases',
  },
};

function arrayLiteralFor(source, field) {
  const match = source.match(new RegExp(`${field}:\\s*\\[([^\\]]*)\\]`));
  assert.ok(match, `missing ${field} array`);
  return [...match[1].matchAll(/'([^']+)'/g)].map(([, value]) => value);
}

function stringLiteralFor(source, field) {
  const match = source.match(new RegExp(`${field}:\\s*'([^']+)'`));
  assert.ok(match, `missing ${field} string`);
  return match[1];
}

test('P0-C4 driver entrypoints have the exact gate/test/scenario contract', () => {
  const observedTests = [];

  for (const [filename, expected] of Object.entries(expectedDrivers)) {
    const path = join(driversDirectory, filename);
    const source = readFileSync(path, 'utf8');

    assert.equal(source.split('\n', 1)[0], '#!/usr/bin/env node', `${filename} must be executable Node.js`);
    assert.match(source, /import\s*\{\s*runGateDriver\s*\}\s*from\s*['"]\.\.\/lib\/driver-runtime\.mjs['"]/);
    assert.match(source, /await\s+runGateDriver\s*\(\s*\{/);
    assert.equal(stringLiteralFor(source, 'gate'), expected.gate);
    assert.deepEqual(arrayLiteralFor(source, 'tests'), expected.tests);
    assert.equal(stringLiteralFor(source, 'scenario'), expected.scenario);
    assert.equal(statSync(path).isFile(), true);

    observedTests.push(...expected.tests);
  }

  assert.equal(new Set(observedTests).size, observedTests.length, 'each physical test must have one driver owner');
  assert.deepEqual(observedTests.sort(), [
    'audit-console-observation',
    'claude-code-unattended-sign',
    'cloud-possession-proof',
    'cursor-code-unattended-sign',
    'exact-pkg-install',
    'launchd-xpc-approval',
    'secure-enclave-key-creation',
    'secure-enclave-nonexportability',
    'unrelated-process-denied',
  ]);
});

test('P0-C4 drivers delegate execution and do not log or handle secrets', () => {
  for (const filename of Object.keys(expectedDrivers)) {
    const source = readFileSync(join(driversDirectory, filename), 'utf8');

    assert.doesNotMatch(source, /console\.|process\.(stdout|stderr|env)|child_process|execFile|spawn|spawnSync/);
    assert.doesNotMatch(source, /(?:secret|token|password|private[_-]?key|credential|authorization)/i);
    assert.doesNotMatch(source, /(?:passed|qualified|approved|allow|deny|success|failure|true|false)/i);
    assert.doesNotMatch(source, /(?:JSON|config|fixture|mock|stub|claim|static)/i);
    assert.equal((source.match(/runGateDriver/g) ?? []).length, 2, `${filename} must delegate exactly once`);
  }
});
