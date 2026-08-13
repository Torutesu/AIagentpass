import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_GATES, REQUIRED_TESTS } from '../scripts/release/run-p0c-qualification.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const drivers = path.join(root, 'scripts/release/p0c/drivers');

test('checked-in physical drivers assign every runner test exactly once', () => {
  const declared = new Map(); const testOwners = new Map();
  for (const gate of REQUIRED_GATES) {
    const file = path.join(drivers, gate); const stat = fs.statSync(file);
    assert.equal(stat.isFile(), true); assert.notEqual(stat.mode & 0o111, 0, `${gate} must be executable`);
    const source = fs.readFileSync(file, 'utf8');
    const gateMatch = source.match(/gate:\s*['"]([^'"]+)['"]/u);
    const testsMatch = source.match(/tests:\s*\[([^\]]+)\]/u);
    assert.equal(gateMatch?.[1], gate); assert.ok(testsMatch, `${gate} must declare tests`);
    const tests = [...testsMatch[1].matchAll(/['"]([^'"]+)['"]/gu)].map((match) => match[1]);
    assert.ok(tests.length > 0); declared.set(gate, tests);
    for (const name of tests) {
      assert.equal(testOwners.has(name), false, `${name} is assigned to more than one gate`);
      testOwners.set(name, gate);
    }
  }
  assert.deepEqual([...declared.keys()], [...REQUIRED_GATES]);
  assert.deepEqual([...testOwners.keys()].sort(), [...REQUIRED_TESTS].sort());
  const allowedFiles = new Set([...REQUIRED_GATES, 'install-signing-drivers.test.mjs', 'lifecycle-drivers.test.mjs']);
  assert.deepEqual(fs.readdirSync(drivers).sort(), [...allowedFiles].sort());
});
