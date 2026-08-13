import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../../..');
const ENTRYPOINT = 'run-fixed-protected-qualification.mjs';
const INSTALLED_ENTRYPOINT = `n3e/${ENTRYPOINT}`;
const SOURCE_ENTRYPOINT = `scripts/release/n3e/${ENTRYPOINT}`;
const packageJSON = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const workflow = fs.readFileSync(path.join(ROOT, '.github/workflows/p0c-hardware-qualification.yml'), 'utf8');

const expectedPair = `['${INSTALLED_ENTRYPOINT}', '${SOURCE_ENTRYPOINT}']`;
const unarmedPair = "['n3e/qualification-unarmed-control.mjs', 'scripts/release/n3e/qualification-unarmed-control.mjs']";

test('the fixed protected qualification entrypoint is present in the source tree', () => {
  assert.equal(fs.existsSync(path.join(ROOT, SOURCE_ENTRYPOINT)), true, `missing ${SOURCE_ENTRYPOINT}`);
});

test('the N3-E packaging test is included in the package test surface', () => {
  assert.match(packageJSON.scripts.test, /scripts\/release\/n3e\/\*\.test\.mjs/u);
  assert.equal(packageJSON.scripts['test:n3e:packaging'], 'node --test scripts/release/n3e/packaging.test.mjs');
  assert.match(packageJSON.scripts.lint, /scripts\/release\/n3e\/\*\.mjs/u);
});

test('both hardware-lane preflights pin the fixed protected entrypoint source and installed names', () => {
  assert.equal(workflow.split(expectedPair).length - 1, 2, `expected the fixed pair in both hardware-lane preflights: ${expectedPair}`);
  assert.equal(workflow.split(unarmedPair).length - 1, 2, 'expected the unarmed control in both hardware-lane preflights');
  assert.equal(workflow.split(`qualification tool manifest is invalid`).length - 1, 2, 'expected duplicated immutable manifest checks for both hardware lanes');
});
