import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertExternalGates, assertWorkflowBoundary } from './ci-preflight.mjs';

test('workflow boundary rejects pull requests and non-main refs', () => {
  assert.throws(() => assertWorkflowBoundary({ eventName: 'pull_request', ref: 'refs/heads/main', repository: 'Torutesu/AIagentpass' }), /cannot access release credentials/);
  assert.throws(() => assertWorkflowBoundary({ eventName: 'workflow_dispatch', ref: 'refs/heads/feature', repository: 'Torutesu/AIagentpass' }), /protected main/);
});

test('external gate preflight rejects not_proven evidence and requires explicit status', () => {
  const root = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-ci-preflight-'));
  const blocked = join(root, 'blocked.json');
  const passed = join(root, 'passed.json');
  fs.writeFileSync(blocked, JSON.stringify({ apple: { status: 'not_proven' } }));
  fs.writeFileSync(passed, JSON.stringify({ qualified: true, production: true }));
  assert.throws(() => assertExternalGates({ gateFiles: [blocked], required: { qualified: true } }), /not_proven/);
  assert.throws(() => assertExternalGates({ gateFiles: [passed], required: { hardware: true } }), /hardware=true/);
  assert.deepEqual(assertExternalGates({ gateFiles: [passed], required: { qualified: true, production: true } }), { files: 1, required: ['qualified', 'production'] });
});
