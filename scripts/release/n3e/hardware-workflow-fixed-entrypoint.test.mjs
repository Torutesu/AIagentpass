import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..', '..');
const WORKFLOW_PATH = resolve(ROOT, '.github/workflows/p0c-hardware-qualification.yml');
const workflow = fs.readFileSync(WORKFLOW_PATH, 'utf8');

const QUALIFICATION_TOOL_ROOT = '/opt/agentpass/p0c/qualification-tool';
const FIXED_ENTRYPOINT = `${QUALIFICATION_TOOL_ROOT}/n3e/qualification-suite-orchestrator.mjs`;
const FIXED_INPUT_MATERIALIZER = `${QUALIFICATION_TOOL_ROOT}/n3e/qualification-input-materializer.mjs`;
const FIXED_RELEASE_MATERIALIZER = `${QUALIFICATION_TOOL_ROOT}/n3e/qualification-release-materializer.mjs`;
const FIXED_INPUT_PATH = '/private/var/db/agentpass-qualification/input.json';
const FIXED_NODE = 'sudo -n /usr/bin/node';
const MATERIALIZER_SOURCE = 'scripts/release/n3e/qualification-input-materializer.mjs';
const MATERIALIZER_INSTALLED = 'n3e/qualification-input-materializer.mjs';
const SUITE_SOURCE = 'scripts/release/n3e/qualification-suite-orchestrator.mjs';
const SUITE_INSTALLED = 'n3e/qualification-suite-orchestrator.mjs';

const REQUIRED_SCENARIOS = Object.freeze([
  'pre-cloud-kill',
  'post-cloud-pre-local-kill',
  'post-activation-pre-audit-kill',
  'post-audit-pre-reply-loss',
  'audit-fsync-failure',
  'transport-reply-loss'
]);

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const job = (name) => {
  const headings = [...workflow.matchAll(/^  ([A-Za-z0-9_-]+):\s*$/gm)];
  const current = headings.find((match) => match[1] === name);
  assert.ok(current, `missing workflow job: ${name}`);
  const next = headings.find((match) => match.index > current.index);
  return workflow.slice(current.index, next?.index ?? workflow.length);
};

const laneSections = () => [
  ['apple-silicon-qualification', job('apple-silicon-qualification')],
  ['intel-t2-qualification', job('intel-t2-qualification')]
];

const shellLines = (section) => section.split('\n').map((line) => line.trim()).filter(Boolean);

const fixedInvocation = new RegExp(`^${escapeRegExp(FIXED_NODE)} ${escapeRegExp(FIXED_ENTRYPOINT)} (run|recover)$`, 'u');
const materializerInvocation = new RegExp(`^${escapeRegExp(FIXED_NODE)} ${escapeRegExp(FIXED_INPUT_MATERIALIZER)} materialize$`, 'u');

const missingFixedInvocationContracts = (name, section) => {
  const lines = shellLines(section);
  const fixedLines = lines.filter((line) => line.startsWith(`${FIXED_NODE} ${FIXED_ENTRYPOINT} `));
  const operations = fixedLines.map((line) => fixedInvocation.exec(line)?.[1] ?? null);
  const missing = [];

  if (operations.length !== 2 || operations.filter(Boolean).length !== 2 || operations.sort().join(',') !== 'recover,run') {
    missing.push(`${name}: must invoke ${FIXED_ENTRYPOINT} exactly twice with the closed argv operations run and recover; observed ${JSON.stringify(fixedLines)}`);
  }

  for (const line of fixedLines) {
    if (!fixedInvocation.test(line)) missing.push(`${name}: fixed entrypoint invocation has caller-controlled executable/arguments: ${line}`);
  }

  return missing;
};

test('both hardware lanes use only the installed fixed entrypoint and closed run/recover argv', () => {
  const missing = laneSections().flatMap(([name, section]) => missingFixedInvocationContracts(name, section));
  assert.deepEqual(missing, [], `fixed-entrypoint workflow contracts are missing:\n${missing.join('\n')}`);
});

test('both hardware lanes materialize the fixed root input through the pinned installed tool', () => {
  const missing = [];
  for (const [name, section] of laneSections()) {
    const lines = shellLines(section);
    const materializerLines = lines.filter((line) => line.startsWith(`${FIXED_NODE} ${FIXED_INPUT_MATERIALIZER} `));
    const materializerOperations = materializerLines.map((line) => materializerInvocation.exec(line)?.[0] ?? null);
    const fixedRunIndex = lines.findIndex((line) => fixedInvocation.test(line) && line.endsWith(' run'));
    const materializerIndex = lines.findIndex((line) => materializerInvocation.test(line));

    if (!section.includes(`['${MATERIALIZER_INSTALLED}', '${MATERIALIZER_SOURCE}']`)) {
      missing.push(`${name}: preflight manifest must pin ${MATERIALIZER_INSTALLED} to ${MATERIALIZER_SOURCE}`);
    }
    if (materializerOperations.length !== 1 || materializerOperations[0] === null) {
      missing.push(`${name}: must invoke the root-owned installed fixed-input materializer exactly once with only materialize; observed ${JSON.stringify(materializerLines)}`);
    }
    if (!section.includes(FIXED_INPUT_PATH)) missing.push(`${name}: must bind the materializer and fixed entrypoint to ${FIXED_INPUT_PATH}`);
    if (materializerIndex < 0 || fixedRunIndex < 0 || materializerIndex >= fixedRunIndex) {
      missing.push(`${name}: fixed input must be materialized before the fixed entrypoint run`);
    }
    for (const line of materializerLines) {
      if (!materializerInvocation.test(line)) missing.push(`${name}: fixed-input materializer has a dynamic executable path or caller argument: ${line}`);
      if (/\$(?:CANDIDATE|OUTPUT|TEMPLATE|REPORT|PRODUCT)|--(?:output|manifest|signature|public-key|product|run-binding)/u.test(line)) {
        missing.push(`${name}: fixed-input materializer must derive its input from protected installed state, not dynamic workflow paths: ${line}`);
      }
    }
  }
  assert.deepEqual(missing, [], `fixed-root-input workflow contracts are missing:\n${missing.join('\n')}`);
});

test('both hardware lanes explicitly orchestrate the unarmed control and the complete ordered six-scenario suite', () => {
  const missing = [];
  const suiteSourcePath = resolve(ROOT, SUITE_SOURCE);
  let suiteSource = '';
  try { suiteSource = fs.readFileSync(suiteSourcePath, 'utf8'); } catch { missing.push(`installed suite source is missing from the trusted checkout: ${SUITE_SOURCE}`); }
  if (suiteSource) {
    if (!suiteSource.includes('QUALIFICATION_SUITE_STEPS')) missing.push('suite orchestrator must execute its closed suite-step inventory');
    if (!suiteSource.includes('QUALIFICATION_SUITE_MAX_STEPS = 7')) missing.push('suite orchestrator must bind one unarmed control plus six scenarios');
    if (!suiteSource.includes('executeQualificationUnarmedControl')) missing.push('suite orchestrator must execute the unarmed-control contract');
    if (!suiteSource.includes('consumeFixedQualificationSuiteInput')) missing.push('suite orchestrator must consume the one-shot seven-Grant suite input');
    if (!suiteSource.includes('runFixedStep')) missing.push('suite orchestrator must execute every suite step through the fixed composition');
    if (!suiteSource.includes("['recover', 'run']") && !suiteSource.includes("['run', 'recover']")) missing.push('suite orchestrator CLI must be closed to run|recover');
  }
  for (const [name, section] of laneSections()) {
    const lines = shellLines(section);
    if (!section.includes(`['${SUITE_INSTALLED}', '${SUITE_SOURCE}']`)) missing.push(`${name}: preflight manifest must pin ${SUITE_INSTALLED} to ${SUITE_SOURCE}`);
    const suiteLines = lines.filter((line) => line.startsWith(`${FIXED_NODE} ${FIXED_ENTRYPOINT} `));
    if (suiteLines.length !== 2) missing.push(`${name}: must execute the installed suite entrypoint for the unarmed+six suite with run and recover; observed ${JSON.stringify(suiteLines)}`);
    if (suiteLines.some((line) => !fixedInvocation.test(line))) missing.push(`${name}: suite entrypoint must receive only run or recover and no dynamic executable/path arguments`);
  }
  assert.deepEqual(missing, [], `qualification-suite workflow contracts are missing:\n${missing.join('\n')}`);
});

test('both hardware lanes stage and recover candidate-bound release trust through the installed boundary', () => {
  const missing = [];
  for (const [name, section] of laneSections()) {
    const lines = shellLines(section).filter((line) => line.includes(FIXED_RELEASE_MATERIALIZER));
    if (lines.length !== 2) missing.push(`${name}: expected one release materialize and one release recover invocation; observed ${JSON.stringify(lines)}`);
    if (!lines.some((line) => line.startsWith(`${FIXED_NODE} ${FIXED_RELEASE_MATERIALIZER} materialize `))) missing.push(`${name}: missing installed release materialization boundary`);
    if (!lines.some((line) => line === `${FIXED_NODE} ${FIXED_RELEASE_MATERIALIZER} recover`)) missing.push(`${name}: missing closed release recovery invocation`);
    if (!section.includes('/private/var/db/agentpass-qualification/release-trust.json')) missing.push(`${name}: release trust fixed path is not asserted`);
  }
  assert.deepEqual(missing, [], `release materialization workflow contracts are missing:\n${missing.join('\n')}`);
});
