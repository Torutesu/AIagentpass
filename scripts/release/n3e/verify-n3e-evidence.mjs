#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const N3E_SCHEMA_VERSION = 1;
export const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
export const REQUIRED_SCENARIOS = Object.freeze([
  'service-kill-after-cloud-commit',
  'daemon-restart-after-cloud-commit',
  'lost-reply-after-cloud-commit',
  'audit-fsync-failure-recovery'
]);

const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_DEPTH = 16;
const MAX_SCENARIO_EVENTS = 24;
const MAX_PROCESS_OBSERVATIONS = 8;
const MAX_DIGEST_REFERENCES = 32;
const FORBIDDEN_KEY = /(?:secret|token|password|private|credential|authorization|stdout|stderr|output|response[_-]?body|raw|signature|nonce)/iu;
const FORBIDDEN_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sk|ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{8,}|\bprivate[-_ ]?(?:key|token|credential)\b)/iu;

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value);
  const expected = [...keys];
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing, unknown, or non-canonical fields`);
};

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const parseString = (source, cursor) => {
  const start = cursor.index;
  cursor.index += 1;
  while (cursor.index < source.length) {
    const character = source[cursor.index];
    if (character === '\\') {
      cursor.index += 1;
      if (cursor.index >= source.length) throw new Error('invalid JSON string escape');
      if (source[cursor.index] === 'u') cursor.index += 4;
      else cursor.index += 1;
      continue;
    }
    if (character === '"') {
      cursor.index += 1;
      return JSON.parse(source.slice(start, cursor.index));
    }
    if (character < ' ') throw new Error('unescaped control character in JSON string');
    cursor.index += 1;
  }
  throw new Error('unterminated JSON string');
};

const skipWhitespace = (source, cursor) => {
  while (cursor.index < source.length && /\s/u.test(source[cursor.index])) cursor.index += 1;
};

const parseJSONWithDuplicateKeyRejection = (source) => {
  const cursor = { index: 0 };
  const parseValue = (depth) => {
    if (depth > MAX_DEPTH) throw new Error('JSON nesting is too deep');
    skipWhitespace(source, cursor);
    const character = source[cursor.index];
    if (character === '"') return parseString(source, cursor);
    if (character === '{') {
      cursor.index += 1;
      const result = {};
      const keys = new Set();
      skipWhitespace(source, cursor);
      if (source[cursor.index] === '}') { cursor.index += 1; return result; }
      while (true) {
        skipWhitespace(source, cursor);
        if (source[cursor.index] !== '"') throw new Error('JSON object key must be a string');
        const key = parseString(source, cursor);
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        keys.add(key);
        skipWhitespace(source, cursor);
        if (source[cursor.index] !== ':') throw new Error('JSON object key is missing a colon');
        cursor.index += 1;
        result[key] = parseValue(depth + 1);
        skipWhitespace(source, cursor);
        if (source[cursor.index] === '}') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') throw new Error('JSON object is missing a comma');
        cursor.index += 1;
      }
    }
    if (character === '[') {
      cursor.index += 1;
      const result = [];
      skipWhitespace(source, cursor);
      if (source[cursor.index] === ']') { cursor.index += 1; return result; }
      while (true) {
        result.push(parseValue(depth + 1));
        skipWhitespace(source, cursor);
        if (source[cursor.index] === ']') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') throw new Error('JSON array is missing a comma');
        cursor.index += 1;
      }
    }
    const literal = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(source.slice(cursor.index));
    if (!literal) throw new Error('invalid JSON value');
    cursor.index += literal[0].length;
    return JSON.parse(literal[0]);
  };
  const value = parseValue(0);
  skipWhitespace(source, cursor);
  if (cursor.index !== source.length) throw new Error('trailing JSON data');
  return value;
};

const scanForbiddenMaterial = (value, path = '$') => {
  if (Array.isArray(value)) {
    if (value.length > 256) throw new Error(`${path} is too large`);
    value.forEach((item, index) => scanForbiddenMaterial(item, `${path}[${index}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    Object.entries(value).forEach(([key, item]) => {
      if (FORBIDDEN_KEY.test(key)) throw new Error(`${path}.${key} contains forbidden secret or raw-output material`);
      scanForbiddenMaterial(item, `${path}.${key}`);
    });
    return;
  }
  if (typeof value === 'string' && FORBIDDEN_VALUE.test(value)) throw new Error(`${path} contains forbidden secret material`);
};

const stringValue = (value, pattern, label, max = 256) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value;
};

const digest = (value, label) => stringValue(value, DIGEST, label, 64);
const timestamp = (value, label) => {
  stringValue(value, ISO_TIME, label, 24);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} is invalid`);
  return value;
};
const decimal = (value, label, maximum = 9_223_372_036_854_775_807n) => {
  stringValue(value, DECIMAL, label, 20);
  if (BigInt(value) > maximum) throw new Error(`${label} is out of range`);
  return value;
};

const validateBinding = (value) => {
  exactKeys(value, ['artifact_sha256', 'source_commit', 'team_id', 'code_identities_sha256'], 'binding');
  return Object.freeze({
    artifact_sha256: digest(value.artifact_sha256, 'binding.artifact_sha256'),
    source_commit: stringValue(value.source_commit, COMMIT, 'binding.source_commit', 40),
    team_id: stringValue(value.team_id, TEAM_ID, 'binding.team_id', 10),
    code_identities_sha256: digest(value.code_identities_sha256, 'binding.code_identities_sha256')
  });
};

const validateProcessObservation = (value, label) => {
  exactKeys(value, ['process_role', 'pid', 'start_time_ns', 'boot_id_digest', 'executable_sha256', 'code_identity_sha256', 'observed_at', 'state'], label);
  const state = value.state;
  if (state !== 'running' && state !== 'exited') throw new Error(`${label}.state is invalid`);
  return Object.freeze({
    process_role: stringValue(value.process_role, SAFE_NAME, `${label}.process_role`, 80),
    pid: decimal(value.pid, `${label}.pid`, 2_147_483_647n),
    start_time_ns: decimal(value.start_time_ns, `${label}.start_time_ns`),
    boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`),
    executable_sha256: digest(value.executable_sha256, `${label}.executable_sha256`),
    code_identity_sha256: digest(value.code_identity_sha256, `${label}.code_identity_sha256`),
    observed_at: timestamp(value.observed_at, `${label}.observed_at`),
    state
  });
};

const validateEvent = (value, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const kind = value.kind;
  if (kind === 'process_alive' || kind === 'process_start') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'process_pid', 'process_start_time_ns'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), process_pid: decimal(value.process_pid, `${label}.process_pid`, 2_147_483_647n), process_start_time_ns: decimal(value.process_start_time_ns, `${label}.process_start_time_ns`) });
  }
  if (kind === 'process_exit') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'process_pid', 'process_start_time_ns', 'exit_reason'], label);
    if (value.exit_reason !== 'SIGKILL' && value.exit_reason !== 'restart') throw new Error(`${label}.exit_reason is invalid`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), process_pid: decimal(value.process_pid, `${label}.process_pid`, 2_147_483_647n), process_start_time_ns: decimal(value.process_start_time_ns, `${label}.process_start_time_ns`), exit_reason: value.exit_reason });
  }
  if (kind === 'cloud_commit') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'commit_receipt_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), commit_receipt_digest: digest(value.commit_receipt_digest, `${label}.commit_receipt_digest`) });
  }
  if (kind === 'reply_lost') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'transport_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), transport_digest: digest(value.transport_digest, `${label}.transport_digest`) });
  }
  if (kind === 'recovery') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'result_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), result_digest: digest(value.result_digest, `${label}.result_digest`) });
  }
  if (kind === 'audit_fsync') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'audit_record_digest', 'result'], label);
    if (value.result !== 'success' && value.result !== 'failure') throw new Error(`${label}.result is invalid`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), audit_record_digest: digest(value.audit_record_digest, `${label}.audit_record_digest`), result: value.result });
  }
  if (kind === 'audit_ack') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'audit_record_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), audit_record_digest: digest(value.audit_record_digest, `${label}.audit_record_digest`) });
  }
  throw new Error(`${label}.kind is unknown`);
};

const validateDigestReferences = (value, label) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_DIGEST_REFERENCES) throw new Error(`${label} is invalid`);
  const result = value.map((item, index) => {
    exactKeys(item, ['kind', 'sha256'], `${label}[${index}]`);
    return Object.freeze({ kind: stringValue(item.kind, SAFE_NAME, `${label}[${index}].kind`, 80), sha256: digest(item.sha256, `${label}[${index}].sha256`) });
  });
  if (result.some((item, index) => index > 0 && item.kind <= result[index - 1].kind) || new Set(result.map((item) => item.kind)).size !== result.length) throw new Error(`${label} must be sorted and unique`);
  return Object.freeze(result);
};

const sameProcess = (left, right) => left.pid === right.pid && left.start_time_ns === right.start_time_ns && left.boot_id_digest === right.boot_id_digest;
const processKey = (item) => `${item.pid}:${item.start_time_ns}:${item.boot_id_digest}`;
const eventTime = (event) => Date.parse(event.observed_at);

const requireSequence = (events, name, sequence) => {
  let cursor = -1;
  for (const kind of sequence) {
    const index = events.findIndex((event, eventIndex) => eventIndex > cursor && event.kind === kind);
    if (index === -1) throw new Error(`${name} does not prove required ${kind} transition`);
    cursor = index;
  }
};

const validateScenario = (value, index, host) => {
  const label = `scenarios[${index}]`;
  exactKeys(value, ['name', 'status', 'started_at', 'completed_at', 'process_observations', 'events', 'evidence_digests'], label);
  if (value.name !== REQUIRED_SCENARIOS[index]) throw new Error(`${label}.name is missing, duplicated, or out of order`);
  if (value.status !== 'passed') throw new Error(`${label}.status must be passed`);
  const started = timestamp(value.started_at, `${label}.started_at`);
  const completed = timestamp(value.completed_at, `${label}.completed_at`);
  if (Date.parse(started) > Date.parse(completed)) throw new Error(`${label} timestamps are reversed`);
  if (!Array.isArray(value.process_observations) || value.process_observations.length < 2 || value.process_observations.length > MAX_PROCESS_OBSERVATIONS) throw new Error(`${label}.process_observations is insufficient`);
  const processes = value.process_observations.map((item, itemIndex) => validateProcessObservation(item, `${label}.process_observations[${itemIndex}]`));
  if (processes.some((item, itemIndex) => itemIndex > 0 && Date.parse(item.observed_at) <= Date.parse(processes[itemIndex - 1].observed_at))) throw new Error(`${label}.process_observations must be time ordered`);
  if (processes.some((item) => Date.parse(item.observed_at) < Date.parse(started) || Date.parse(item.observed_at) > Date.parse(completed))) throw new Error(`${label}.process_observations escape the scenario window`);
  if (processes.some((item) => item.boot_id_digest !== host.boot_id_digest)) throw new Error(`${label}.process_observations boot identity is not bound to host`);
  const processObservationsByKey = new Map();
  for (const observation of processes) {
    const key = processKey(observation);
    const entries = processObservationsByKey.get(key) ?? [];
    entries.push(observation);
    processObservationsByKey.set(key, entries);
  }
  if (!Array.isArray(value.events) || value.events.length < 4 || value.events.length > MAX_SCENARIO_EVENTS) throw new Error(`${label}.events is insufficient`);
  const events = value.events.map((item, itemIndex) => validateEvent(item, `${label}.events[${itemIndex}]`));
  if (events.some((item, itemIndex) => itemIndex > 0 && eventTime(item) <= eventTime(events[itemIndex - 1]))) throw new Error(`${label}.events must be time ordered`);
  if (events.some((item) => eventTime(item) < Date.parse(started) || eventTime(item) > Date.parse(completed))) throw new Error(`${label}.events escape the scenario window`);
  if (events.some((item) => item.boot_id_digest !== host.boot_id_digest)) throw new Error(`${label}.events boot identity is not bound to host`);
  if (events.some((event) => {
    if (event.kind !== 'process_alive' && event.kind !== 'process_start' && event.kind !== 'process_exit') return false;
    const observations = processObservationsByKey.get(`${event.process_pid}:${event.process_start_time_ns}:${event.boot_id_digest}`) ?? [];
    const expectedState = event.kind === 'process_exit' ? 'exited' : 'running';
    return !observations.some((observation) => observation.state === expectedState);
  })) throw new Error(`${label} has an unobserved process transition`);
  const first = processes[0];
  const last = processes[processes.length - 1];
  if (value.name === 'service-kill-after-cloud-commit') {
    requireSequence(events, value.name, ['process_alive', 'cloud_commit', 'process_exit', 'reply_lost', 'process_start', 'recovery']);
    if (events.find((event) => event.kind === 'process_exit').exit_reason !== 'SIGKILL' || sameProcess(first, last)) throw new Error(`${label} does not prove a killed and replaced process`);
  } else if (value.name === 'daemon-restart-after-cloud-commit') {
    requireSequence(events, value.name, ['process_alive', 'cloud_commit', 'process_exit', 'process_start', 'recovery']);
    if (events.find((event) => event.kind === 'process_exit').exit_reason !== 'restart' || sameProcess(first, last)) throw new Error(`${label} does not prove a daemon restart`);
  } else if (value.name === 'lost-reply-after-cloud-commit') {
    requireSequence(events, value.name, ['process_alive', 'cloud_commit', 'reply_lost', 'recovery']);
    if (!sameProcess(first, last)) throw new Error(`${label} lost-reply proof must retain the same process identity`);
  } else if (value.name === 'audit-fsync-failure-recovery') {
    requireSequence(events, value.name, ['process_alive', 'cloud_commit', 'audit_fsync', 'reply_lost', 'audit_fsync', 'audit_ack', 'recovery']);
    const fsyncs = events.filter((event) => event.kind === 'audit_fsync');
    if (fsyncs[0].result !== 'failure' || fsyncs[1].result !== 'success' || fsyncs[0].audit_record_digest !== fsyncs[1].audit_record_digest || fsyncs[1].audit_record_digest !== events.find((event) => event.kind === 'audit_ack').audit_record_digest) throw new Error(`${label} does not prove audit fsync recovery`);
  }
  const evidenceDigests = validateDigestReferences(value.evidence_digests, `${label}.evidence_digests`);
  return Object.freeze({ name: value.name, status: value.status, started_at: started, completed_at: completed, process_observations: Object.freeze(processes), events: Object.freeze(events), evidence_digests: evidenceDigests });
};

const evidenceBody = (value) => {
  const { evidence_sha256: ignored, ...body } = value;
  return body;
};

export const n3eEvidenceHash = (value) => sha256(canonicalJSON(evidenceBody(value)));

export const validateN3EEvidence = (value) => {
  scanForbiddenMaterial(value);
  exactKeys(value, ['schema_version', 'candidate_id', 'binding', 'started_at', 'completed_at', 'host', 'scenarios', 'evidence_sha256'], 'N3-E evidence');
  if (value.schema_version !== N3E_SCHEMA_VERSION) throw new Error('N3-E schema version is unsupported');
  const candidateId = stringValue(value.candidate_id, SAFE_NAME, 'candidate_id', 80);
  const binding = validateBinding(value.binding);
  const started = timestamp(value.started_at, 'started_at');
  const completed = timestamp(value.completed_at, 'completed_at');
  if (Date.parse(started) > Date.parse(completed)) throw new Error('N3-E timestamps are reversed');
  exactKeys(value.host, ['platform', 'architecture', 'os_build', 'boot_id_digest'], 'host');
  if (value.host.platform !== 'macos' || (value.host.architecture !== 'arm64' && value.host.architecture !== 'x86_64')) throw new Error('host platform or architecture is invalid');
  const host = Object.freeze({ platform: value.host.platform, architecture: value.host.architecture, os_build: stringValue(value.host.os_build, /^[A-Za-z0-9._-]{3,32}$/u, 'host.os_build', 32), boot_id_digest: digest(value.host.boot_id_digest, 'host.boot_id_digest') });
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== REQUIRED_SCENARIOS.length) throw new Error('N3-E scenarios are incomplete');
  const scenarios = value.scenarios.map((item, index) => validateScenario(item, index, host));
  if (scenarios.some((scenario) => Date.parse(scenario.started_at) < Date.parse(started) || Date.parse(scenario.completed_at) > Date.parse(completed))) throw new Error('scenario timestamps escape the qualification window');
  const evidenceSha256 = digest(value.evidence_sha256, 'evidence_sha256');
  const normalized = Object.freeze({ schema_version: N3E_SCHEMA_VERSION, candidate_id: candidateId, binding, started_at: started, completed_at: completed, host, scenarios: Object.freeze(scenarios), evidence_sha256: evidenceSha256 });
  if (n3eEvidenceHash(normalized) !== evidenceSha256) throw new Error('N3-E evidence digest mismatch');
  return normalized;
};

export const parseN3EEvidence = (input, { maxBytes = MAX_EVIDENCE_BYTES } = {}) => {
  const bytes = Buffer.isBuffer(input) ? input : typeof input === 'string' ? Buffer.from(input, 'utf8') : null;
  if (!bytes || bytes.length === 0 || bytes.length > maxBytes) throw new Error('N3-E evidence input is missing or too large');
  const source = bytes.toString('utf8');
  const value = parseJSONWithDuplicateKeyRejection(source);
  if (source !== canonicalJSON(value).toString('utf8')) throw new Error('N3-E evidence must use canonical JSON');
  return validateN3EEvidence(value);
};

export const verifyN3EEvidence = (input, expectedBinding, options = {}) => {
  const evidence = Buffer.isBuffer(input) || typeof input === 'string' ? parseN3EEvidence(input, options) : validateN3EEvidence(input);
  if (expectedBinding !== undefined) {
    const binding = validateBinding(expectedBinding);
    if (JSON.stringify(binding) !== JSON.stringify(evidence.binding)) throw new Error('N3-E candidate binding mismatch');
  }
  return evidence;
};

export const verifyN3EEvidenceFile = (path, expectedBinding, options = {}) => verifyN3EEvidence(fs.readFileSync(path), expectedBinding, options);

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [, , path, artifactSha256, sourceCommit, teamId, codeIdentitiesSha256] = process.argv;
  if (!path) {
    process.stderr.write('usage: verify-n3e-evidence.mjs <evidence.json> [artifact_sha256 source_commit team_id code_identities_sha256]\n');
    process.exitCode = 2;
  } else {
    try {
      const expected = artifactSha256 ? { artifact_sha256: artifactSha256, source_commit: sourceCommit, team_id: teamId, code_identities_sha256: codeIdentitiesSha256 } : undefined;
      const evidence = verifyN3EEvidenceFile(path, expected);
      process.stdout.write(`${JSON.stringify({ schema_version: evidence.schema_version, candidate_id: evidence.candidate_id, evidence_sha256: evidence.evidence_sha256, scenarios: evidence.scenarios.map(({ name, status }) => ({ name, status })) }, null, 2)}\n`);
    } catch (error) {
      process.stderr.write(`N3-E evidence refused: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  }
}
