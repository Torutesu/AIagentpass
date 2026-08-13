#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const N3E_SCHEMA_VERSION = 1;
export const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
export const REQUIRED_SCENARIOS = Object.freeze([
  'pre-cloud-kill',
  'post-cloud-pre-local-kill',
  'post-activation-pre-audit-kill',
  'post-audit-pre-reply-loss',
  'audit-fsync-failure',
  'transport-reply-loss'
]);

const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_DEPTH = 16;
const MAX_SCENARIO_EVENTS = 16;
const MAX_PROCESS_OBSERVATIONS = 8;
const MAX_DIGEST_REFERENCES = 24;
const FORBIDDEN_KEY = /(?:secret|token|password|private|credential|authorization|stdout|stderr|output|response[_-]?body|raw|signature|nonce)/iu;
const FORBIDDEN_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sk|ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{8,}|\bprivate[-_ ]?(?:key|token|credential)\b)/iu;

const SCENARIO_EVENT_INVENTORY = Object.freeze({
  'pre-cloud-kill': Object.freeze(['process_alive', 'process_exit', 'process_start', 'cloud_observation', 'local_authority']),
  'post-cloud-pre-local-kill': Object.freeze(['process_alive', 'cloud_commit', 'process_exit', 'process_start', 'recovery', 'cloud_observation', 'local_authority']),
  'post-activation-pre-audit-kill': Object.freeze(['process_alive', 'cloud_commit', 'local_activation', 'process_exit', 'process_start', 'cloud_observation', 'local_authority']),
  'post-audit-pre-reply-loss': Object.freeze(['process_alive', 'cloud_commit', 'local_activation', 'audit_fsync', 'audit_ack', 'process_exit', 'reply_lost', 'process_start', 'recovery', 'cloud_observation', 'local_authority']),
  'audit-fsync-failure': Object.freeze(['process_alive', 'cloud_commit', 'local_activation', 'audit_fsync', 'compensation', 'cloud_observation', 'local_authority']),
  'transport-reply-loss': Object.freeze(['process_alive', 'cloud_commit', 'local_activation', 'audit_fsync', 'audit_ack', 'reply_lost', 'recovery', 'cloud_observation', 'local_authority'])
});

const SCENARIO_DIGEST_INVENTORY = Object.freeze({
  'pre-cloud-kill': Object.freeze(['cloud-observation-0', 'code-identity-set', 'local-authority-0', 'process-code-identity-0', 'process-executable-0']),
  'post-cloud-pre-local-kill': Object.freeze(['cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0']),
  'post-activation-pre-audit-kill': Object.freeze(['cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0']),
  'post-audit-pre-reply-loss': Object.freeze(['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0', 'reply-result-0', 'transport-0']),
  'audit-fsync-failure': Object.freeze(['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'compensation-0', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0']),
  'transport-reply-loss': Object.freeze(['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0', 'reply-result-0', 'transport-0'])
});

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
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'commit_receipt_digest', 'session_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), commit_receipt_digest: digest(value.commit_receipt_digest, `${label}.commit_receipt_digest`), session_digest: digest(value.session_digest, `${label}.session_digest`) });
  }
  if (kind === 'cloud_observation') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'observation_digest', 'commit_count', 'session_count', 'active_session_count', 'compensation_count', 'commit_receipt_digest', 'session_digest', 'compensation_digest'], label);
    const count = (field) => {
      if (value[field] !== '0' && value[field] !== '1') throw new Error(`${label}.${field} must be 0 or 1`);
      return value[field];
    };
    const nullableDigest = (field) => {
      if (value[field] !== null) return digest(value[field], `${label}.${field}`);
      return null;
    };
    return Object.freeze({
      kind,
      observed_at: timestamp(value.observed_at, `${label}.observed_at`),
      boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`),
      request_digest: digest(value.request_digest, `${label}.request_digest`),
      observation_digest: digest(value.observation_digest, `${label}.observation_digest`),
      commit_count: count('commit_count'),
      session_count: count('session_count'),
      active_session_count: count('active_session_count'),
      compensation_count: count('compensation_count'),
      commit_receipt_digest: nullableDigest('commit_receipt_digest'),
      session_digest: nullableDigest('session_digest'),
      compensation_digest: nullableDigest('compensation_digest')
    });
  }
  if (kind === 'local_activation') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'authority_digest', 'session_digest'], label);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), authority_digest: digest(value.authority_digest, `${label}.authority_digest`), session_digest: digest(value.session_digest, `${label}.session_digest`) });
  }
  if (kind === 'local_authority') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'authority_digest', 'authority_count', 'state', 'session_digest'], label);
    if (value.authority_count !== '0' && value.authority_count !== '1') throw new Error(`${label}.authority_count must be 0 or 1`);
    if (value.state !== 'absent' && value.state !== 'active' && value.state !== 'revoked') throw new Error(`${label}.state is invalid`);
    if (value.authority_count === '0' && value.state === 'active') throw new Error(`${label} cannot report active authority with a zero count`);
    if (value.authority_count === '1' && value.state === 'absent') throw new Error(`${label} cannot report absent authority with a non-zero count`);
    if (value.session_digest !== null) digest(value.session_digest, `${label}.session_digest`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), authority_digest: digest(value.authority_digest, `${label}.authority_digest`), authority_count: value.authority_count, state: value.state, session_digest: value.session_digest });
  }
  if (kind === 'reply_lost') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'transport_digest', 'result_digest', 'loss_boundary'], label);
    if (value.loss_boundary !== 'daemon-kill' && value.loss_boundary !== 'transport') throw new Error(`${label}.loss_boundary is invalid`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), transport_digest: digest(value.transport_digest, `${label}.transport_digest`), result_digest: digest(value.result_digest, `${label}.result_digest`), loss_boundary: value.loss_boundary });
  }
  if (kind === 'recovery') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'result_digest', 'commit_receipt_digest', 'session_digest', 'retry_kind'], label);
    if (value.retry_kind !== 'exact') throw new Error(`${label}.retry_kind must be exact`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), result_digest: digest(value.result_digest, `${label}.result_digest`), commit_receipt_digest: digest(value.commit_receipt_digest, `${label}.commit_receipt_digest`), session_digest: digest(value.session_digest, `${label}.session_digest`), retry_kind: value.retry_kind });
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
  if (kind === 'compensation') {
    exactKeys(value, ['kind', 'observed_at', 'boot_id_digest', 'request_digest', 'session_digest', 'compensation_digest', 'reason', 'result'], label);
    if (value.reason !== 'audit-fsync-failure' || value.result !== 'revoked') throw new Error(`${label} compensation is invalid`);
    return Object.freeze({ kind, observed_at: timestamp(value.observed_at, `${label}.observed_at`), boot_id_digest: digest(value.boot_id_digest, `${label}.boot_id_digest`), request_digest: digest(value.request_digest, `${label}.request_digest`), session_digest: digest(value.session_digest, `${label}.session_digest`), compensation_digest: digest(value.compensation_digest, `${label}.compensation_digest`), reason: value.reason, result: value.result });
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

const requireDigestReference = (references, kind, expected, label) => {
  const reference = references.find((item) => item.kind === kind);
  if (!reference || reference.sha256 !== expected) throw new Error(`${label} is not bound to digest inventory`);
};

const requireCloudObservationBinding = (references, observation, label) => {
  requireDigestReference(references, 'cloud-observation-0', observation.observation_digest, `${label}.cloud_observation`);
  if (observation.commit_count === '0' && (observation.session_count !== '0' || observation.active_session_count !== '0' || observation.compensation_count !== '0' || observation.commit_receipt_digest !== null || observation.session_digest !== null || observation.compensation_digest !== null)) throw new Error(`${label} zero Cloud observation is inconsistent`);
  if (observation.commit_count === '1' && observation.session_count !== '1') throw new Error(`${label} Cloud commit does not prove one Cloud session`);
  if (observation.session_count === '1' && observation.session_digest === null) throw new Error(`${label} Cloud session count has no digest`);
  if (observation.commit_count === '1' && observation.commit_receipt_digest === null) throw new Error(`${label} Cloud commit count has no receipt digest`);
  if (observation.compensation_count === '1' && observation.compensation_digest === null) throw new Error(`${label} compensation count has no digest`);
  if (observation.active_session_count === '1' && observation.session_count !== '1') throw new Error(`${label} active Cloud session has no committed session`);
  if (observation.compensation_count === '1' && observation.active_session_count !== '0') throw new Error(`${label} compensated Cloud session remains active`);
};

const requireExactDigestInventory = (references, expected, label) => {
  const actual = references.map((item) => item.kind);
  if (actual.length !== expected.length || actual.some((kind, index) => kind !== expected[index])) throw new Error(`${label} digest inventory is missing, unknown, duplicated, or out of order`);
};

const validateScenario = (value, index, host, binding) => {
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
  if (!Array.isArray(value.events) || value.events.length < 1 || value.events.length > MAX_SCENARIO_EVENTS) throw new Error(`${label}.events is insufficient`);
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
  const evidenceDigests = validateDigestReferences(value.evidence_digests, `${label}.evidence_digests`);
  requireExactDigestInventory(evidenceDigests, SCENARIO_DIGEST_INVENTORY[value.name], label);
  requireDigestReference(evidenceDigests, 'code-identity-set', binding.code_identities_sha256, `${label}.code-identity-set`);
  requireDigestReference(evidenceDigests, 'process-executable-0', processes[0].executable_sha256, `${label}.process-executable-0`);
  requireDigestReference(evidenceDigests, 'process-code-identity-0', processes[0].code_identity_sha256, `${label}.process-code-identity-0`);
  if (processes.some((item) => item.process_role !== processes[0].process_role || item.executable_sha256 !== processes[0].executable_sha256 || item.code_identity_sha256 !== processes[0].code_identity_sha256)) throw new Error(`${label} process identity is not stable across the scenario`);
  const expectedKinds = SCENARIO_EVENT_INVENTORY[value.name];
  if (events.map((event) => event.kind).some((kind, eventIndex) => kind !== expectedKinds[eventIndex]) || events.length !== expectedKinds.length) throw new Error(`${label} event inventory is missing, unknown, duplicated, or out of order`);
  const first = processes[0];
  const last = processes[processes.length - 1];
  const killed = value.name === 'pre-cloud-kill' || value.name === 'post-cloud-pre-local-kill' || value.name === 'post-activation-pre-audit-kill' || value.name === 'post-audit-pre-reply-loss';
  if (killed) {
    if (processes.length !== 3 || processes[0].state !== 'running' || processes[1].state !== 'exited' || processes[2].state !== 'running' || !sameProcess(processes[0], processes[1]) || sameProcess(first, last)) throw new Error(`${label} does not prove a killed and replaced process`);
    const exit = events.find((event) => event.kind === 'process_exit');
    if (exit.exit_reason !== 'SIGKILL') throw new Error(`${label} must use SIGKILL for the activation fault`);
  } else if (processes.length !== 2 || processes.some((process) => process.state !== 'running') || !sameProcess(first, last)) {
    throw new Error(`${label} must retain one running process identity`);
  }
  const alive = events.find((event) => event.kind === 'process_alive');
  if (alive.process_pid !== first.pid || alive.process_start_time_ns !== first.start_time_ns) throw new Error(`${label} process_alive is not bound to the first process`);
  const start = events.find((event) => event.kind === 'process_start');
  if (start && (start.process_pid !== last.pid || start.process_start_time_ns !== last.start_time_ns)) throw new Error(`${label} process_start is not bound to the observed process`);
  const commit = events.find((event) => event.kind === 'cloud_commit');
  const recovery = events.find((event) => event.kind === 'recovery');
  const lost = events.find((event) => event.kind === 'reply_lost');
  const activation = events.find((event) => event.kind === 'local_activation');
  const observation = events.find((event) => event.kind === 'cloud_observation');
  const authority = events.find((event) => event.kind === 'local_authority');
  requireCloudObservationBinding(evidenceDigests, observation, label);
  if (commit) {
    requireDigestReference(evidenceDigests, 'cloud-commit-0', commit.commit_receipt_digest, `${label}.cloud-commit`);
    if (observation.request_digest !== commit.request_digest || observation.commit_receipt_digest !== commit.commit_receipt_digest || observation.session_digest !== commit.session_digest) throw new Error(`${label} Cloud observation does not match the committed Cloud session`);
    if (observation.commit_count !== '1' || observation.session_count !== '1') throw new Error(`${label} Cloud commit does not prove exactly one Cloud session`);
  } else if (observation.commit_count !== '0' || observation.session_count !== '0') {
    throw new Error(`${label} reports Cloud activity without a Cloud commit event`);
  }
  if (recovery) {
    requireDigestReference(evidenceDigests, 'recovery-result-0', recovery.result_digest, `${label}.recovery-result`);
    if (recovery.commit_receipt_digest !== commit?.commit_receipt_digest || recovery.session_digest !== commit?.session_digest) throw new Error(`${label} recovery is not an exact retry of the committed Cloud Session`);
    if (lost && (recovery.request_digest !== lost.request_digest || recovery.result_digest !== lost.result_digest)) throw new Error(`${label} recovery is not an exact retry of the lost result`);
  }
  if (lost) {
    requireDigestReference(evidenceDigests, 'transport-0', lost.transport_digest, `${label}.transport`);
    requireDigestReference(evidenceDigests, 'reply-result-0', lost.result_digest, `${label}.reply-result`);
  }
  if (activation) {
    requireDigestReference(evidenceDigests, 'local-activation-0', activation.authority_digest, `${label}.local-activation`);
    if (!commit || activation.session_digest !== commit.session_digest) throw new Error(`${label} local activation is not bound to the Cloud session`);
  }
  requireDigestReference(evidenceDigests, 'local-authority-0', authority.authority_digest, `${label}.local-authority`);
  if (authority.session_digest !== null && (!commit || authority.session_digest !== commit.session_digest)) throw new Error(`${label} local authority is bound to the wrong Cloud session`);
  if (value.name === 'pre-cloud-kill') {
    if (commit || observation.commit_count !== '0' || observation.session_count !== '0' || authority.authority_count !== '0' || authority.state !== 'absent') throw new Error(`${label} does not prove no Cloud commit, Session, or local authority`);
  } else if (value.name === 'post-cloud-pre-local-kill') {
    if (!commit || !recovery || observation.active_session_count !== '1' || observation.compensation_count !== '0' || authority.authority_count !== '0' || authority.state !== 'absent') throw new Error(`${label} does not prove exact Cloud recovery before local activation`);
  } else if (value.name === 'post-activation-pre-audit-kill') {
    if (!commit || !activation || observation.active_session_count !== '1' || authority.authority_count !== '0' || authority.state !== 'absent') throw new Error(`${label} does not prove no local authority after restart`);
  } else if (value.name === 'post-audit-pre-reply-loss') {
    const fsync = events.find((event) => event.kind === 'audit_fsync');
    const ack = events.find((event) => event.kind === 'audit_ack');
    if (!commit || !activation || !lost || lost.loss_boundary !== 'daemon-kill' || fsync.result !== 'success' || ack.audit_record_digest !== fsync.audit_record_digest || authority.authority_count !== '0' || authority.state !== 'absent') throw new Error(`${label} does not prove exact result after post-audit kill`);
    requireDigestReference(evidenceDigests, 'audit-record-0', fsync.audit_record_digest, `${label}.audit-record`);
  } else if (value.name === 'audit-fsync-failure') {
    const fsync = events.find((event) => event.kind === 'audit_fsync');
    const compensation = events.find((event) => event.kind === 'compensation');
    if (!commit || !activation || fsync.result !== 'failure' || compensation.request_digest !== commit.request_digest || compensation.session_digest !== commit.session_digest || observation.compensation_count !== '1' || observation.active_session_count !== '0' || observation.compensation_digest !== compensation.compensation_digest || authority.authority_count !== '0' || authority.state !== 'revoked') throw new Error(`${label} does not prove compensation and no authority after audit fsync failure`);
    requireDigestReference(evidenceDigests, 'audit-record-0', fsync.audit_record_digest, `${label}.audit-record`);
    requireDigestReference(evidenceDigests, 'compensation-0', compensation.compensation_digest, `${label}.compensation`);
  } else if (value.name === 'transport-reply-loss') {
    const fsync = events.find((event) => event.kind === 'audit_fsync');
    const ack = events.find((event) => event.kind === 'audit_ack');
    if (!commit || !activation || !lost || lost.loss_boundary !== 'transport' || fsync.result !== 'success' || ack.audit_record_digest !== fsync.audit_record_digest || authority.authority_count !== '1' || authority.state !== 'active' || observation.active_session_count !== '1') throw new Error(`${label} does not prove exact transport retry`);
    requireDigestReference(evidenceDigests, 'audit-record-0', fsync.audit_record_digest, `${label}.audit-record`);
  }
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
  const scenarios = value.scenarios.map((item, index) => validateScenario(item, index, host, binding));
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
