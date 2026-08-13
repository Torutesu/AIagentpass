#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from './qualification-canonical-json.mjs';
import {
  QUALIFICATION_ACTIVATION_MIN_TTL_SECONDS,
} from './qualification-activation-contract.mjs';
import {
  FIXED_INPUT_KIND,
  FIXED_INPUT_SCHEMA_VERSION
} from './run-fixed-protected-qualification.mjs';
import {
  QUALIFICATION_SUITE_INPUT_KIND,
  QUALIFICATION_SUITE_STEPS,
  canonicalQualificationSuiteInput
} from './qualification-suite-input.mjs';
import { proveNoQualificationProcesses } from './qualification-scenario-driver.mjs';

export const QUALIFICATION_RELAY_SCHEMA_VERSION = 1;
export const QUALIFICATION_RELAY_REQUEST_KIND = 'agentpass-n3e-qualification-relay-claim-request';
export const QUALIFICATION_RELAY_BATCH_KIND = 'agentpass-n3e-qualification-grant-batch';
export const QUALIFICATION_RELAY_REQUEST_PATH = '/private/var/db/agentpass-qualification/relay-request.json';
export const QUALIFICATION_RELAY_INBOX_PATH = '/private/var/db/agentpass-qualification/input.inbox.json';
export const QUALIFICATION_RELAY_ROOT_DIRECTORY = dirname(QUALIFICATION_RELAY_REQUEST_PATH);
export const QUALIFICATION_RELAY_MAX_REQUEST_BYTES = 32 * 1024;
export const QUALIFICATION_RELAY_MAX_RESPONSE_BYTES = 512 * 1024;
export const QUALIFICATION_RELAY_MAX_RUN_BINDING_BYTES = 128;
export const QUALIFICATION_RELAY_MAX_TTL_SECONDS = 3_600;

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$/u;
const MANIFEST_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const RUN_BINDING = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const STAGING_FILE = /^\.qualification-relay-input\.[0-9]+\.[a-f0-9]{32}\.tmp$/u;

const REQUEST_KEYS = Object.freeze([
  'agent_id',
  'agent_kind',
  'artifact_sha256',
  'batch_id',
  'candidate_checkpoint_sha256',
  'candidate_sha256',
  'device_id',
  'expires_at',
  'kind',
  'organization_id',
  'release_trust_sha256',
  'request_id',
  'requested_ttl_seconds',
  'schema_version',
  'source_commit',
  'team_id'
]);
const ENVELOPE_KEYS = Object.freeze(['batch', 'request_id']);
const BATCH_KEYS = Object.freeze([
  'agent_id',
  'agent_kind',
  'artifact_sha256',
  'batch_id',
  'candidate_checkpoint_sha256',
  'candidate_sha256',
  'device_id',
  'expires_at',
  'kind',
  'organization_id',
  'release_trust_sha256',
  'requested_ttl_seconds',
  'schema_version',
  'source_commit',
  'steps',
  'team_id',
  'manifest'
]);
const STEP_KEYS = Object.freeze(['grant', 'index', 'kind', 'phase', 'run_binding', 'scenario']);
const GRANT_KEYS = Object.freeze(['signature', 'statement', 'statement_hash', 'type', 'version']);
const STATEMENT_KEYS = Object.freeze([
  'adapter_id',
  'adapter_version',
  'agent_id',
  'agent_kind',
  'authority_generation',
  'control_sequence',
  'device_id',
  'expires_at',
  'grant_id',
  'issuer',
  'key_id',
  'max_signatures',
  'not_before',
  'organization_id',
  'process_binding_policy_id',
  'scope',
  'version',
  'worktree_binding_sha256'
]);
const SCOPE_REQUIRED_KEYS = Object.freeze(['branches', 'operations', 'remotes', 'repositories']);
const SCOPE_OPTIONAL_KEYS = Object.freeze(['tags']);
const PATTERN_SET_KEYS = Object.freeze(['allow', 'deny']);
const REQUEST_BINDING_KEYS = Object.freeze([
  'organization_id',
  'device_id',
  'agent_id',
  'agent_kind',
  'requested_ttl_seconds',
  'candidate_sha256',
  'source_commit',
  'artifact_sha256',
  'release_trust_sha256',
  'candidate_checkpoint_sha256',
  'expires_at',
  'batch_id',
  'team_id'
]);
const MANIFEST_CANDIDATE_KEYS = Object.freeze([
  'agent_id',
  'agent_kind',
  'artifact_sha256',
  'batch_id',
  'candidate_checkpoint_sha256',
  'candidate_sha256',
  'device_id',
  'expires_at',
  'organization_id',
  'release_trust_sha256',
  'requested_ttl_seconds',
  'source_commit',
  'team_id'
]);
const MANIFEST_STEP_KEYS = Object.freeze([
  'grant_hash',
  'grant_id',
  'index',
  'kind',
  'phase',
  'run_binding',
  'scenario',
  'statement_hash'
]);
const SIGNED_MANIFEST_STEP_KEYS = Object.freeze([...MANIFEST_STEP_KEYS, 'grant']);
const MANIFEST_STATEMENT_KEYS = Object.freeze([
  'agent_id',
  'agent_kind',
  'artifact_sha256',
  'batch_id',
  'candidate_checkpoint_sha256',
  'candidate_sha256',
  'device_id',
  'expires_at',
  'issued_at',
  'key_id',
  'organization_id',
  'release_trust_sha256',
  'requested_ttl_seconds',
  'source_commit',
  'steps',
  'team_id',
  'type',
  'issuer',
  'version'
]);

const fail = (message) => { throw new Error(message); };
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const same = (left, right) => left === right;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

const exactKeys = (value, expected, label) => {
  if (!isObject(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) fail(`${label} contains an accessor`);
  }
};

const keysWithOptional = (value, required, optional, label) => {
  if (!isObject(value)) fail(`${label} is invalid`);
  const allowed = new Set([...required, ...optional]);
  const actual = Object.keys(value);
  if (actual.some((key) => !allowed.has(key)) || required.some((key) => !hasOwn(value, key))) fail(`${label} is not closed`);
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) fail(`${label} contains an accessor`);
  }
};

const sorted = (value) => Array.isArray(value)
  ? value.map(sorted)
  : isObject(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]))
    : value;

const canonicalDocument = (value) => Buffer.from(`${JSON.stringify(sorted(value), null, 2)}\n`, 'utf8');

const parseStrictJson = (bytes, label, maximum) => {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > maximum) fail(`${label} is invalid`);
  let source;
  try { source = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(`${label} is invalid`); }
  if (source.startsWith('\uFEFF')) fail(`${label} contains a BOM`);
  const cursor = { index: 0 };
  const whitespace = () => { while (/^[ \t\n\r]$/u.test(source[cursor.index] ?? '')) cursor.index += 1; };
  const string = () => {
    const start = cursor.index;
    if (source[cursor.index] !== '"') fail(`${label} contains invalid JSON`);
    cursor.index += 1;
    while (cursor.index < source.length) {
      const code = source.charCodeAt(cursor.index);
      if (code < 0x20) fail(`${label} contains invalid JSON`);
      if (source[cursor.index] === '\\') { cursor.index += 2; continue; }
      if (source[cursor.index] === '"') {
        cursor.index += 1;
        try { return JSON.parse(source.slice(start, cursor.index)); } catch { fail(`${label} contains invalid JSON`); }
      }
      cursor.index += 1;
    }
    fail(`${label} contains invalid JSON`);
  };
  const value = (depth) => {
    if (depth > 32) fail(`${label} is too deeply nested`);
    whitespace();
    const character = source[cursor.index];
    if (character === '"') return string();
    if (character === '{') {
      cursor.index += 1; const result = {}; const seen = new Set(); whitespace();
      if (source[cursor.index] === '}') { cursor.index += 1; return result; }
      for (;;) {
        whitespace(); const key = string();
        if (seen.has(key)) fail(`${label} contains duplicate JSON fields`);
        seen.add(key); whitespace();
        if (source[cursor.index] !== ':') fail(`${label} contains invalid JSON`);
        cursor.index += 1; result[key] = value(depth + 1); whitespace();
        if (source[cursor.index] === '}') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') fail(`${label} contains invalid JSON`);
        cursor.index += 1;
      }
    }
    if (character === '[') {
      cursor.index += 1; const result = []; whitespace();
      if (source[cursor.index] === ']') { cursor.index += 1; return result; }
      for (;;) {
        result.push(value(depth + 1)); whitespace();
        if (source[cursor.index] === ']') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') fail(`${label} contains invalid JSON`);
        cursor.index += 1;
      }
    }
    const start = cursor.index;
    while (cursor.index < source.length && !/[ \t\n\r,\]}]/u.test(source[cursor.index])) cursor.index += 1;
    if (start === cursor.index) fail(`${label} contains invalid JSON`);
    const token = source.slice(start, cursor.index);
    if (!['true', 'false', 'null'].includes(token) && !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/u.test(token)) fail(`${label} contains invalid JSON`);
    try { return JSON.parse(token); } catch { fail(`${label} contains invalid JSON`); }
  };
  const parsed = value(0); whitespace();
  if (cursor.index !== source.length) fail(`${label} contains trailing data`);
  return parsed;
};

const parseResponseValue = (value) => {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    const parsed = parseStrictJson(bytes, 'qualification relay response', QUALIFICATION_RELAY_MAX_RESPONSE_BYTES);
    if (!bytes.equals(canonicalDocument(parsed))) fail('qualification relay response is not canonical');
    return parsed;
  }
  return value;
};

const uuid = (value, label) => { if (typeof value !== 'string' || !UUID.test(value)) fail(`${label} is invalid`); return value; };
const digest = (value, label) => { if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${label} is invalid`); return value; };
const commit = (value, label) => { if (typeof value !== 'string' || !COMMIT.test(value)) fail(`${label} is invalid`); return value; };
const teamId = (value, label) => { if (typeof value !== 'string' || !/^[A-Z0-9]{10}$/u.test(value)) fail(`${label} is invalid`); return value; };
const cloudAgentKind = (value, label) => { if (!['claude-code', 'cursor'].includes(value)) fail(`${label} is invalid`); return value; };
const ttl = (value, label) => {
  if (!Number.isSafeInteger(value) || value < QUALIFICATION_ACTIVATION_MIN_TTL_SECONDS || value > QUALIFICATION_RELAY_MAX_TTL_SECONDS) fail(`${label} is invalid`);
  return value;
};
const timestamp = (value, label) => {
  if (typeof value !== 'string' || !TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) fail(`${label} is invalid`);
  return value;
};
const positiveInteger = (value, label) => { if (!Number.isSafeInteger(value) || value < 1) fail(`${label} is invalid`); return value; };
const safeIdentifier = (value, label) => { if (typeof value !== 'string' || !SAFE_IDENTIFIER.test(value)) fail(`${label} is invalid`); return value; };

const validateStringArray = (value, label, { min = 0, max = 64, pattern } = {}) => {
  if (!Array.isArray(value) || value.length < min || value.length > max) fail(`${label} is invalid`);
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0 || item.length > 4096 || (pattern && !pattern.test(item)) || seen.has(item)) fail(`${label} is invalid`);
    seen.add(item);
  }
  return value;
};

const validateScope = (scope) => {
  keysWithOptional(scope, SCOPE_REQUIRED_KEYS, SCOPE_OPTIONAL_KEYS, 'Grant scope');
  validateStringArray(scope.operations, 'Grant scope operations', { min: 1, max: 64 });
  if (scope.operations.some((operation) => operation !== 'git.commit.sign')) fail('Grant scope operation is invalid');
  validateStringArray(scope.repositories, 'Grant scope repositories', { min: 1, max: 64, pattern: /^\//u });
  for (const key of ['branches', 'remotes', ...(hasOwn(scope, 'tags') ? ['tags'] : [])]) {
    exactKeys(scope[key], PATTERN_SET_KEYS, `Grant scope ${key}`);
    validateStringArray(scope[key].allow, `Grant scope ${key}.allow`, { max: 64 });
    validateStringArray(scope[key].deny, `Grant scope ${key}.deny`, { max: 64 });
  }
  return scope;
};

const normalizeGrant = (value, expected) => {
  exactKeys(value, GRANT_KEYS, 'Cloud Grant');
  if (value.version !== 1 || value.type !== 'agentpass.agent-session-grant' || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail('Cloud Grant envelope is invalid');
  exactKeys(value.statement, STATEMENT_KEYS, 'Cloud Grant statement');
  const statement = value.statement;
  if (statement.version !== 1 || statement.issuer !== 'agentpass-cloud') fail('Cloud Grant statement is invalid');
  uuid(statement.grant_id, 'Cloud Grant grant_id');
  uuid(statement.organization_id, 'Cloud Grant organization_id');
  uuid(statement.device_id, 'Cloud Grant device_id');
  uuid(statement.agent_id, 'Cloud Grant agent_id');
  cloudAgentKind(statement.agent_kind, 'Cloud Grant agent_kind');
  uuid(statement.adapter_id, 'Cloud Grant adapter_id');
  if (typeof statement.adapter_version !== 'string' || !/^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(statement.adapter_version)) fail('Cloud Grant adapter_version is invalid');
  digest(statement.worktree_binding_sha256, 'Cloud Grant worktree binding');
  safeIdentifier(statement.process_binding_policy_id, 'Cloud Grant process binding policy');
  validateScope(statement.scope);
  if (statement.max_signatures !== 1) fail('Cloud Grant max_signatures is invalid');
  timestamp(statement.not_before, 'Cloud Grant not_before');
  timestamp(statement.expires_at, 'Cloud Grant expires_at');
  if (Date.parse(statement.not_before) >= Date.parse(statement.expires_at)) fail('Cloud Grant expiry order is invalid');
  positiveInteger(statement.control_sequence, 'Cloud Grant control_sequence');
  positiveInteger(statement.authority_generation, 'Cloud Grant authority_generation');
  safeIdentifier(statement.key_id, 'Cloud Grant key_id');
  if (statement.organization_id !== expected.organization_id || statement.device_id !== expected.device_id || statement.agent_id !== expected.agent_id || statement.agent_kind !== expected.agent_kind || statement.expires_at !== expected.expires_at) fail('Cloud Grant statement binding does not match the claim');
  if (value.statement_hash !== sha256(Buffer.from(canonicalJson(statement), 'utf8'))) fail('Cloud Grant statement hash is invalid');
  return Object.freeze(value);
};

const normalizeRequest = (value) => {
  exactKeys(value, REQUEST_KEYS, 'qualification relay request');
  if (value.schema_version !== QUALIFICATION_RELAY_SCHEMA_VERSION || value.kind !== QUALIFICATION_RELAY_REQUEST_KIND) fail('qualification relay request identity is invalid');
  uuid(value.request_id, 'qualification relay request_id');
  uuid(value.organization_id, 'qualification relay organization_id');
  uuid(value.device_id, 'qualification relay device_id');
  uuid(value.agent_id, 'qualification relay agent_id');
  uuid(value.batch_id, 'qualification relay batch_id');
  cloudAgentKind(value.agent_kind, 'qualification relay agent_kind');
  ttl(value.requested_ttl_seconds, 'qualification relay requested_ttl_seconds');
  digest(value.candidate_sha256, 'qualification relay candidate_sha256');
  commit(value.source_commit, 'qualification relay source_commit');
  digest(value.artifact_sha256, 'qualification relay artifact_sha256');
  digest(value.release_trust_sha256, 'qualification relay release_trust_sha256');
  digest(value.candidate_checkpoint_sha256, 'qualification relay candidate_checkpoint_sha256');
  timestamp(value.expires_at, 'qualification relay expires_at');
  teamId(value.team_id, 'qualification relay team_id');
  return Object.freeze(Object.fromEntries(REQUEST_KEYS.map((key) => [key, value[key]])));
};

export const canonicalQualificationRelayRequest = (value) => canonicalDocument(normalizeRequest(value));

export const parseQualificationRelayRequest = (bytes) => {
  const value = parseStrictJson(bytes, 'qualification relay request', QUALIFICATION_RELAY_MAX_REQUEST_BYTES);
  const normalized = normalizeRequest(value);
  if (!Buffer.from(bytes).equals(canonicalQualificationRelayRequest(normalized))) fail('qualification relay request is not canonical');
  return normalized;
};

const normalizeVerifiedManifest = (value, batch, request) => {
  let candidate;
  let manifestSteps;
  if (isObject(value) && value.verified === true) {
    exactKeys(value, ['candidate', 'steps', 'verified'], 'qualification batch manifest verification result');
    candidate = value.candidate;
    manifestSteps = value.steps;
  } else if (isObject(value) && hasOwn(value, 'statement')) {
    exactKeys(value, ['signature', 'statement', 'statement_hash', 'type', 'version'], 'verified qualification batch manifest');
    if (value.version !== 1 || value.type !== 'agentpass.qualification-grant-batch-manifest' || typeof value.signature !== 'string' || !MANIFEST_SIGNATURE.test(value.signature) || !DIGEST.test(value.statement_hash)) fail('verified qualification batch manifest envelope is invalid');
    exactKeys(value.statement, MANIFEST_STATEMENT_KEYS, 'verified qualification batch manifest statement');
    if (value.statement.version !== 1 || value.statement.type !== 'agentpass.qualification-grant-batch-manifest' || value.statement.issuer !== 'agentpass-cloud') fail('verified qualification batch manifest statement is invalid');
    candidate = Object.fromEntries(MANIFEST_CANDIDATE_KEYS.map((key) => [key, value.statement[key]]));
    manifestSteps = value.statement.steps;
  } else {
    fail('qualification batch manifest was not verified');
  }
  exactKeys(candidate, MANIFEST_CANDIDATE_KEYS, 'qualification batch manifest candidate bindings');
  for (const key of MANIFEST_CANDIDATE_KEYS) {
    if (candidate[key] !== request[key] || candidate[key] !== batch[key]) fail(`qualification batch manifest ${key} binding is invalid`);
  }
  if (!Array.isArray(manifestSteps) || manifestSteps.length !== QUALIFICATION_SUITE_STEPS.length) fail('qualification batch manifest step bindings are invalid');
  const seenGrantIds = new Set();
  const seenGrantHashes = new Set();
  const seenStatementHashes = new Set();
  const seenRunBindings = new Set();
  const stepKeys = manifestSteps.some((step) => isObject(step) && hasOwn(step, 'grant')) ? SIGNED_MANIFEST_STEP_KEYS : MANIFEST_STEP_KEYS;
  const steps = manifestSteps.map((step, index) => {
    exactKeys(step, stepKeys, `qualification batch manifest step ${index}`);
    const expected = QUALIFICATION_SUITE_STEPS[index];
    if (step.index !== index || step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase) fail('qualification batch manifest steps are missing, duplicated, or reordered');
    uuid(step.grant_id, 'qualification batch manifest grant_id');
    digest(step.grant_hash, 'qualification batch manifest grant_hash');
    digest(step.statement_hash, 'qualification batch manifest statement_hash');
    if (typeof step.run_binding !== 'string' || !RUN_BINDING.test(step.run_binding) || seenRunBindings.has(step.run_binding)) fail('qualification batch manifest run binding is invalid or reused');
    if (seenGrantIds.has(step.grant_id) || seenGrantHashes.has(step.grant_hash) || seenStatementHashes.has(step.statement_hash)) fail('qualification batch manifest Grant binding is reused');
    seenGrantIds.add(step.grant_id); seenGrantHashes.add(step.grant_hash); seenStatementHashes.add(step.statement_hash); seenRunBindings.add(step.run_binding);
    return Object.freeze({ index, kind: step.kind, scenario: step.scenario, phase: step.phase, run_binding: step.run_binding, grant_id: step.grant_id, grant_hash: step.grant_hash, statement_hash: step.statement_hash, ...(hasOwn(step, 'grant') ? { grant: step.grant } : {}) });
  });
  return Object.freeze({ candidate: Object.freeze(Object.fromEntries(MANIFEST_CANDIDATE_KEYS.map((key) => [key, candidate[key]]))), steps: Object.freeze(steps) });
};

const verifyBatchManifest = (rawBatch, request, verifier) => {
  if (typeof verifier !== 'function') fail('qualification batch manifest verifier is required');
  if (!isObject(rawBatch) || !hasOwn(rawBatch, 'manifest')) fail('qualification batch manifest is required');
  let verified;
  try { verified = verifier(rawBatch.manifest, Object.freeze({ request, batch: rawBatch })); } catch { fail('qualification batch manifest verification failed'); }
  if (verified && typeof verified.then === 'function') fail('qualification batch manifest verifier must be synchronous');
  return normalizeVerifiedManifest(verified, rawBatch, request);
};

export const normalizeQualificationBatchManifestVerification = normalizeVerifiedManifest;

const normalizeBatchResponse = (response, request, { verifyBatchManifest: manifestVerifier } = {}) => {
  const value = parseResponseValue(response);
  exactKeys(value, ENVELOPE_KEYS, 'qualification relay response envelope');
  uuid(value.request_id, 'qualification relay response request_id');
  if (!isObject(value.batch)) fail('qualification relay batch is invalid');
  const manifest = verifyBatchManifest(value.batch, request, manifestVerifier);
  exactKeys(value.batch, BATCH_KEYS, 'qualification relay batch');
  const batch = value.batch;
  if (batch.schema_version !== QUALIFICATION_RELAY_SCHEMA_VERSION || batch.kind !== QUALIFICATION_RELAY_BATCH_KIND) fail('qualification relay batch identity is invalid');
  uuid(batch.batch_id, 'qualification relay batch_id');
  teamId(batch.team_id, 'qualification relay batch team_id');
  for (const key of REQUEST_BINDING_KEYS) {
    if (!same(batch[key], request[key])) fail(`qualification relay batch ${key} binding is invalid`);
  }
  if (!Array.isArray(batch.steps) || batch.steps.length !== QUALIFICATION_SUITE_STEPS.length) fail('qualification relay batch step inventory is invalid');
  const runBindings = new Set();
  const grantIds = new Set();
  const proofDigests = new Set();
  const steps = batch.steps.map((step, index) => {
    exactKeys(step, STEP_KEYS, `qualification relay batch step ${index}`);
    const expected = QUALIFICATION_SUITE_STEPS[index];
    if (step.index !== index || step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase) fail('qualification relay batch steps are missing, duplicated, or reordered');
    if (typeof step.run_binding !== 'string' || !RUN_BINDING.test(step.run_binding) || Buffer.byteLength(step.run_binding, 'utf8') > QUALIFICATION_RELAY_MAX_RUN_BINDING_BYTES || runBindings.has(step.run_binding)) fail('qualification relay run binding is invalid or reused');
    runBindings.add(step.run_binding);
    const grant = normalizeGrant(step.grant, batch);
    if (grantIds.has(grant.statement.grant_id)) fail('qualification relay Grant is reused');
    grantIds.add(grant.statement.grant_id);
    const proofDigest = sha256(Buffer.from(canonicalJson(grant), 'utf8'));
    if (proofDigests.has(proofDigest)) fail('qualification relay Grant proof is reused');
    proofDigests.add(proofDigest);
    const manifestStep = manifest.steps[index];
    if (manifestStep.grant_id !== grant.statement.grant_id || manifestStep.grant_hash !== proofDigest || manifestStep.statement_hash !== grant.statement_hash || manifestStep.run_binding !== step.run_binding) fail('qualification batch manifest does not bind the exact Grant');
    return Object.freeze({ index, kind: expected.kind, scenario: expected.scenario, phase: expected.phase, run_binding: step.run_binding, grant });
  });
  return Object.freeze({
    batch: Object.freeze({
      schema_version: batch.schema_version,
      kind: batch.kind,
      batch_id: batch.batch_id,
      organization_id: batch.organization_id,
      device_id: batch.device_id,
      agent_id: batch.agent_id,
      agent_kind: batch.agent_kind,
      requested_ttl_seconds: batch.requested_ttl_seconds,
      candidate_sha256: batch.candidate_sha256,
      source_commit: batch.source_commit,
      artifact_sha256: batch.artifact_sha256,
      team_id: batch.team_id,
      release_trust_sha256: batch.release_trust_sha256,
      candidate_checkpoint_sha256: batch.candidate_checkpoint_sha256,
      expires_at: batch.expires_at,
      steps: Object.freeze(steps)
    }),
    request_id: value.request_id
  });
};

export const normalizeQualificationDeviceRelayResponse = normalizeBatchResponse;
export const parseQualificationDeviceRelayResponse = (bytes, request, options = {}) => normalizeBatchResponse(bytes, request, options);

const activationAgentKind = (value) => value === 'claude-code' ? 'claude_code' : 'cursor';

export const qualificationRelayResponseToSuiteInput = (response, request, options = {}) => {
  const normalized = normalizeBatchResponse(response, request, options);
  const expiry = Math.floor(Date.parse(normalized.batch.expires_at) / 1000);
  if (!Number.isSafeInteger(expiry) || expiry <= 0) fail('qualification relay expiry cannot be represented');
  const suite = {
    schema_version: 1,
    kind: QUALIFICATION_SUITE_INPUT_KIND,
    steps: normalized.batch.steps.map((step, index) => ({
      kind: step.kind,
      scenario: step.scenario,
      phase: step.phase,
      input: {
        schema_version: FIXED_INPUT_SCHEMA_VERSION,
        kind: FIXED_INPUT_KIND,
        provision: {
          scenario: QUALIFICATION_SUITE_STEPS[index].kind === 'unarmed-control' ? QUALIFICATION_SUITE_STEPS[1].scenario : step.scenario,
          expires_at_epoch_seconds: expiry,
          run_binding: step.run_binding
        },
        activation: {
          schema_version: 1,
          agent_id: normalized.batch.agent_id,
          agent_kind: activationAgentKind(normalized.batch.agent_kind),
          requested_ttl_seconds: normalized.batch.requested_ttl_seconds,
          proof: canonicalJson(step.grant)
        }
      }
    }))
  };
  const bytes = canonicalQualificationSuiteInput(suite);
  return Object.freeze({
    request_id: normalized.request_id,
    batch_id: normalized.batch.batch_id,
    suite: Object.freeze(JSON.parse(bytes.toString('utf8'))),
    bytes,
    document_sha256: sha256(bytes),
    document_bytes: bytes.length
  });
};

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) fail(`${label} path is invalid`);
  return value;
};

const identity = (stat) => Object.freeze({
  dev: String(stat.dev), ino: String(stat.ino), mode: String(stat.mode), nlink: String(stat.nlink), size: String(stat.size),
  mtime_ns: String(stat.mtimeNs), ctime_ns: String(stat.ctimeNs), uid: String(stat.uid), gid: String(stat.gid)
});
const sameIdentity = (left, right) => Object.keys(left).every((key) => left[key] === right[key]);
const sameFileObject = (left, right) => ['dev', 'ino', 'mode', 'size', 'uid', 'gid'].every((key) => left[key] === right[key]);
const objectFromIdentity = (value) => Object.fromEntries(['dev', 'ino', 'mode', 'size', 'uid', 'gid'].map((key) => [key, BigInt(value[key])]));

const validateParent = (directory, { fileSystem, expectedUid, production }) => {
  const root = absolutePath(directory, 'qualification relay root');
  let current = root;
  for (;;) {
    let stat;
    try { stat = fileSystem.lstatSync(current, { bigint: true }); } catch { fail('qualification relay root is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o022n) !== 0n) fail('qualification relay root is unsafe');
    if (current === root && (stat.mode & 0o7777n) !== BigInt(DIRECTORY_MODE)) fail('qualification relay root mode is unsafe');
    if (!production || current === '/') break;
    current = resolve(current, '..');
  }
  return root;
};

const syncDirectory = (directory, fileSystem) => {
  if (!Number.isInteger(NOFOLLOW)) fail('qualification relay requires O_NOFOLLOW');
  let descriptor;
  try {
    descriptor = fileSystem.openSync(directory, fileSystem.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
    fileSystem.fsyncSync(descriptor);
  } catch { fail('qualification relay directory sync failed'); }
  finally { if (descriptor !== undefined) { try { fileSystem.closeSync(descriptor); } catch { fail('qualification relay directory sync failed'); } } }
};

const readStableRequest = ({ requestPath, fileSystem, expectedUid, production }) => {
  let descriptor;
  try { descriptor = fileSystem.openSync(requestPath, fileSystem.constants.O_RDONLY | NOFOLLOW); } catch { fail('qualification relay claim request is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== BigInt(FILE_MODE) || before.size <= 0n || before.size > BigInt(QUALIFICATION_RELAY_MAX_REQUEST_BYTES)) fail('qualification relay claim request is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count <= 0) fail('qualification relay claim request changed while reading');
      offset += count;
    }
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = fileSystem.lstatSync(requestPath, { bigint: true });
    const beforeIdentity = identity(before);
    if (!sameIdentity(beforeIdentity, identity(after)) || !sameIdentity(beforeIdentity, identity(current))) fail('qualification relay claim request changed while reading');
    const request = parseQualificationRelayRequest(bytes);
    return Object.freeze({ request, bytes, identity: beforeIdentity });
  } finally { fileSystem.closeSync(descriptor); }
};

const consumeRequest = ({ requestPath, expectedIdentity, fileSystem, root }) => {
  const current = fileSystem.lstatSync(requestPath, { bigint: true });
  if (!sameIdentity(expectedIdentity, identity(current))) fail('qualification relay claim request changed before consumption');
  try { fileSystem.unlinkSync(requestPath); } catch { fail('qualification relay claim request consumption failed'); }
  syncDirectory(root, fileSystem);
};

const ensureAbsent = (filePath, fileSystem, label) => {
  try { fileSystem.lstatSync(filePath, { bigint: true }); fail(`${label} already exists; recovery is required`); }
  catch (error) { if (error?.message?.includes('already exists')) throw error; if (error?.code !== 'ENOENT') throw error; }
};

const assertFile = (stat, expectedUid, expectedSize = null, links = 1n) => {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || stat.nlink !== links || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || (expectedSize !== null && stat.size !== BigInt(expectedSize))) fail('qualification relay output file is unsafe');
};

const writeAll = (descriptor, bytes, fileSystem) => {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('qualification relay output write failed');
    offset += count;
  }
};

const publishSuite = ({ bytes, inboxPath, root, fileSystem, expectedUid, processId, randomBytes }) => {
  ensureAbsent(inboxPath, fileSystem, 'qualification relay inbox');
  let random;
  try { random = randomBytes(16); } catch { fail('qualification relay staging name generation failed'); }
  if (!(random instanceof Uint8Array) || random.length !== 16) fail('qualification relay staging name generation failed');
  const staging = join(root, `.qualification-relay-input.${processId}.${Buffer.from(random).toString('hex')}.tmp`);
  let descriptor;
  let linked = false;
  let published = false;
  let boundIdentity;
  try {
    descriptor = fileSystem.openSync(staging, fileSystem.constants.O_WRONLY | fileSystem.constants.O_CREAT | fileSystem.constants.O_EXCL | NOFOLLOW, FILE_MODE);
    const opened = fileSystem.fstatSync(descriptor, { bigint: true }); assertFile(opened, expectedUid, 0n, 1n);
    writeAll(descriptor, bytes, fileSystem); fileSystem.fchmodSync(descriptor, FILE_MODE);
    const staged = fileSystem.fstatSync(descriptor, { bigint: true }); assertFile(staged, expectedUid, bytes.length, 1n); boundIdentity = identity(staged);
    fileSystem.fsyncSync(descriptor); fileSystem.closeSync(descriptor); descriptor = undefined;
    const beforeLink = fileSystem.lstatSync(staging, { bigint: true }); assertFile(beforeLink, expectedUid, bytes.length, 1n);
    if (!sameFileObject(beforeLink, objectFromIdentity(boundIdentity))) fail('qualification relay staging file changed');
    fileSystem.linkSync(staging, inboxPath); linked = true; published = true;
    const installed = fileSystem.lstatSync(inboxPath, { bigint: true }); assertFile(installed, expectedUid, bytes.length, 2n);
    if (!sameFileObject(beforeLink, installed)) fail('qualification relay published file changed');
    const installedBytes = fileSystem.readFileSync(inboxPath);
    if (!Buffer.from(installedBytes).equals(bytes)) fail('qualification relay published bytes changed');
    fileSystem.unlinkSync(staging); linked = false;
    const final = fileSystem.lstatSync(inboxPath, { bigint: true }); assertFile(final, expectedUid, bytes.length, 1n);
    if (!sameFileObject(beforeLink, final)) fail('qualification relay published file changed');
    syncDirectory(root, fileSystem);
  } catch {
    if (descriptor !== undefined) { try { fileSystem.closeSync(descriptor); } catch {} }
    try {
      const current = fileSystem.lstatSync(staging, { bigint: true });
      if (current.isFile() && !current.isSymbolicLink() && current.uid === BigInt(expectedUid) && (current.nlink === 1n || current.nlink === 2n) && (current.mode & 0o7777n) === BigInt(FILE_MODE) && (!boundIdentity || sameFileObject(current, objectFromIdentity(boundIdentity)))) fileSystem.unlinkSync(staging);
    } catch {}
    if (linked || published) {
      try {
        const current = fileSystem.lstatSync(inboxPath, { bigint: true });
        if (current.isFile() && !current.isSymbolicLink() && current.uid === BigInt(expectedUid) && (current.nlink === 1n || current.nlink === 2n) && (current.mode & 0o7777n) === BigInt(FILE_MODE) && (!boundIdentity || sameFileObject(current, objectFromIdentity(boundIdentity)))) fileSystem.unlinkSync(inboxPath);
      } catch {}
    }
    try { syncDirectory(root, fileSystem); } catch {}
    fail('qualification relay publication failed');
  }
  return Object.freeze({ ok: true, action: 'published', document_sha256: sha256(bytes), document_bytes: bytes.length });
};

const productionGuard = ({ production, platform, uid, expectedUid, requestPath, inboxPath, fileSystem, randomBytes, processId }) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || requestPath !== QUALIFICATION_RELAY_REQUEST_PATH || inboxPath !== QUALIFICATION_RELAY_INBOX_PATH || fileSystem !== fs || randomBytes !== crypto.randomBytes || processId !== process.pid)) fail('qualification relay requires the fixed root production boundary');
  if (!production && uid !== expectedUid) fail('qualification relay requires the expected owner');
};

const resolveOptions = (options = {}) => {
  const fileSystem = options.fileSystem ?? fs;
  const production = options.production ?? true;
  const expectedUid = options.expectedUid ?? 0;
  const uid = options.uid ?? process.getuid?.();
  const requestPath = options.requestPath ?? QUALIFICATION_RELAY_REQUEST_PATH;
  const inboxPath = options.inboxPath ?? QUALIFICATION_RELAY_INBOX_PATH;
  const root = dirname(requestPath);
  if (!Number.isInteger(expectedUid) || expectedUid < 0 || !Number.isInteger(uid) || uid < 0) fail('qualification relay owner is invalid');
  absolutePath(requestPath, 'qualification relay request'); absolutePath(inboxPath, 'qualification relay inbox');
  if (root !== dirname(inboxPath) || root !== QUALIFICATION_RELAY_ROOT_DIRECTORY && production) fail('qualification relay paths are not fixed');
  const processId = options.processId ?? process.pid;
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  if (!Number.isInteger(processId) || processId < 0 || typeof randomBytes !== 'function') fail('qualification relay process options are invalid');
  const resolved = { ...options, fileSystem, production, expectedUid, uid, requestPath, inboxPath, root, processId, randomBytes, platform: options.platform ?? process.platform };
  productionGuard(resolved);
  validateParent(root, resolved);
  return resolved;
};

const fixedPackagedDeviceClient = Object.freeze({
  claim: async () => { fail('fixed packaged Device API client is unavailable'); }
});
export const fixedQualificationDeviceClient = fixedPackagedDeviceClient;

const resolveDeviceClient = (options) => {
  if (options.production) {
    if (options.deviceClient !== undefined) fail('qualification relay refuses a dynamic production Device API client');
    return fixedPackagedDeviceClient;
  }
  const client = options.deviceClient;
  if (typeof client === 'function') return Object.freeze({ claim: client });
  if (!client || typeof client.claim !== 'function') fail('qualification relay Device API client is invalid');
  return client;
};

export const claimQualificationDeviceRelay = async (options = {}) => {
  const resolved = resolveOptions(options);
  if (typeof resolved.verifyBatchManifest !== 'function') fail('qualification batch manifest verifier is required');
  const client = resolveDeviceClient(resolved);
  ensureAbsent(resolved.inboxPath, resolved.fileSystem, 'qualification relay inbox');
  const claimed = readStableRequest(resolved);
  consumeRequest({ requestPath: resolved.requestPath, expectedIdentity: claimed.identity, fileSystem: resolved.fileSystem, root: resolved.root });
  let response;
  try {
    const deviceRequest = Object.freeze({
      schema_version: 1,
      candidate_sha256: claimed.request.candidate_sha256,
      artifact_sha256: claimed.request.artifact_sha256,
      source_commit: claimed.request.source_commit,
      team_id: claimed.request.team_id,
      release_trust_sha256: claimed.request.release_trust_sha256,
      candidate_checkpoint_sha256: claimed.request.candidate_checkpoint_sha256
    });
    response = await client.claim({
      batch_id: claimed.request.batch_id,
      device_id: claimed.request.device_id,
      organization_id: claimed.request.organization_id,
      local_request_id: claimed.request.request_id,
      request: deviceRequest
    });
    const suite = qualificationRelayResponseToSuiteInput(response, claimed.request, { verifyBatchManifest: resolved.verifyBatchManifest });
    return publishSuite({ bytes: suite.bytes, inboxPath: resolved.inboxPath, root: resolved.root, fileSystem: resolved.fileSystem, expectedUid: resolved.expectedUid, processId: resolved.processId, randomBytes: resolved.randomBytes });
  } catch {
    try {
      const current = resolved.fileSystem.lstatSync(resolved.inboxPath, { bigint: true });
      if (current.isFile() && !current.isSymbolicLink() && current.uid === BigInt(resolved.expectedUid) && current.nlink === 1n && (current.mode & 0o7777n) === BigInt(FILE_MODE)) resolved.fileSystem.unlinkSync(resolved.inboxPath);
      syncDirectory(resolved.root, resolved.fileSystem);
    } catch {}
    fail('qualification relay claim failed');
  }
};

const removeSafeFile = (filePath, { fileSystem, expectedUid, label }) => {
  let stat;
  try { stat = fileSystem.lstatSync(filePath, { bigint: true }); } catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
  assertFile(stat, expectedUid, null, 1n);
  fileSystem.unlinkSync(filePath);
  return true;
};

export const recoverQualificationDeviceRelay = (options = {}) => {
  const resolved = resolveOptions(options);
  const prove = resolved.proveNoActiveRelay ?? (resolved.production ? proveNoQualificationProcesses : undefined);
  if (typeof prove !== 'function' || prove() !== true) fail('qualification relay recovery refused an active qualification process');
  const removed = [];
  for (const [filePath, label] of [[resolved.requestPath, 'qualification relay claim request'], [resolved.inboxPath, 'qualification relay inbox']]) {
    if (removeSafeFile(filePath, { fileSystem: resolved.fileSystem, expectedUid: resolved.expectedUid, label })) removed.push(label);
  }
  for (const entry of resolved.fileSystem.readdirSync(resolved.root, { withFileTypes: true })) {
    if (!STAGING_FILE.test(entry.name)) continue;
    if (!entry.isFile() || entry.isSymbolicLink()) fail('qualification relay staging inventory is unsafe');
    if (removeSafeFile(join(resolved.root, entry.name), { fileSystem: resolved.fileSystem, expectedUid: resolved.expectedUid, label: 'qualification relay staging file' })) removed.push('qualification relay staging file');
  }
  syncDirectory(resolved.root, resolved.fileSystem);
  return Object.freeze({ ok: true, action: removed.length === 0 ? 'already-recovered' : 'recovered', removed_count: removed.length });
};

export const parseQualificationDeviceRelayCLI = (args) => {
  if (!Array.isArray(args) || args.length !== 1 || !['claim', 'recover'].includes(args[0])) fail('usage: qualification-device-relay.mjs claim | recover');
  return Object.freeze({ operation: args[0] });
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const operation = parseQualificationDeviceRelayCLI(process.argv.slice(2)).operation;
    const result = operation === 'claim' ? await claimQualificationDeviceRelay() : recoverQualificationDeviceRelay();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const message = error?.message === 'usage: qualification-device-relay.mjs claim | recover' ? error.message : 'qualification device relay refused';
    process.stderr.write(`${message}\n`);
    process.exitCode = 2;
  }
}
