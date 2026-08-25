import crypto from 'node:crypto';

export const QUALIFICATION_ACTIVATION_SCHEMA_VERSION = 1;
// These limits are part of the XPC handoff contract. Keep them aligned with
// AgentPassAgentSessionRequest.maximumProofBytes and the Swift host's
// maximumActivationDocumentBytes respectively.
export const QUALIFICATION_ACTIVATION_MAX_BYTES = 16 * 1024;
export const QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES = 4 * 1024;
export const QUALIFICATION_ACTIVATION_MAX_DEPTH = 32;
export const QUALIFICATION_ACTIVATION_MAX_TTL_SECONDS = 28_800;
export const QUALIFICATION_ACTIVATION_MIN_TTL_SECONDS = 60;
export const QUALIFICATION_ACTIVATION_FIELDS = Object.freeze([
  'schema_version',
  'agent_id',
  'agent_kind',
  'requested_ttl_seconds',
  'proof'
]);
export const QUALIFICATION_AGENT_KINDS = Object.freeze(['claude_code', 'cursor']);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WHITESPACE = new Set([' ', '\t', '\n', '\r']);
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

const fail = (message) => { throw new TypeError(message); };

const byteLength = (value) => Buffer.byteLength(value, 'utf8');

const hasUnpairedSurrogate = (value) => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
};

const safeString = (value, label) => {
  if (typeof value !== 'string' || hasUnpairedSurrogate(value)) fail(`${label} is invalid`);
  return value;
};

const exactObject = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail(`${label} has unknown fields`);
  const expected = [...keys].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) fail(`${label} contains an accessor field`);
  }
  return value;
};

const canonicalJson = (value, depth = 0) => {
  if (depth > QUALIFICATION_ACTIVATION_MAX_DEPTH) fail('JSON nesting is too deep');
  if (value === null) return 'null';
  if (typeof value === 'string') {
    safeString(value, 'JSON string');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('JSON number is invalid');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item, depth + 1)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(',')}}`;
  }
  fail('JSON value is invalid');
};

const decodeUtf8 = (bytes, label, maximum) => {
  if (!(bytes instanceof Uint8Array)) fail(`${label} must be bytes`);
  if (bytes.byteLength === 0 || bytes.byteLength > maximum) fail(`${label} exceeds its size limit`);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
};

const parseStrictJson = (bytes, label, maximum) => {
  const source = decodeUtf8(bytes, label, maximum);
  if (source.charCodeAt(0) === 0xfeff) fail(`${label} contains a BOM`);
  const cursor = { index: 0 };

  const skipWhitespace = () => {
    while (cursor.index < source.length && WHITESPACE.has(source[cursor.index])) cursor.index += 1;
  };

  const parseString = () => {
    const start = cursor.index;
    if (source[cursor.index] !== '"') fail(`${label} contains invalid JSON`);
    cursor.index += 1;
    while (cursor.index < source.length) {
      const code = source.charCodeAt(cursor.index);
      if (code < 0x20) fail(`${label} contains invalid JSON`);
      if (source[cursor.index] === '\\') {
        cursor.index += 1;
        if (cursor.index >= source.length) fail(`${label} contains invalid JSON`);
        cursor.index += 1;
        continue;
      }
      if (source[cursor.index] === '"') {
        cursor.index += 1;
        try {
          return safeString(JSON.parse(source.slice(start, cursor.index)), `${label} string`);
        } catch {
          fail(`${label} contains invalid JSON`);
        }
      }
      cursor.index += 1;
    }
    fail(`${label} contains invalid JSON`);
  };

  const parseValue = (depth) => {
    if (depth > QUALIFICATION_ACTIVATION_MAX_DEPTH) fail(`${label} nesting is too deep`);
    skipWhitespace();
    const character = source[cursor.index];
    if (character === '"') return parseString();
    if (character === '{') {
      cursor.index += 1;
      const result = Object.create(null);
      const keys = new Set();
      skipWhitespace();
      if (source[cursor.index] === '}') { cursor.index += 1; return result; }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) fail(`${label} contains duplicate JSON fields`);
        keys.add(key);
        skipWhitespace();
        if (source[cursor.index] !== ':') fail(`${label} contains invalid JSON`);
        cursor.index += 1;
        result[key] = parseValue(depth + 1);
        skipWhitespace();
        if (source[cursor.index] === '}') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') fail(`${label} contains invalid JSON`);
        cursor.index += 1;
      }
    }
    if (character === '[') {
      cursor.index += 1;
      const result = [];
      skipWhitespace();
      if (source[cursor.index] === ']') { cursor.index += 1; return result; }
      while (true) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (source[cursor.index] === ']') { cursor.index += 1; return result; }
        if (source[cursor.index] !== ',') fail(`${label} contains invalid JSON`);
        cursor.index += 1;
      }
    }
    const start = cursor.index;
    while (cursor.index < source.length && !WHITESPACE.has(source[cursor.index]) && !',]}'.includes(source[cursor.index])) cursor.index += 1;
    if (cursor.index === start) fail(`${label} contains invalid JSON`);
    try {
      return JSON.parse(source.slice(start, cursor.index));
    } catch {
      fail(`${label} contains invalid JSON`);
    }
  };

  const value = parseValue(0);
  skipWhitespace();
  if (cursor.index !== source.length) fail(`${label} contains trailing data`);
  return value;
};

const validateProof = (value) => {
  const proof = safeString(value, 'proof');
  const proofBytes = Buffer.from(proof, 'utf8');
  if (proofBytes.length === 0 || proofBytes.length > QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES) fail('proof exceeds its size limit');
  const parsed = parseStrictJson(proofBytes, 'proof', QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) fail('proof must be a JSON object');
  let canonical;
  try { canonical = Buffer.from(canonicalJson(parsed), 'utf8'); } catch { fail('proof is not canonical JSON'); }
  if (!canonical.equals(proofBytes)) fail('proof is not canonical JSON');
  return proof;
};

export const normalizeQualificationActivation = (value) => {
  exactObject(value, QUALIFICATION_ACTIVATION_FIELDS, 'qualification activation');
  if (value.schema_version !== QUALIFICATION_ACTIVATION_SCHEMA_VERSION) fail('schema_version is unsupported');
  const agentId = safeString(value.agent_id, 'agent_id');
  if (!UUID.test(agentId)) fail('agent_id is invalid');
  const agentKind = safeString(value.agent_kind, 'agent_kind');
  if (!QUALIFICATION_AGENT_KINDS.includes(agentKind)) fail('agent_kind is invalid');
  const ttl = value.requested_ttl_seconds;
  if (!Number.isSafeInteger(ttl) || ttl < QUALIFICATION_ACTIVATION_MIN_TTL_SECONDS || ttl > QUALIFICATION_ACTIVATION_MAX_TTL_SECONDS) fail('requested_ttl_seconds is invalid');
  const proof = validateProof(value.proof);
  const normalized = {
    schema_version: QUALIFICATION_ACTIVATION_SCHEMA_VERSION,
    agent_id: agentId,
    agent_kind: agentKind,
    requested_ttl_seconds: ttl,
    proof
  };
  return Object.freeze(normalized);
};

export const canonicalQualificationActivation = (value) => {
  const normalized = normalizeQualificationActivation(value);
  const bytes = Buffer.from(canonicalJson(normalized), 'utf8');
  if (bytes.length > QUALIFICATION_ACTIVATION_MAX_BYTES) fail('qualification activation exceeds its size limit');
  return bytes;
};

export const parseQualificationActivation = (bytes) => {
  const value = parseStrictJson(bytes, 'qualification activation', QUALIFICATION_ACTIVATION_MAX_BYTES);
  const normalized = normalizeQualificationActivation(value);
  const canonical = canonicalQualificationActivation(normalized);
  if (!canonical.equals(Buffer.from(bytes))) fail('qualification activation is not canonical JSON');
  return normalized;
};

export const qualificationActivationPublicMetadata = (value) => {
  const normalized = normalizeQualificationActivation(value);
  const proofBytes = Buffer.from(normalized.proof, 'utf8');
  return Object.freeze({
    schema_version: normalized.schema_version,
    agent_id: normalized.agent_id,
    agent_kind: normalized.agent_kind,
    requested_ttl_seconds: normalized.requested_ttl_seconds,
    proof_sha256: crypto.createHash('sha256').update(proofBytes).digest('hex'),
    proof_bytes: proofBytes.length
  });
};
