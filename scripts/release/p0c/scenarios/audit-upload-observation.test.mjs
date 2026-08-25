import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performAuditUploadObservation } from './audit-upload-observation';

const ids = { organization_id: '11111111-1111-4111-8111-111111111111', device_id: '22222222-2222-4222-8222-222222222222', agent_id: '33333333-3333-4333-8333-333333333333' };
const input = { schema_version: 1, ...ids, ttl_seconds: 60, audit_upload_url: 'https://cloud.example.test/audit/upload', audit_probe_url: 'https://cloud.example.test/audit/probe', repository: '/qualification/repository', branch: 'main', remote: 'origin' };
const machine = { serviceLabel: 'dev.agentpass.native-service', serviceConfigPath: '/tmp/native-service.json', checkpointDirectory: '/tmp', testRepository: input.repository, cloudProbeURL: 'https://cloud.example.test/probe', executables: { native_client: { path: '/private/native-client' } } };
const release = { artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: 'ABCDE12345' };
const canonical = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const hash = (value) => crypto.createHash('sha256').update(canonical(value)).digest('hex');
const outer = (value) => ({ ok: true, error: null, public_key: null, stdout_base64: Buffer.from(JSON.stringify(value)).toString('base64'), version: 1 });
const commandOK = (stdout = '') => ({ ok: true, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });

test('DI-free audit path starts/revokes the same native session and proves stale denial', async () => {
  let revoked = false; let operationId; let records = []; const nativeCalls = []; let counter = 0;
  const appendAudit = (decision) => { const requestId = `${String(++counter).padStart(8, '0')}-0000-4000-8000-000000000000`; const record = { timestamp: `2026-08-14T00:00:0${counter}.000Z`, previous_hash: records.at(-1)?.hash ?? '0'.repeat(64), operation: 'git.commit.sign', decision, request_id: requestId, payload_sha256: String.fromCharCode(97 + counter).repeat(64) }; record.hash = hash(record); records = [...records, record]; return requestId; };
  const runPinned = async (_entry, args) => {
    const action = args.at(-1); nativeCalls.push(action);
    if (action === 'ping') return commandOK();
    if (action === 'session-start') return commandOK(JSON.stringify(outer({ agent_id: ids.agent_id, expires_at: '2099-01-01T00:00:00.000Z', token: 's'.repeat(40) })));
    if (action === 'session-revoke') { revoked = true; return commandOK(JSON.stringify(outer({ generation: 2, revoked_sessions: 1 }))); }
    if (action === 'audit-status') return commandOK(JSON.stringify(outer({ valid: true, entries: records.length, head_hash: records.at(-1)?.hash ?? '0'.repeat(64) })));
    throw new Error(`unexpected native action: ${action}`);
  };
  const runCommand = async (_command, args) => {
    if (args.includes('hash-object')) return commandOK(`${'a'.repeat(64)}\n`);
    if (args.includes('rev-parse')) return commandOK(`${'b'.repeat(40)}\n`);
    if (args.includes('verify-commit')) return commandOK('GOOD ssh signature\n');
    if (args.includes('commit')) { appendAudit(revoked ? 'deny' : 'allow'); return revoked ? { ...commandOK(), ok: false } : commandOK(); }
    return commandOK();
  };
  const makeEvent = (record, previous) => { const event = { version: 1, event_id: record.request_id, request_id: record.request_id, agent_id: ids.agent_id, operation: 'git.commit.sign', decision: record.decision, reason: record.decision === 'allow' ? 'allowed' : 'denied', policy_sequence: 1, capability_sequence: 1, repository: input.repository, branch: input.branch, remote: input.remote, payload_digest: record.payload_sha256, device_timestamp: record.timestamp, previous_hash: previous, event_hash: '' }; event.event_hash = hash(Object.fromEntries(Object.entries(event).filter(([key]) => key !== 'event_hash'))); return event; };
  const fetchImpl = async (url, options) => { const path = new URL(url).pathname; const body = JSON.parse(options.body); operationId ??= body.operation_id; if (path.endsWith('/upload')) return { status: 202, arrayBuffer: async () => Buffer.from(JSON.stringify({ accepted: true, batch_id: 'batch-1234', event_ids: records.map((record) => record.request_id), operation_id: operationId })) }; let previous = '0'.repeat(64); const events = records.map((record) => { const event = makeEvent(record, previous); previous = event.event_hash; return event; }); return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify({ device_id: ids.device_id, events, next_cursor: null, operation_id: operationId, organization_id: ids.organization_id })) }; };
  const result = await performAuditUploadObservation({ release, machine, production: false, getUid: () => 0, readConfig: () => input, readServiceConfig: () => ({ audit_log_path: '/tmp/audit.jsonl' }), readAudit: async () => Buffer.from(records.map((record) => JSON.stringify(record)).join('\n') + '\n'), readSigner: () => ({ sha256: 'c'.repeat(64) }), runCommand, runPinned, fetchImpl, withCheckpoint: async (_path, operation) => operation(), sleepFn: async () => {} });
  assert.deepEqual(result, ['audit-console-observation']);
  assert.deepEqual(nativeCalls, ['session-start', 'ping', 'session-revoke', 'ping', 'audit-status']);
  assert.equal(records[0].decision, 'allow'); assert.equal(records[1].decision, 'deny');
});

test('audit input requires bounded short-lived session TTL', async () => {
  const bad = { ...input, ttl_seconds: 301 };
  await assert.rejects(() => performAuditUploadObservation({ release, machine, production: false, getUid: () => 0, readConfig: () => bad, withCheckpoint: async (_path, operation) => operation() }), /audit input is invalid/u);
});
