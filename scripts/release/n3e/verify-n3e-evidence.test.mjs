import assert from 'node:assert/strict';
import test from 'node:test';

import {
  REQUIRED_SCENARIOS,
  n3eEvidenceHash,
  parseN3EEvidence,
  validateN3EEvidence,
  verifyN3EEvidence
} from './verify-n3e-evidence.mjs';

const digest = (letter) => letter.repeat(64);
const binding = {
  artifact_sha256: digest('a'),
  source_commit: 'b'.repeat(40),
  team_id: 'ABCDE12345',
  code_identities_sha256: digest('d')
};
const boot = digest('e');
const executable = digest('f');
const codeIdentity = digest('c');
const iso = (second) => `2026-08-13T00:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second % 60).padStart(2, '0')}.000Z`;
const event = (kind, second, fields = {}) => ({ kind, observed_at: iso(second), boot_id_digest: boot, ...fields });
const process = (second, pid, startTime, state) => ({ process_role: 'native-service', pid: String(pid), start_time_ns: String(startTime), boot_id_digest: boot, executable_sha256: executable, code_identity_sha256: codeIdentity, observed_at: iso(second), state });

const common = Object.freeze({
  request: digest('1'),
  receipt: digest('2'),
  session: digest('3'),
  observation: digest('4'),
  authority: digest('5'),
  activation: digest('6'),
  result: digest('7'),
  transport: digest('8'),
  audit: digest('9'),
  compensation: digest('0')
});

const digestValue = (kind) => ({
  'cloud-commit-0': common.receipt,
  'cloud-observation-0': common.observation,
  'code-identity-set': binding.code_identities_sha256,
  'local-activation-0': common.authority,
  'local-authority-0': common.authority,
  'process-code-identity-0': codeIdentity,
  'process-executable-0': executable,
  'recovery-result-0': common.result,
  'reply-result-0': common.result,
  'transport-0': common.transport,
  'audit-record-0': common.audit,
  'compensation-0': common.compensation
}[kind]);

const refs = (kinds) => [...kinds].sort().map((kind) => ({ kind, sha256: digestValue(kind) }));
const cloudCommit = (offset) => event('cloud_commit', offset + 2, { request_digest: common.request, commit_receipt_digest: common.receipt, session_digest: common.session });
const cloudObservation = (offset, { committed = true, compensated = false } = {}) => event('cloud_observation', offset + 12, {
  request_digest: common.request,
  observation_digest: common.observation,
  commit_count: committed ? '1' : '0',
  session_count: committed ? '1' : '0',
  active_session_count: committed && !compensated ? '1' : '0',
  compensation_count: compensated ? '1' : '0',
  commit_receipt_digest: committed ? common.receipt : null,
  session_digest: committed ? common.session : null,
  compensation_digest: compensated ? common.compensation : null
});
const localAuthority = (offset, state, count, session = null) => event('local_authority', offset + 13, { authority_digest: common.authority, authority_count: count, state, session_digest: session });
const activation = (offset) => event('local_activation', offset + 3, { authority_digest: common.authority, session_digest: common.session });
const auditFsync = (offset, result) => event('audit_fsync', offset + 4, { audit_record_digest: common.audit, result });
const auditAck = (offset) => event('audit_ack', offset + 5, { audit_record_digest: common.audit });
const lostReply = (offset, boundary) => event('reply_lost', offset + (boundary === 'daemon-kill' ? 8 : 6), { request_digest: common.request, transport_digest: common.transport, result_digest: common.result, loss_boundary: boundary });
const recovery = (offset, second) => event('recovery', second, { request_digest: common.request, result_digest: common.result, commit_receipt_digest: common.receipt, session_digest: common.session, retry_kind: 'exact' });

const scenario = (name, offset) => {
  const first = process(offset, 4100, 1000, 'running');
  const exited = process(offset + 7, 4100, 1000, 'exited');
  const replacement = process(offset + 10, 4101, 2000, 'running');
  const same = process(offset + 10, 4100, 1000, 'running');
  let processes;
  let events;
  let digestKinds;
  if (name === 'pre-cloud-kill') {
    processes = [first, exited, replacement];
    events = [
      event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }),
      event('process_exit', offset + 6, { process_pid: first.pid, process_start_time_ns: first.start_time_ns, exit_reason: 'SIGKILL' }),
      event('process_start', offset + 9, { process_pid: replacement.pid, process_start_time_ns: replacement.start_time_ns }),
      cloudObservation(offset, { committed: false }),
      localAuthority(offset, 'absent', '0')
    ];
    digestKinds = ['cloud-observation-0', 'code-identity-set', 'local-authority-0', 'process-code-identity-0', 'process-executable-0'];
  } else if (name === 'post-cloud-pre-local-kill') {
    processes = [first, exited, replacement];
    events = [
      event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }), cloudCommit(offset),
      event('process_exit', offset + 6, { process_pid: first.pid, process_start_time_ns: first.start_time_ns, exit_reason: 'SIGKILL' }),
      event('process_start', offset + 9, { process_pid: replacement.pid, process_start_time_ns: replacement.start_time_ns }),
      recovery(offset, offset + 11), cloudObservation(offset), localAuthority(offset, 'absent', '0')
    ];
    digestKinds = ['cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0'];
  } else if (name === 'post-activation-pre-audit-kill') {
    processes = [first, exited, replacement];
    events = [
      event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }), cloudCommit(offset), activation(offset),
      event('process_exit', offset + 6, { process_pid: first.pid, process_start_time_ns: first.start_time_ns, exit_reason: 'SIGKILL' }),
      event('process_start', offset + 9, { process_pid: replacement.pid, process_start_time_ns: replacement.start_time_ns }),
      cloudObservation(offset), localAuthority(offset, 'absent', '0')
    ];
    digestKinds = ['cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0'];
  } else if (name === 'post-audit-pre-reply-loss') {
    processes = [first, exited, replacement];
    events = [
      event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }), cloudCommit(offset), activation(offset), auditFsync(offset, 'success'), auditAck(offset),
      event('process_exit', offset + 7, { process_pid: first.pid, process_start_time_ns: first.start_time_ns, exit_reason: 'SIGKILL' }), lostReply(offset, 'daemon-kill'),
      event('process_start', offset + 9, { process_pid: replacement.pid, process_start_time_ns: replacement.start_time_ns }), recovery(offset, offset + 11), cloudObservation(offset), localAuthority(offset, 'absent', '0')
    ];
    digestKinds = ['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0', 'reply-result-0', 'transport-0'];
  } else if (name === 'audit-fsync-failure') {
    processes = [first, same];
    events = [event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }), cloudCommit(offset), activation(offset), auditFsync(offset, 'failure'), event('compensation', offset + 5, { request_digest: common.request, session_digest: common.session, compensation_digest: common.compensation, reason: 'audit-fsync-failure', result: 'revoked' }), cloudObservation(offset, { compensated: true }), localAuthority(offset, 'revoked', '0', common.session)];
    digestKinds = ['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'compensation-0', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0'];
  } else {
    processes = [first, same];
    events = [event('process_alive', offset + 1, { process_pid: first.pid, process_start_time_ns: first.start_time_ns }), cloudCommit(offset), activation(offset), auditFsync(offset, 'success'), auditAck(offset), lostReply(offset, 'transport'), recovery(offset, offset + 7), cloudObservation(offset), localAuthority(offset, 'active', '1', common.session)];
    digestKinds = ['audit-record-0', 'cloud-commit-0', 'cloud-observation-0', 'code-identity-set', 'local-activation-0', 'local-authority-0', 'process-code-identity-0', 'process-executable-0', 'recovery-result-0', 'reply-result-0', 'transport-0'];
  }
  return { name, status: 'passed', started_at: iso(offset), completed_at: iso(offset + 18), process_observations: processes, events, evidence_digests: refs(digestKinds) };
};

const makeEvidence = () => {
  const value = {
    schema_version: 1, candidate_id: 'release-2026-08-13-01', binding, started_at: iso(0), completed_at: iso(190),
    host: { platform: 'macos', architecture: 'arm64', os_build: '24A335', boot_id_digest: boot },
    scenarios: REQUIRED_SCENARIOS.map((name, index) => scenario(name, 10 + index * 30)), evidence_sha256: ''
  };
  value.evidence_sha256 = n3eEvidenceHash(value);
  return value;
};

const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;

test('accepts the exact ordered six-scenario, candidate-bound evidence set', () => {
  const value = makeEvidence();
  const parsed = parseN3EEvidence(Buffer.from(canonical(value)));
  assert.deepEqual(parsed.scenarios.map(({ name }) => name), [...REQUIRED_SCENARIOS]);
  assert.deepEqual(verifyN3EEvidence(canonical(value), binding).binding, binding);
});

test('rejects scenario inventory substitution, omission, duplication, or reordering', () => {
  const value = makeEvidence();
  for (const mutate of [
    (copy) => { copy.scenarios[0].name = 'unknown-scenario'; },
    (copy) => { copy.scenarios[1] = copy.scenarios[0]; },
    (copy) => { copy.scenarios.reverse(); },
    (copy) => { copy.scenarios.pop(); }
  ]) {
    const copy = structuredClone(value);
    mutate(copy);
    copy.evidence_sha256 = n3eEvidenceHash(copy);
    assert.throws(() => validateN3EEvidence(copy), /(?:name|incomplete)/u);
  }
});

test('requires digest-bound Cloud observations for every count assertion', () => {
  const value = makeEvidence();
  const copy = structuredClone(value);
  copy.scenarios[0].events[3].observation_digest = digest('9');
  copy.evidence_sha256 = n3eEvidenceHash(copy);
  assert.throws(() => validateN3EEvidence(copy), /not bound to digest inventory/u);
  const inconsistent = structuredClone(value);
  inconsistent.scenarios[0].events[3].commit_count = '1';
  inconsistent.evidence_sha256 = n3eEvidenceHash(inconsistent);
  assert.throws(() => validateN3EEvidence(inconsistent), /Cloud (?:commit|observation)/u);
});

test('proves the six distinct fault outcomes and rejects boundary substitutions', () => {
  const value = makeEvidence();
  assert.equal(value.scenarios[0].events.some(({ kind }) => kind === 'cloud_commit'), false);
  assert.equal(value.scenarios[1].events.find(({ kind }) => kind === 'recovery').retry_kind, 'exact');
  assert.equal(value.scenarios[2].events.at(-1).state, 'absent');
  assert.equal(value.scenarios[3].events.find(({ kind }) => kind === 'reply_lost').loss_boundary, 'daemon-kill');
  assert.equal(value.scenarios[4].events.find(({ kind }) => kind === 'compensation').result, 'revoked');
  assert.equal(value.scenarios[5].events.find(({ kind }) => kind === 'reply_lost').loss_boundary, 'transport');
  const copy = structuredClone(value);
  copy.scenarios[5].events[5].loss_boundary = 'daemon-kill';
  copy.evidence_sha256 = n3eEvidenceHash(copy);
  assert.throws(() => validateN3EEvidence(copy), /exact transport retry/u);
});

test('rejects binding, boot, process, and exact-result substitutions', () => {
  const value = makeEvidence();
  assert.throws(() => verifyN3EEvidence(value, { ...binding, artifact_sha256: digest('9') }), /binding mismatch/u);
  const bootMismatch = structuredClone(value);
  bootMismatch.scenarios[2].events[0].boot_id_digest = digest('9');
  bootMismatch.evidence_sha256 = n3eEvidenceHash(bootMismatch);
  assert.throws(() => validateN3EEvidence(bootMismatch), /boot identity/u);
  const processMismatch = structuredClone(value);
  processMismatch.scenarios[1].events[3].process_pid = '9999';
  processMismatch.evidence_sha256 = n3eEvidenceHash(processMismatch);
  assert.throws(() => validateN3EEvidence(processMismatch), /unobserved process transition/u);
  const resultMismatch = structuredClone(value);
  resultMismatch.scenarios[5].events[5].result_digest = digest('a');
  resultMismatch.evidence_sha256 = n3eEvidenceHash(resultMismatch);
  assert.throws(() => validateN3EEvidence(resultMismatch), /reply-result|exact retry/u);
});

test('rejects non-canonical JSON, duplicate keys, secrets, and raw output', () => {
  const value = makeEvidence();
  assert.throws(() => parseN3EEvidence(JSON.stringify(value)), /canonical JSON/u);
  const duplicate = canonical(value).replace('"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,');
  assert.throws(() => parseN3EEvidence(duplicate), /duplicate JSON key/u);
  const nestedDuplicate = canonical(value).replace(`"sha256": "${common.observation}"`, `"sha256": "${common.observation}", "sha256": "${digest('z')}"`);
  assert.throws(() => parseN3EEvidence(nestedDuplicate), /duplicate JSON key/u);
  const raw = structuredClone(value);
  raw.scenarios[0].events[0].stdout = 'native service output';
  assert.throws(() => validateN3EEvidence(raw), /forbidden secret or raw-output/u);
  const secret = structuredClone(value);
  secret.scenarios[0].evidence_digests[0].kind = 'private-key';
  assert.throws(() => validateN3EEvidence(secret), /forbidden .*material/u);
});

test('hashing is deterministic and bounded', () => {
  const value = makeEvidence();
  assert.match(value.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(n3eEvidenceHash(value), value.evidence_sha256);
  assert.throws(() => parseN3EEvidence(Buffer.alloc(2 * 1024 * 1024 + 1)), /too large/u);
});
