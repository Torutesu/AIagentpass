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
  code_identities_sha256: digest('c')
};
const boot = digest('d');
const executable = digest('e');
const codeIdentity = digest('f');
const iso = (second) => `2026-08-13T00:00:${String(second).padStart(2, '0')}.000Z`;
const event = (kind, second, fields = {}) => ({ kind, observed_at: iso(second), boot_id_digest: boot, ...fields });
const process = (second, pid, startTime, state) => ({ process_role: 'native-service', pid: String(pid), start_time_ns: String(startTime), boot_id_digest: boot, executable_sha256: executable, code_identity_sha256: codeIdentity, observed_at: iso(second), state });

const scenario = (name, offset, mode) => {
  const p1 = process(offset, 4100, 1000, 'running');
  const p1Exited = process(offset + 3, 4100, 1000, 'exited');
  const p2 = process(offset + 5, mode === 'same' ? 4100 : 4101, mode === 'same' ? 1000 : 2000, 'running');
  const requestDigest = digest('1');
  const receiptDigest = digest('2');
  const transportDigest = digest('3');
  const auditDigest = digest('4');
  const resultDigest = digest('5');
  let processes;
  let events;
  if (name === 'service-kill-after-cloud-commit') {
    processes = [p1, p1Exited, p2];
    events = [
      event('process_alive', offset, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns }),
      event('cloud_commit', offset + 1, { request_digest: requestDigest, commit_receipt_digest: receiptDigest }),
      event('process_exit', offset + 2, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns, exit_reason: 'SIGKILL' }),
      event('reply_lost', offset + 3, { transport_digest: transportDigest }),
      event('process_start', offset + 5, { process_pid: p2.pid, process_start_time_ns: p2.start_time_ns }),
      event('recovery', offset + 6, { request_digest: requestDigest, result_digest: resultDigest })
    ];
  } else if (name === 'daemon-restart-after-cloud-commit') {
    processes = [p1, p1Exited, p2];
    events = [
      event('process_alive', offset, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns }),
      event('cloud_commit', offset + 1, { request_digest: requestDigest, commit_receipt_digest: receiptDigest }),
      event('process_exit', offset + 2, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns, exit_reason: 'restart' }),
      event('process_start', offset + 5, { process_pid: p2.pid, process_start_time_ns: p2.start_time_ns }),
      event('recovery', offset + 6, { request_digest: requestDigest, result_digest: resultDigest })
    ];
  } else if (name === 'lost-reply-after-cloud-commit') {
    processes = [p1, p2];
    events = [
      event('process_alive', offset, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns }),
      event('cloud_commit', offset + 1, { request_digest: requestDigest, commit_receipt_digest: receiptDigest }),
      event('reply_lost', offset + 2, { transport_digest: transportDigest }),
      event('recovery', offset + 3, { request_digest: requestDigest, result_digest: resultDigest })
    ];
  } else {
    processes = [p1, p2];
    events = [
      event('process_alive', offset, { process_pid: p1.pid, process_start_time_ns: p1.start_time_ns }),
      event('cloud_commit', offset + 1, { request_digest: requestDigest, commit_receipt_digest: receiptDigest }),
      event('audit_fsync', offset + 2, { audit_record_digest: auditDigest, result: 'failure' }),
      event('reply_lost', offset + 3, { transport_digest: transportDigest }),
      event('audit_fsync', offset + 4, { audit_record_digest: auditDigest, result: 'success' }),
      event('audit_ack', offset + 5, { audit_record_digest: auditDigest }),
      event('recovery', offset + 6, { request_digest: requestDigest, result_digest: resultDigest })
    ];
  }
  return {
    name,
    status: 'passed',
    started_at: iso(offset),
    completed_at: iso(offset + 8),
    process_observations: processes,
    events,
    evidence_digests: [
      { kind: 'audit-record', sha256: auditDigest },
      { kind: 'process-trace', sha256: digest('6') }
    ]
  };
};

const makeEvidence = () => {
  const value = {
    schema_version: 1,
    candidate_id: 'release-2026-08-13-01',
    binding,
    started_at: iso(0),
    completed_at: iso(40),
    host: { platform: 'macos', architecture: 'arm64', os_build: '24A335', boot_id_digest: boot },
    scenarios: [
      scenario(REQUIRED_SCENARIOS[0], 1, 'replacement'),
      scenario(REQUIRED_SCENARIOS[1], 10, 'replacement'),
      scenario(REQUIRED_SCENARIOS[2], 20, 'same'),
      scenario(REQUIRED_SCENARIOS[3], 30, 'same')
    ],
    evidence_sha256: ''
  };
  value.evidence_sha256 = n3eEvidenceHash(value);
  return value;
};

const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;

test('accepts a canonical, candidate-bound N3-E evidence set', () => {
  const value = makeEvidence();
  const parsed = parseN3EEvidence(Buffer.from(canonical(value)));
  assert.equal(parsed.binding.artifact_sha256, binding.artifact_sha256);
  assert.deepEqual(parsed.scenarios.map(({ name }) => name), [...REQUIRED_SCENARIOS]);
  assert.deepEqual(verifyN3EEvidence(canonical(value), binding).binding, binding);
});

test('rejects binding substitution and self-digest tampering', () => {
  const value = makeEvidence();
  assert.throws(() => verifyN3EEvidence(value, { ...binding, artifact_sha256: digest('9') }), /binding mismatch/);
  const tampered = structuredClone(value);
  tampered.host.os_build = '24A336';
  assert.throws(() => validateN3EEvidence(tampered), /digest mismatch/);
});

test('rejects non-canonical JSON, duplicate keys, and bounded over-size input', () => {
  const value = makeEvidence();
  assert.throws(() => parseN3EEvidence(JSON.stringify(value)), /canonical JSON/);
  const duplicate = canonical(value).replace('"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,');
  assert.throws(() => parseN3EEvidence(duplicate), /duplicate JSON key/);
  assert.throws(() => parseN3EEvidence(Buffer.alloc(2 * 1024 * 1024 + 1)), /too large/);
});

test('rejects unknown, missing, duplicate, or out-of-order scenarios', () => {
  const value = makeEvidence();
  const unknown = structuredClone(value);
  unknown.scenarios[0].name = 'unknown-scenario';
  unknown.evidence_sha256 = n3eEvidenceHash(unknown);
  assert.throws(() => validateN3EEvidence(unknown), /name/);
  const duplicate = structuredClone(value);
  duplicate.scenarios[1] = duplicate.scenarios[0];
  duplicate.evidence_sha256 = n3eEvidenceHash(duplicate);
  assert.throws(() => validateN3EEvidence(duplicate), /name/);
  const missing = structuredClone(value);
  missing.scenarios.pop();
  missing.evidence_sha256 = n3eEvidenceHash(missing);
  assert.throws(() => validateN3EEvidence(missing), /incomplete/);
});

test('rejects missing process transitions and incomplete audit fsync proof', () => {
  const value = makeEvidence();
  const noExitObservation = structuredClone(value);
  noExitObservation.scenarios[0].process_observations[1].state = 'running';
  noExitObservation.evidence_sha256 = n3eEvidenceHash(noExitObservation);
  assert.throws(() => validateN3EEvidence(noExitObservation), /unobserved process transition/);
  const audit = structuredClone(value);
  audit.scenarios[3].events[4].result = 'failure';
  audit.evidence_sha256 = n3eEvidenceHash(audit);
  assert.throws(() => validateN3EEvidence(audit), /audit fsync recovery/);
});

test('rejects raw outputs and secret material even when attached to otherwise valid evidence', () => {
  const value = makeEvidence();
  const raw = structuredClone(value);
  raw.scenarios[0].events[0].stdout = 'native service output';
  assert.throws(() => validateN3EEvidence(raw), /forbidden secret or raw-output/);
  const secret = structuredClone(value);
  secret.scenarios[0].evidence_digests[0].kind = 'private-key';
  assert.throws(() => validateN3EEvidence(secret), /forbidden .*material/);
  const pem = structuredClone(value);
  pem.candidate_id = '-----BEGIN PRIVATE KEY-----';
  assert.throws(() => validateN3EEvidence(pem), /forbidden secret material/);
});

test('rejects scenario clocks or boot observations that cannot prove transitions', () => {
  const value = makeEvidence();
  const clock = structuredClone(value);
  clock.scenarios[1].events[2].observed_at = clock.scenarios[1].events[1].observed_at;
  clock.evidence_sha256 = n3eEvidenceHash(clock);
  assert.throws(() => validateN3EEvidence(clock), /time ordered/);
  const bootMismatch = structuredClone(value);
  bootMismatch.scenarios[2].process_observations[1].boot_id_digest = digest('9');
  bootMismatch.evidence_sha256 = n3eEvidenceHash(bootMismatch);
  assert.throws(() => validateN3EEvidence(bootMismatch), /boot identity/);
});

test('does not accept raw JSON with duplicate keys hidden in nested evidence', () => {
  const value = makeEvidence();
  const source = canonical(value).replace('"sha256": "' + digest('4') + '"', '"sha256": "' + digest('4') + '", "sha256": "' + digest('5') + '"');
  assert.throws(() => parseN3EEvidence(source), /duplicate JSON key/);
});

test('fixture hashing is deterministic and uses SHA-256', () => {
  const value = makeEvidence();
  assert.match(value.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(n3eEvidenceHash(value), value.evidence_sha256);
});
