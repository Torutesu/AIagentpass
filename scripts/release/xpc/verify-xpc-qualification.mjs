#!/usr/bin/env node
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const SCHEMA_VERSION = 2;
const HEX64 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const REQUIRED_KEYS = Object.freeze(['candidate_sha256', 'child_requirement', 'host_activation', 'launch_observation', 'negative_cases', 'schema_version', 'source_commit']);
const ACTIVATION_KEYS = Object.freeze(['audit_token_capture', 'audit_token_sha256', 'child_process_identity_sha256', 'child_requirement_sha256', 'projection_sha256', 'status', 'transport']);
const REQUIREMENT_KEYS = Object.freeze(['evaluation', 'principal', 'sha256']);
const LAUNCH_OBSERVATION_KEYS = Object.freeze(['artifact_sha256', 'child_mach_service', 'child_pid', 'child_start_time_ns', 'host_mach_service', 'host_pid', 'host_start_time_ns', 'mode', 'status']);
const NEGATIVE_CASE_KEYS = Object.freeze(['case', 'result']);
const NEGATIVE_CASES = Object.freeze(['same_uid_wrong_child', 'wrong_team', 'wrong_entitlement', 'stale_or_reused_audit_token']);
const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};
const digest = (value, label) => { if (typeof value !== 'string' || !HEX64.test(value)) throw new Error(`${label} must be a lowercase SHA-256 digest`); };

export function validateXpcQualificationEvidence(value) {
  exactKeys(value, REQUIRED_KEYS, 'XPC qualification evidence');
  if (value.schema_version !== SCHEMA_VERSION) throw new Error('XPC qualification schema_version is unsupported');
  digest(value.candidate_sha256, 'candidate_sha256');
  if (typeof value.source_commit !== 'string' || !COMMIT.test(value.source_commit)) throw new Error('source_commit is invalid');
  exactKeys(value.host_activation, ACTIVATION_KEYS, 'host_activation');
  for (const [field, label] of [['audit_token_sha256', 'live audit-token digest'], ['child_process_identity_sha256', 'Child process identity digest'], ['child_requirement_sha256', 'Child requirement digest'], ['projection_sha256', 'Host activation projection digest']]) digest(value.host_activation[field], label);
  if (value.host_activation.audit_token_capture !== 'live_eight_field') throw new Error('audit-token capture is not live_eight_field');
  if (value.host_activation.status !== 'passed') throw new Error('Host activation projection is not passed');
  if (value.host_activation.transport !== 'authenticated_xpc') throw new Error('Host activation transport is not authenticated_xpc');
  exactKeys(value.launch_observation, LAUNCH_OBSERVATION_KEYS, 'launch_observation');
  digest(value.launch_observation.artifact_sha256, 'launch observation artifact digest');
  if (value.launch_observation.artifact_sha256 !== value.candidate_sha256) throw new Error('launch observation is not bound to candidate artifact');
  if (value.launch_observation.mode !== 'launchd_mach_nsxpc') throw new Error('launch observation is not a real launchd Mach NSXPC observation');
  if (value.launch_observation.host_mach_service !== 'dev.agentpass.agent-host' || value.launch_observation.child_mach_service !== 'dev.agentpass.child-git') throw new Error('launch observation Mach service identity is not fixed');
  for (const [field, label] of [['host_pid', 'Host PID'], ['child_pid', 'Child PID']]) {
    if (!Number.isSafeInteger(value.launch_observation[field]) || value.launch_observation[field] <= 0) throw new Error(`${label} is invalid`);
  }
  if (value.launch_observation.host_pid === value.launch_observation.child_pid) throw new Error('Host and Child PID must be distinct');
  for (const [field, label] of [['host_start_time_ns', 'Host start time'], ['child_start_time_ns', 'Child start time']]) {
    if (typeof value.launch_observation[field] !== 'string' || !/^[0-9]+$/u.test(value.launch_observation[field])) throw new Error(`${label} is invalid`);
  }
  if (value.launch_observation.status !== 'passed') throw new Error('launch observation is not passed');
  exactKeys(value.child_requirement, REQUIREMENT_KEYS, 'child_requirement');
  digest(value.child_requirement.sha256, 'child_requirement.sha256');
  if (value.child_requirement.principal !== 'dev.agentpass.git-sign-xpc') throw new Error('Child requirement principal is not fixed');
  if (value.child_requirement.evaluation !== 'passed') throw new Error('Child-specific requirement evaluation is not passed');
  if (value.child_requirement.sha256 !== value.host_activation.child_requirement_sha256) throw new Error('Child requirement digest is not bound to Host activation');
  if (!Array.isArray(value.negative_cases) || value.negative_cases.length !== NEGATIVE_CASES.length) throw new Error('negative_cases must contain the fixed denial matrix');
  const seen = new Set();
  for (const entry of value.negative_cases) {
    exactKeys(entry, NEGATIVE_CASE_KEYS, 'negative case');
    if (!NEGATIVE_CASES.includes(entry.case) || seen.has(entry.case)) throw new Error('negative case set is not exact');
    seen.add(entry.case); if (entry.result !== 'denied_before_sign') throw new Error(`negative case ${entry.case} did not deny before sign`);
  }
  if (seen.size !== NEGATIVE_CASES.length) throw new Error('negative case set is incomplete');
  const serialized = JSON.stringify(value);
  if (/(?:audit[_-]?token|raw[_-]?token|private[_-]?key|credential|signature)\s*:/iu.test(serialized)) throw new Error('evidence contains a prohibited raw secret-bearing field');
  return Object.freeze({ schema_version: value.schema_version, candidate_sha256: value.candidate_sha256, source_commit: value.source_commit, evidence_sha256: createHash('sha256').update(serialized, 'utf8').digest('hex') });
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const input = process.argv[2]; if (!input || process.argv.length !== 3) throw new Error('Usage: verify-xpc-qualification.mjs EVIDENCE.json');
  const result = validateXpcQualificationEvidence(JSON.parse(fs.readFileSync(input, 'utf8')));
  process.stdout.write(`XPC qualification evidence valid: candidate=${result.candidate_sha256}, evidence=${result.evidence_sha256}\n`);
}
