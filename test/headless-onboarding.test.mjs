import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  parseEnrollmentInvitation,
  publicSetupFailure,
  publicSetupResult,
  readHeadlessOnboarding,
  redactDiagnostic,
  validateHeadlessEnrollmentBaseUrl
} from "../lib/headless-onboarding.mjs";
import { createSetupJournal, loadSetupJournal } from "../lib/setup-journal.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-headless-onboarding-"));
  const directory = path.join(root, "config");
  return { root, directory };
}

function cleanup(value) {
  fs.rmSync(value.root, { recursive: true, force: true });
}

function invitation() {
  const receipt = crypto.generateKeyPairSync("ed25519");
  const publicKey = receipt.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(receipt.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const candidate = {
    version: 1,
    enrollment_id: "11111111-1111-4111-8111-111111111111",
    organization_id: "22222222-2222-4222-8222-222222222222",
    device_id: "33333333-3333-4333-8333-333333333333",
    candidate_id: "release-2026-08-13-01",
    artifact_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: fingerprint,
    expires_at: "2099-01-02T03:04:05.000Z"
  };
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: candidate.enrollment_id,
    organization_id: candidate.organization_id,
    device_id: candidate.device_id,
    label: "build-mac-01",
    platform: "macos",
    candidate_binding: candidate,
    challenge_id: candidate.enrollment_id,
    nonce: "A".repeat(43),
    expires_at: candidate.expires_at,
    challenge: {
      challenge_id: candidate.enrollment_id,
      nonce: "A".repeat(43),
      expires_at: candidate.expires_at,
      candidate_id: candidate.candidate_id,
      device_key_fingerprint: fingerprint
    },
    credential: "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE",
    endpoint: `/v1/enrollments/${candidate.enrollment_id}`,
    possession_receipt_verification: { key_id: "receipt-key-v1", algorithm: "ed25519", public_key: publicKey }
  };
}

test("strictly parses the v2 stdin handoff and rejects endpoint/platform substitution", () => {
  const value = invitation();
  const parsed = parseEnrollmentInvitation({ enrollment: value });
  assert.equal(parsed.version, 2);
  assert.equal(parsed.endpoint, `/v1/enrollments/${parsed.enrollment_id}`);
  assert.equal(parsed.platform, "macos");
  assert.equal(parsed.credential, value.credential);
  assert.throws(() => parseEnrollmentInvitation({ ...value, platform: "linux" }), /v2 macOS/);
  const { version: _missingVersion, ...missingVersion } = value;
  assert.throws(() => parseEnrollmentInvitation(missingVersion), /unknown or missing fields/);
  assert.throws(() => parseEnrollmentInvitation({ ...value, version: 1 }), /v2 macOS/);
  assert.throws(() => parseEnrollmentInvitation({ ...value, endpoint: "https://api.example.test/v1" }), /endpoint/);
  assert.throws(() => parseEnrollmentInvitation({ ...value, possession_receipt_verification: { ...value.possession_receipt_verification, public_key: "-----BEGIN PRIVATE KEY-----" } }), /verification key/);
  assert.equal(validateHeadlessEnrollmentBaseUrl("https://api.example.test/v1/"), "https://api.example.test/v1");
  for (const value of ["http://api.example.test/v1", "https://api.example.test/api", "https://user:pass@api.example.test/v1", "https://api.example.test/v1?token=secret"]) {
    assert.throws(() => validateHeadlessEnrollmentBaseUrl(value), /HTTPS|credential-free/);
  }
});

test("shared status is resumable after a fresh process reads the durable journal", () => {
  const value = fixture();
  try {
    const first = createSetupJournal({ directory: value.directory, clock: () => "2030-01-01T00:00:00.000Z" });
    first.transition("app_verified");

    const result = readHeadlessOnboarding({ journalOptions: { directory: value.directory } });
    assert.equal(result.ok, true);
    assert.equal(result.status.state, "app_verified");
    assert.equal(result.status.revision, 1);
    assert.equal(result.status.next_actions[0].id, "initialize_local_config");
    assert.equal(loadSetupJournal({ directory: value.directory }).status().state, "app_verified");
  } finally { cleanup(value); }
});

test("journal corruption is blocked and never presented as a fresh setup", () => {
  const value = fixture();
  try {
    const journal = createSetupJournal({ directory: value.directory });
    const raw = JSON.parse(fs.readFileSync(journal.paths.journalPath, "utf8"));
    raw.state = "app_verified";
    fs.writeFileSync(journal.paths.journalPath, `${JSON.stringify(raw)}\n`, { mode: 0o600 });
    fs.chmodSync(journal.paths.journalPath, 0o600);

    const result = readHeadlessOnboarding({ journalOptions: { directory: value.directory } });
    assert.equal(result.ok, false);
    assert.equal(result.status, null);
    assert.equal(result.error.error.code, "TAMPERED_JOURNAL");
    assert.equal(result.error.error.message.includes(value.root), false);
    assert.equal(result.error.error.remediation.includes(value.root), false);
  } finally { cleanup(value); }
});

test("public setup output drops evidence and redacts diagnostics", () => {
  const result = publicSetupResult({
    execute: true,
    changed: true,
    action: {
      id: "enroll_device",
      from_state: "service_keys_activated",
      target_state: "device_enrolled",
      operation_id: "setup:secret-journal:8:enroll_device",
      command: "agentpass setup continue"
    },
    evidence: { proof: { credential: "reusable-secret" } },
    journal: {
      version: 1,
      journal_id: "123e4567-e89b-12d3-a456-426614174000",
      revision: 8,
      state: "device_enrolled",
      updated_at: "2030-01-01T00:00:00.000Z",
      setup_complete: false,
      next_actions: [{ id: "connect_editor", target_state: "editor_connected", command: "agentpass setup continue" }],
      history_length: 9
    }
  });
  const serialized = JSON.stringify(result);
  assert.equal(result.ok, true);
  assert.equal(Object.hasOwn(result, "evidence"), false);
  assert.equal(serialized.includes("reusable-secret"), false);
  assert.equal(serialized.includes("operation_id"), false);

  const diagnostic = redactDiagnostic("failed token=super-secret at /Users/alice/Secrets/key.json");
  assert.equal(diagnostic.includes("super-secret"), false);
  assert.equal(diagnostic.includes("/Users/alice"), false);
  assert.equal(redactDiagnostic({ secret: "never" }), "diagnostic_available");
});

test("setup failures have stable machine-readable redacted shape", () => {
  const result = publicSetupFailure(Object.assign(new Error("private key at /Users/alice/key"), { code: "SERVICE_RESTART_FAILED" }), { state: "device_enrolled" });
  assert.deepEqual(result, {
    version: 1,
    ok: false,
    error: {
      code: "SERVICE_RESTART_FAILED",
      message: "The native service could not be restarted safely.",
      remediation: "Run `agentpass setup status` and `agentpass doctor` before retrying."
    },
    state: "device_enrolled",
    onboarding: {
      version: 1,
      initialized: true,
      state: "device_enrolled",
      setup_complete: false,
      next_actions: [],
    }
  });
});
