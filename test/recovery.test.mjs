import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { generateRecoveryIdentity, recoveryPolicyHash, requestHash, signRecoveryRequest, validateRecoveryRequest, verifyRecoveryAuthorization, verifyRecoveryThreshold } from "../lib/recovery.mjs";

const proposedPublicKey = (() => {
  const key = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
  const field = (value) => { const data = Buffer.from(value, "base64url"); const length = Buffer.alloc(4); length.writeUInt32BE(data.length); return Buffer.concat([length, data]); };
  const text = (value) => field(Buffer.from(value));
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(key.x, "base64url"), Buffer.from(key.y, "base64url")]);
  return `ecdsa-sha2-nistp256 ${Buffer.concat([text("ecdsa-sha2-nistp256"), text("nistp256"), field(point)]).toString("base64")}`;
})();

function request(now = Date.now(), policy = { version: 1, policy_id: "offline-recovery", threshold: 1, authorities: [] }) {
  return {
    version: 1,
    installation_id: "build-mac-01",
    role: "audit_checkpoint",
    from_generation: 1,
    from_fingerprint: `SHA256:${Buffer.alloc(32, 1).toString("base64url")}`,
    proposed_generation: 2,
    proposed_public_key: proposedPublicKey,
    recovery_policy_version: policy.version,
    recovery_policy_id: policy.policy_id,
    recovery_policy_hash: recoveryPolicyHash(policy),
    lifecycle_head_hash: "a".repeat(64),
    audit_entries: 42,
    audit_head_hash: "b".repeat(64),
    latest_checkpoint_hash: "c".repeat(64),
    latest_receipt_hash: "d".repeat(64),
    control_sequence: 7,
    nonce: crypto.randomBytes(32).toString("base64url"),
    issued_at: new Date(now - 1_000).toISOString(),
    expires_at: new Date(now + 14 * 60_000).toISOString()
  };
}

test("offline recovery requires unique threshold signatures over an exact request", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-"));
  const first = generateRecoveryIdentity(root, "security-1");
  const second = generateRecoveryIdentity(root, "security-2");
  const policy = { version: 1, policy_id: "offline-recovery", threshold: 2, authorities: [{ id: first.signer_id, public_key: first.public_key }, { id: second.signer_id, public_key: second.public_key }] };
  const value = request(Date.now(), policy);
  const one = signRecoveryRequest(value, first.private_file, first.signer_id);
  const two = signRecoveryRequest(value, second.private_file, second.signer_id);
  assert.equal(verifyRecoveryAuthorization(value, one, policy.authorities[0]).request_hash, requestHash(value));
  assert.deepEqual(verifyRecoveryThreshold(value, [one, two], policy).accepted, ["security-1", "security-2"]);
  assert.throws(() => verifyRecoveryThreshold(value, [one], policy), /threshold/);
  assert.throws(() => verifyRecoveryThreshold(value, [one, one], policy), /Duplicate/);
  assert.throws(() => verifyRecoveryThreshold(value, [one, two], { ...policy, authorities: [policy.authorities[0], { ...policy.authorities[0], id: "security-2" }] }), /duplicate authority keys/);
  assert.throws(() => verifyRecoveryThreshold(value, [one, two], { ...policy, policy_id: "substituted" }), /not bound/);
  assert.throws(() => verifyRecoveryThreshold({ ...value, audit_entries: 43 }, [one, two], policy), /statement|signature|request/i);
});

test("recovery request and signing key validation fail closed", () => {
  const now = Date.now();
  assert.throws(() => validateRecoveryRequest({ ...request(now), extra: true }, now), /encoding/);
  assert.throws(() => validateRecoveryRequest({ ...request(now), expires_at: new Date(now + 16 * 60_000).toISOString() }, now), /window/);
  assert.throws(() => validateRecoveryRequest({ ...request(now), proposed_generation: 3 }, now), /generation/);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-"));
  const identity = generateRecoveryIdentity(root, "security-1");
  fs.chmodSync(identity.private_file, 0o644);
  assert.throws(() => signRecoveryRequest(request(now), identity.private_file, identity.signer_id, now), /permissions/);
});
