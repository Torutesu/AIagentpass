import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import { anchorRecoveryAuthorization, createAnchorRecoveryPolicy } from "../lib/anchor.mjs";
import { canonicalJson } from "../lib/identity.mjs";
import { nativeAuditPublicKeyFingerprint } from "../lib/native-audit.mjs";
import { recoveryPolicyHash, recoveryPolicyToAnchorPolicy } from "../lib/recovery.mjs";

const cli = path.resolve("bin/agentpass.mjs");

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
}

function canonicalFile(directory, name, value) {
  const file = path.join(directory, name);
  fs.writeFileSync(file, `${canonicalJson(value)}\n`, { mode: 0o600 });
  return file;
}

const proposedPublicKey = (() => {
  const key = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
  const field = (value) => { const data = Buffer.from(value, "base64url"); const length = Buffer.alloc(4); length.writeUInt32BE(data.length); return Buffer.concat([length, data]); };
  const text = (value) => field(Buffer.from(value));
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(key.x, "base64url"), Buffer.from(key.y, "base64url")]);
  return `ecdsa-sha2-nistp256 ${Buffer.concat([text("ecdsa-sha2-nistp256"), text("nistp256"), field(point)]).toString("base64")}`;
})();

function recoveryRequest(now = Date.now(), policy = { version: 1, policy_id: "offline-recovery", threshold: 1, authorities: [] }) {
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

function anchorAuthorization(policy, now = Date.now()) {
  const anchorPolicy = recoveryPolicyToAnchorPolicy(policy);
  return anchorRecoveryAuthorization({
    version: 3,
    tenant: "recovery-host",
    installation_id: "build-mac-01",
    role: "audit_checkpoint",
    operation_id: "anchor-recovery-operation-001",
    recovery_request_id: "anchor-recovery-request-001",
    recovery_policy_id: anchorPolicy.policy_id,
    recovery_policy_hash: anchorPolicy.policy_hash,
    from_generation: 1,
    to_generation: 2,
    old_key_fingerprint: `SHA256:${Buffer.alloc(32, 1).toString("base64url")}`,
    new_key_fingerprint: nativeAuditPublicKeyFingerprint(proposedPublicKey),
    new_public_key: proposedPublicKey,
    lifecycle_head_hash: "1".repeat(64),
    created_at: new Date(now - 1_000).toISOString(),
    expires_at: new Date(now + 14 * 60_000).toISOString(),
    previous_transition_hash: "2".repeat(64),
    previous_transition_receipt_hash: "3".repeat(64),
    last_checkpoint_index: 7,
    last_checkpoint_hash: "4".repeat(64),
    last_checkpoint_receipt_hash: "5".repeat(64),
    previous_anchor_event_index: 9,
    previous_anchor_event_hash: "6".repeat(64),
    retiring_generation_pending_checkpoint_count: 0
  });
}

test("recovery CLI generates, signs, and verifies canonical threshold authorization", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-cli-"));
  const identities = [];

  for (const signer of ["security-1", "security-2"]) {
    const directory = path.join(root, signer);
    const generated = run(["recovery", "keygen", directory, "--signer", signer]);
    assert.equal(generated.status, 0, generated.stderr);
    assert.equal(generated.stdout, `${canonicalJson(JSON.parse(generated.stdout))}\n`);
    assert.doesNotMatch(generated.stdout, /PRIVATE KEY|private\.pem|private_file/);
    const metadata = JSON.parse(generated.stdout);
    const privateFile = path.join(directory, `${signer}.private.pem`);
    assert.equal(fs.statSync(privateFile).mode & 0o777, 0o600);
    assert.equal(fs.statSync(metadata.public_file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(privateFile).nlink, 1);

    identities.push({ signer, metadata, privateFile });
  }

  const policy = {
    version: 1,
    policy_id: "offline-recovery",
    threshold: 2,
    authorities: identities.map(({ signer, metadata }) => ({ id: signer, public_key: fs.readFileSync(metadata.public_file, "utf8") }))
  };
  const requestFile = canonicalFile(root, "request.json", recoveryRequest(Date.now(), policy));
  for (const identity of identities) {
    const signed = run(["recovery", "sign", "--request", requestFile, "--key", identity.privateFile, "--signer", identity.signer]);
    assert.equal(signed.status, 0, signed.stderr);
    identity.authorizationFile = canonicalFile(root, `${identity.signer}.authorization.json`, JSON.parse(signed.stdout));
  }
  const policyFile = canonicalFile(root, "policy.json", policy);
  const verified = run([
    "recovery", "verify", "--request", requestFile, "--policy", policyFile,
    "--authorization", identities[0].authorizationFile,
    "--authorization", identities[1].authorizationFile
  ]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, `${canonicalJson(JSON.parse(verified.stdout))}\n`);
  assert.deepEqual(JSON.parse(verified.stdout).accepted, ["security-1", "security-2"]);
});

test("recovery CLI refuses overwrite and unsafe private-key paths", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-cli-"));
  const directory = path.join(root, "identity");
  assert.equal(run(["recovery", "keygen", directory, "--signer", "security-1"]).status, 0);
  const repeated = run(["recovery", "keygen", directory, "--signer", "security-1"]);
  assert.notEqual(repeated.status, 0);
  assert.match(repeated.stderr, /already exist/);

  const requestFile = canonicalFile(root, "request.json", recoveryRequest());
  const privateFile = path.join(directory, "security-1.private.pem");
  fs.chmodSync(privateFile, 0o644);
  assert.match(run(["recovery", "sign", "--request", requestFile, "--key", privateFile, "--signer", "security-1"]).stderr, /permissions are unsafe/);
  fs.chmodSync(privateFile, 0o600);

  const symlink = path.join(root, "private-symlink.pem");
  fs.symlinkSync(privateFile, symlink);
  assert.match(run(["recovery", "sign", "--request", requestFile, "--key", symlink, "--signer", "security-1"]).stderr, /permissions are unsafe/);

  const hardlink = path.join(root, "private-hardlink.pem");
  fs.linkSync(privateFile, hardlink);
  assert.match(run(["recovery", "sign", "--request", requestFile, "--key", privateFile, "--signer", "security-1"]).stderr, /permissions are unsafe/);
});

test("recovery CLI rejects noncanonical, linked, and oversized JSON inputs", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-cli-"));
  const identityDir = path.join(root, "identity");
  assert.equal(run(["recovery", "keygen", identityDir, "--signer", "security-1"]).status, 0);
  const privateFile = path.join(identityDir, "security-1.private.pem");
  const request = recoveryRequest();

  const pretty = path.join(root, "pretty.json");
  fs.writeFileSync(pretty, JSON.stringify(request, null, 2), { mode: 0o600 });
  assert.match(run(["recovery", "sign", "--request", pretty, "--key", privateFile, "--signer", "security-1"]).stderr, /canonical JSON/);

  const requestFile = canonicalFile(root, "request.json", request);
  const linked = path.join(root, "request-linked.json");
  fs.linkSync(requestFile, linked);
  assert.match(run(["recovery", "sign", "--request", linked, "--key", privateFile, "--signer", "security-1"]).stderr, /single-link/);

  const oversized = path.join(root, "oversized.json");
  fs.writeFileSync(oversized, `{"padding":"${"x".repeat(17 * 1024)}"}`, { mode: 0o600 });
  assert.match(run(["recovery", "sign", "--request", oversized, "--key", privateFile, "--signer", "security-1"]).stderr, /bounded/);

  const invalidUtf8 = path.join(root, "invalid-utf8.json");
  fs.writeFileSync(invalidUtf8, Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]), { mode: 0o600 });
  assert.match(run(["recovery", "sign", "--request", invalidUtf8, "--key", privateFile, "--signer", "security-1"]).stderr, /UTF-8/);
});

test("recovery key generation preserves a pre-existing counterpart file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-recovery-cli-"));
  const directory = path.join(root, "identity");
  fs.mkdirSync(directory, { mode: 0o700 });
  const publicFile = path.join(directory, "security-1.public.pem");
  fs.writeFileSync(publicFile, "operator-owned", { mode: 0o600 });
  const result = run(["recovery", "keygen", directory, "--signer", "security-1"]);
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(publicFile, "utf8"), "operator-owned");
  assert.equal(fs.existsSync(path.join(directory, "security-1.private.pem")), false);
});

test("anchor-v3 CLI converts authorities policy, signs, and emits anchor-compatible canonical evidence", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-recovery-cli-"));
  const identities = ["operator-b", "operator-a"].map((signer) => {
    const directory = path.join(root, signer);
    const generated = run(["recovery", "keygen", directory, "--signer", signer]);
    assert.equal(generated.status, 0, generated.stderr);
    const metadata = JSON.parse(generated.stdout);
    return { signer, privateFile: path.join(directory, `${signer}.private.pem`), publicKey: fs.readFileSync(metadata.public_file, "utf8") };
  });
  const policy = { version: 1, policy_id: "offline-recovery", threshold: 2, authorities: identities.map(({ signer, publicKey }) => ({ id: signer, public_key: publicKey })) };
  const converted = recoveryPolicyToAnchorPolicy(policy);
  assert.deepEqual(converted, createAnchorRecoveryPolicy({ policy_id: policy.policy_id, threshold: policy.threshold, keys: policy.authorities.map(({ id, public_key }) => ({ id, public_key })) }));
  assert.deepEqual(converted.keys.map((item) => item.id), ["operator-a", "operator-b"]);
  assert.ok(converted.keys.every((item) => /^SHA256:[A-Za-z0-9_-]{43}$/.test(item.fingerprint)));

  const authorization = anchorAuthorization(policy);
  assert.deepEqual(authorization, anchorRecoveryAuthorization(authorization));
  const authorizationFile = canonicalFile(root, "authorization.json", authorization);
  const approvalFiles = [];
  for (const [index, identity] of identities.entries()) {
    const output = path.join(root, `${identity.signer}.approval.json`);
    const command = ["recovery", "anchor-sign", "--authorization", authorizationFile, "--key", identity.privateFile, "--signer", identity.signer];
    if (index === 0) command.push("--output", output);
    const signed = run(command);
    assert.equal(signed.status, 0, signed.stderr);
    if (index === 0) {
      assert.equal(signed.stdout, "");
      assert.equal(fs.statSync(output).mode & 0o777, 0o600);
      assert.equal(fs.statSync(output).nlink, 1);
    } else {
      fs.writeFileSync(output, signed.stdout, { flag: "wx", mode: 0o600 });
    }
    const approval = JSON.parse(fs.readFileSync(output, "utf8"));
    const trusted = converted.keys.find((item) => item.id === approval.key_id);
    assert.equal(crypto.verify(null, Buffer.from(canonicalJson(anchorRecoveryAuthorization(authorization))), trusted.public_key, Buffer.from(approval.signature, "base64")), true);
    approvalFiles.push(output);
  }

  const policyFile = canonicalFile(root, "policy.json", policy);
  const anchorPolicyFile = path.join(root, "anchor-policy.json");
  const policyResult = run(["recovery", "anchor-policy", "--policy", policyFile, "--output", anchorPolicyFile]);
  assert.equal(policyResult.status, 0, policyResult.stderr);
  assert.equal(policyResult.stdout, "");
  assert.deepEqual(JSON.parse(fs.readFileSync(anchorPolicyFile, "utf8")), converted);
  assert.equal(fs.statSync(anchorPolicyFile).mode & 0o777, 0o600);
  const verified = run(["recovery", "anchor-verify", "--authorization", authorizationFile, "--policy", policyFile, "--approval", approvalFiles[0], "--approval", approvalFiles[1]]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, `${canonicalJson(JSON.parse(verified.stdout))}\n`);
  const evidence = JSON.parse(verified.stdout);
  assert.deepEqual(evidence, { version: 1, policy: converted, authorization, approvals: evidence.approvals });
  assert.deepEqual(evidence.approvals.map((item) => item.key_id), ["operator-a", "operator-b"]);
});

test("anchor-v3 CLI rejects schema, trust, signature, input-file, and overwrite attacks", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-recovery-cli-"));
  const identityDir = path.join(root, "identity");
  const generated = run(["recovery", "keygen", identityDir, "--signer", "operator-a"]);
  assert.equal(generated.status, 0, generated.stderr);
  const metadata = JSON.parse(generated.stdout);
  const privateFile = path.join(identityDir, "operator-a.private.pem");
  const policy = { version: 1, policy_id: "offline-recovery", threshold: 1, authorities: [{ id: "operator-a", public_key: fs.readFileSync(metadata.public_file, "utf8") }] };
  const policyFile = canonicalFile(root, "policy.json", policy);
  const authorization = anchorAuthorization(policy);
  const authorizationFile = canonicalFile(root, "authorization.json", authorization);
  const output = path.join(root, "approval.json");
  assert.equal(run(["recovery", "anchor-sign", "--authorization", authorizationFile, "--key", privateFile, "--signer", "operator-a", "--output", output]).status, 0);
  const overwrite = run(["recovery", "anchor-sign", "--authorization", authorizationFile, "--key", privateFile, "--signer", "operator-a", "--output", output]);
  assert.notEqual(overwrite.status, 0);
  assert.match(overwrite.stderr, /must not already exist/);

  const extra = canonicalFile(root, "extra.json", { ...authorization, extra: true });
  assert.match(run(["recovery", "anchor-sign", "--authorization", extra, "--key", privateFile, "--signer", "operator-a"]).stderr, /encoding is invalid/);
  const hardlink = path.join(root, "authorization-hardlink.json");
  fs.linkSync(authorizationFile, hardlink);
  assert.match(run(["recovery", "anchor-sign", "--authorization", hardlink, "--key", privateFile, "--signer", "operator-a"]).stderr, /single-link/);
  fs.unlinkSync(hardlink);
  const symlink = path.join(root, "authorization-symlink.json");
  fs.symlinkSync(authorizationFile, symlink);
  assert.match(run(["recovery", "anchor-sign", "--authorization", symlink, "--key", privateFile, "--signer", "operator-a"]).stderr, /single-link/);

  const forged = JSON.parse(fs.readFileSync(output, "utf8"));
  forged.signature = Buffer.alloc(64).toString("base64");
  const forgedFile = canonicalFile(root, "forged.json", forged);
  assert.match(run(["recovery", "anchor-verify", "--authorization", authorizationFile, "--policy", policyFile, "--approval", forgedFile]).stderr, /signature is invalid/);
  assert.match(run(["recovery", "anchor-verify", "--authorization", authorizationFile, "--policy", policyFile, "--approval", output, "--approval", output]).stderr, /unique/);
  const duplicatePolicy = canonicalFile(root, "duplicate-policy.json", { ...policy, threshold: 1, authorities: [...policy.authorities, { id: "operator-b", public_key: policy.authorities[0].public_key }] });
  assert.match(run(["recovery", "anchor-verify", "--authorization", authorizationFile, "--policy", duplicatePolicy, "--approval", output]).stderr, /keys must be unique/);
  const duplicateIDPolicy = canonicalFile(root, "duplicate-id-policy.json", { ...policy, threshold: 1, authorities: [...policy.authorities, policy.authorities[0]] });
  assert.match(run(["recovery", "anchor-verify", "--authorization", authorizationFile, "--policy", duplicateIDPolicy, "--approval", output]).stderr, /keys must be unique/);
});

test("native key deletion fails closed for roles without external archive proof", () => {
  const result = run([
    "native", "key-delete", "git_signing", "1",
    "--reason", "retained", "--retention", "2592000", "--proof", "/tmp/proof.json"
  ]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /key-delete audit_checkpoint/);
});
