import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { anchorPendingCheckpoints, readAnchorReceipts, verifyStoredAnchorReceipts } from "../lib/anchor-client.mjs";
import { createAnchorServer, enrollAnchorTenant, initializeAnchor, submitAnchorCheckpoint, verifyAnchorReceipt, verifyAnchorTenant } from "../lib/anchor.mjs";
import { audit, createAuditCheckpoint, publicKeyFingerprint, readAuditCheckpoints } from "../lib/audit.mjs";
import { canonicalJson, createAuditIdentity } from "../lib/identity.mjs";
import { nativeAuditPublicKeyFingerprint, verifyNativeCheckpointRecord } from "../lib/native-audit.mjs";

function fixture() {
  const host = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-host-"));
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-anchor-server-"));
  const identity = createAuditIdentity(host);
  const initialized = initializeAnchor(anchor);
  enrollAnchorTenant(anchor, "host-one", identity.public_key);
  audit({ operation: "test.one", decision: "allow" }, host);
  const first = createAuditCheckpoint(identity.public_key, host);
  audit({ operation: "test.two", decision: "allow" }, host);
  const second = createAuditCheckpoint(identity.public_key, host);
  return { host, anchor, identity, initialized, first, second };
}

function nativeFixture() {
  const anchor = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-native-anchor-server-"));
  const initialized = initializeAnchor(anchor);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  const publicBlob = Buffer.concat([sshString("ecdsa-sha2-nistp256"), sshString("nistp256"), sshString(point)]);
  const auditPublicKey = `ecdsa-sha2-nistp256 ${publicBlob.toString("base64")}`;
  const enrolled = enrollAnchorTenant(anchor, "native-host", auditPublicKey);
  const checkpoint = (entries, previous, headByte) => {
    const statement = {
      version: 1,
      created_at: new Date(1_800_000_000_000 + entries * 1000).toISOString(),
      entries,
      head_hash: headByte.repeat(64),
      previous_checkpoint_hash: previous
    };
    const signature = crypto.sign("sha256", Buffer.from(canonicalJson(statement)), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
    const record = { ...statement, public_key_fingerprint: nativeAuditPublicKeyFingerprint(auditPublicKey), signature };
    record.checkpoint_hash = crypto.createHash("sha256").update(canonicalJson(record)).digest("hex");
    return record;
  };
  const first = checkpoint(1, "0".repeat(64), "a");
  const second = checkpoint(2, first.checkpoint_hash, "b");
  return { anchor, initialized, enrolled, auditPublicKey, first, second };
}

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

test("anchor signs an append-only checkpoint and receipt chain", () => {
  const value = fixture();
  const firstReceipt = submitAnchorCheckpoint(value.anchor, "host-one", value.first, Date.parse("2026-08-11T00:00:00Z"));
  assert.deepEqual(submitAnchorCheckpoint(value.anchor, "host-one", value.first), firstReceipt, "retries must be idempotent");
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "host-one", value.second, Date.parse("2026-08-11T00:01:00Z"));
  assert.equal(secondReceipt.index, 2);
  assert.equal(secondReceipt.previous_receipt_hash, firstReceipt.receipt_hash);
  assert.equal(verifyAnchorReceipt(secondReceipt, fs.readFileSync(value.initialized.public_file), {
    tenant: "host-one",
    checkpointHash: value.second.checkpoint_hash,
    previousReceiptHash: firstReceipt.receipt_hash
  }).receipt_hash, secondReceipt.receipt_hash);
  assert.deepEqual(verifyAnchorTenant(value.anchor, "host-one"), {
    valid: true,
    records: 2,
    latest_checkpoint: value.second.checkpoint_hash,
    latest_receipt: secondReceipt.receipt_hash
  });
});

test("anchor enrolls and verifies native P-256 checkpoint chains", () => {
  const value = nativeFixture();
  assert.equal(value.enrolled.version, 2);
  assert.equal(value.enrolled.checkpoint_algorithm, "p256-sha256");
  assert.equal(verifyNativeCheckpointRecord(value.first, value.auditPublicKey).checkpoint_hash, value.first.checkpoint_hash);
  const firstReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.first);
  assert.deepEqual(submitAnchorCheckpoint(value.anchor, "native-host", value.first), firstReceipt);
  const secondReceipt = submitAnchorCheckpoint(value.anchor, "native-host", value.second);
  assert.equal(secondReceipt.index, 2);
  assert.deepEqual(verifyAnchorTenant(value.anchor, "native-host"), {
    valid: true,
    records: 2,
    latest_checkpoint: value.second.checkpoint_hash,
    latest_receipt: secondReceipt.receipt_hash
  });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "native-host", { ...value.second, entries: 3 }), /signature|hash/i);
  const configFile = path.join(value.anchor, "tenants", "native-host", "config.json");
  const config = JSON.parse(fs.readFileSync(configFile, "utf8"));
  config.checkpoint_algorithm = "ed25519";
  fs.writeFileSync(configFile, `${JSON.stringify(config)}\n`, { mode: 0o600 });
  assert.throws(() => verifyAnchorTenant(value.anchor, "native-host"), /algorithm|identity/i);
});

test("HTTP anchor accepts native checkpoints and rejects algorithm confusion", async (t) => {
  const value = nativeFixture();
  const server = createAnchorServer(value.anchor);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const endpoint = `http://127.0.0.1:${server.address().port}/v1/checkpoints/native-host`;
  const accepted = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ checkpoint: value.first }) });
  assert.equal(accepted.status, 200);

  const ed25519 = fixture();
  const confused = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ checkpoint: ed25519.first }) });
  assert.equal(confused.status, 400);
  assert.match((await confused.json()).error, /Native audit checkpoint|public.key/i);
});

test("anchor rejects forged, rolled-back, and locally corrupted records", () => {
  const value = fixture();
  const forged = { ...value.first, entries: value.first.entries + 1 };
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", forged), /signature|hash/i);

  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /chain origin/i);
  submitAnchorCheckpoint(value.anchor, "host-one", value.first);
  submitAnchorCheckpoint(value.anchor, "host-one", value.second);
  const rollbackStatement = {
    version: 1,
    created_at: new Date().toISOString(),
    entries: value.first.entries,
    head_hash: value.first.head_hash,
    previous_checkpoint_hash: value.second.checkpoint_hash
  };
  const signature = crypto.sign(null, Buffer.from(JSON.stringify(rollbackStatement)), fs.readFileSync(path.join(value.host, "audit", "checkpoint.pem"))).toString("base64");
  const rollback = { ...rollbackStatement, public_key_fingerprint: publicKeyFingerprint(value.identity.public_key), signature };
  rollback.checkpoint_hash = crypto.createHash("sha256").update(JSON.stringify(rollback)).digest("hex");
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", rollback), /rollback/i);

  const recordsFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl");
  const records = fs.readFileSync(recordsFile, "utf8").trim().split("\n").map(JSON.parse);
  records[0].receipt.signature = `${records[0].receipt.signature.slice(0, -2)}AA`;
  fs.writeFileSync(recordsFile, `${records.map(JSON.stringify).join("\n")}\n`, { mode: 0o600 });
  assert.throws(() => verifyAnchorTenant(value.anchor, "host-one"), /signature|hash/i);
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.second), /signature|hash/i);
});

test("client pushes checkpoints in order, verifies receipts, and retries safely", async (t) => {
  const value = fixture();
  const server = createAnchorServer(value.anchor);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const config = {
    audit_signing: { public_key: value.identity.public_key },
    audit_anchor: {
      url: `http://127.0.0.1:${address.port}`,
      tenant: "host-one",
      public_key: fs.readFileSync(value.initialized.public_file, "utf8")
    }
  };

  await assert.rejects(anchorPendingCheckpoints(config, value.host), /requires HTTPS/);
  const pushed = await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  assert.equal(pushed.anchored, 2);
  assert.equal(verifyStoredAnchorReceipts(config, value.host).receipts, 2);

  audit({ operation: "test.three", decision: "allow" }, value.host);
  const third = createAuditCheckpoint(value.identity.public_key, value.host);
  const accepted = await fetch(`${config.audit_anchor.url}/v1/checkpoints/host-one`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ checkpoint: third })
  });
  assert.equal(accepted.status, 200);
  assert.equal(readAnchorReceipts(value.host).length, 2, "simulates losing the response before local persistence");
  const retried = await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  assert.equal(retried.anchored, 1);
  assert.equal(verifyAnchorTenant(value.anchor, "host-one").records, 3);
});

test("stored receipt tampering fails closed", async (t) => {
  const value = fixture();
  const server = createAnchorServer(value.anchor);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = {
    audit_signing: { public_key: value.identity.public_key },
    audit_anchor: {
      url: `http://127.0.0.1:${server.address().port}`,
      tenant: "host-one",
      public_key: fs.readFileSync(value.initialized.public_file, "utf8")
    }
  };
  await anchorPendingCheckpoints(config, value.host, { allowHttp: true });
  const receiptFile = path.join(value.host, "anchor.receipts.jsonl");
  const receipts = readAnchorReceipts(value.host);
  receipts[0].checkpoint_hash = "f".repeat(64);
  fs.writeFileSync(receiptFile, `${receipts.map(JSON.stringify).join("\n")}\n`, { mode: 0o600 });
  assert.throws(() => verifyStoredAnchorReceipts(config, value.host), /checkpoint mismatch|signature|hash/i);
  await assert.rejects(anchorPendingCheckpoints(config, value.host, { allowHttp: true }), /checkpoint mismatch|signature|hash/i);
});

test("anchor private/public key substitution is rejected", () => {
  const first = fixture();
  const second = fixture();
  fs.copyFileSync(second.initialized.public_file, first.initialized.public_file);
  assert.throws(() => createAnchorServer(first.anchor), /do not match/);
});

test("tenant append locking rejects a live writer and recovers a dead lease", () => {
  const value = fixture();
  const lockFile = path.join(value.anchor, "tenants", "host-one", "records.jsonl.lock");
  fs.writeFileSync(lockFile, JSON.stringify({ pid: process.pid, nonce: "active", created_at: Date.now() }), { mode: 0o600 });
  assert.throws(() => submitAnchorCheckpoint(value.anchor, "host-one", value.first), /Another anchor process/);
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 2_147_483_647, nonce: "dead", created_at: 0 }), { mode: 0o600 });
  assert.equal(submitAnchorCheckpoint(value.anchor, "host-one", value.first).index, 1);
  assert.equal(fs.existsSync(lockFile), false);
});

test("checkpoint list remains independently readable", () => {
  const value = fixture();
  assert.deepEqual(readAuditCheckpoints(value.host).map((item) => item.checkpoint_hash), [value.first.checkpoint_hash, value.second.checkpoint_hash]);
});
