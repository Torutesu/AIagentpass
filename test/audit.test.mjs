import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { audit, createAuditCheckpoint, verifyAudit, verifyAuditCheckpoints } from "../lib/audit.mjs";
import { createAuditIdentity } from "../lib/identity.mjs";

test("audit log is hash chained and detects tampering", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-audit-"));
  audit({ operation: "test.one", decision: "allow" }, dir);
  audit({ operation: "test.two", decision: "deny" }, dir);
  const verified = verifyAudit(dir);
  assert.equal(verified.valid, true);
  assert.equal(verified.entries, 2);
  assert.match(verified.head_hash, /^[0-9a-f]{64}$/);
  const file = path.join(dir, "audit.jsonl");
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  lines[0] = lines[0].replace("test.one", "tampered");
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
  assert.equal(verifyAudit(dir).valid, false);
});

test("audit checkpoints sign and chain an exact audit head", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-checkpoint-"));
  const identity = createAuditIdentity(dir);
  audit({ operation: "test.one", decision: "allow" }, dir);
  const first = createAuditCheckpoint(identity.public_key, dir);
  audit({ operation: "test.two", decision: "allow" }, dir);
  const second = createAuditCheckpoint(identity.public_key, dir);
  assert.equal(second.previous_checkpoint_hash, first.checkpoint_hash);
  assert.deepEqual(verifyAuditCheckpoints(identity.public_key, dir), { valid: true, checkpoints: 2, latest: second.checkpoint_hash });

  const file = path.join(dir, "audit.checkpoints.jsonl");
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  lines[0] = lines[0].replace('"entries":1', '"entries":0');
  fs.writeFileSync(file, `${lines.join("\n")}\n`, { mode: 0o600 });
  assert.equal(verifyAuditCheckpoints(identity.public_key, dir).valid, false);
});

test("checkpoint creation fails closed when the configured public key does not match", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-checkpoint-key-"));
  createAuditIdentity(dir);
  audit({ operation: "test.one", decision: "allow" }, dir);
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const unrelated = publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.throws(() => createAuditCheckpoint(unrelated, dir), /does not match/);
  assert.equal(fs.existsSync(path.join(dir, "audit.checkpoints.jsonl")), false);
});
