import crypto from "node:crypto";
import fs from "node:fs";
import { auditPath, auditPrivateKeyPath, checkpointPath, secureMkdir } from "./config.mjs";

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function audit(event, dir) {
  secureMkdir(dir);
  const file = auditPath(dir);
  const lock = `${file}.lock`;
  acquireLock(lock);
  try {
  const existing = verifyAudit(dir);
  if (!existing.valid) throw new Error(`Audit log integrity check failed at entry ${existing.invalid_entry}`);
  let previous = "0".repeat(64);
  if (fs.existsSync(file)) {
    const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
    if (lines.length) previous = JSON.parse(lines.at(-1)).hash;
  }
  const record = { timestamp: new Date().toISOString(), previous_hash: previous, ...event };
  record.hash = digest(record);
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch {}
  return record;
  } finally {
    try { fs.unlinkSync(lock); } catch {}
  }
}

export function verifyAudit(dir) {
  const file = auditPath(dir);
  if (!fs.existsSync(file)) return { valid: true, entries: 0, head_hash: "0".repeat(64) };
  const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
  let previous = "0".repeat(64);
  for (let index = 0; index < lines.length; index += 1) {
    let record;
    try { record = JSON.parse(lines[index]); }
    catch { return { valid: false, entries: lines.length, invalid_entry: index + 1, head_hash: previous }; }
    const expected = record.hash;
    const copy = { ...record };
    delete copy.hash;
    if (record.previous_hash !== previous || digest(copy) !== expected) {
      return { valid: false, entries: lines.length, invalid_entry: index + 1, head_hash: previous };
    }
    previous = expected;
  }
  return { valid: true, entries: lines.length, head_hash: previous };
}

export function createAuditCheckpoint(publicKey, dir) {
  const lock = `${auditPath(dir)}.lock`;
  acquireLock(lock);
  try {
    const verified = verifyAudit(dir);
    if (!verified.valid) throw new Error(`Audit log integrity check failed at entry ${verified.invalid_entry}`);
    const checkpoints = verifyAuditCheckpoints(publicKey, dir);
    if (!checkpoints.valid) throw new Error(`Audit checkpoint integrity check failed at checkpoint ${checkpoints.invalid_checkpoint ?? "unknown"}`);
    const privateFile = auditPrivateKeyPath(dir);
    assertPrivateKey(privateFile);
    const checkpointFile = checkpointPath(dir);
    const statement = {
      version: 1,
      created_at: new Date().toISOString(),
      entries: verified.entries,
      head_hash: verified.head_hash,
      previous_checkpoint_hash: checkpoints.latest ?? "0".repeat(64)
    };
    const signature = crypto.sign(null, checkpointBytes(statement), fs.readFileSync(privateFile)).toString("base64");
    if (!crypto.verify(null, checkpointBytes(statement), publicKey, Buffer.from(signature, "base64"))) throw new Error("Audit checkpoint private key does not match the configured public key");
    const record = { ...statement, public_key_fingerprint: publicKeyFingerprint(publicKey), signature };
    record.checkpoint_hash = digest(record);
    fs.appendFileSync(checkpointFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    fs.chmodSync(checkpointFile, 0o600);
    return record;
  } finally {
    try { fs.unlinkSync(lock); } catch {}
  }
}

export function verifyAuditCheckpoints(publicKey, dir) {
  const auditResult = verifyAudit(dir);
  if (!auditResult.valid) return { valid: false, checkpoints: 0, reason: "audit_invalid", invalid_entry: auditResult.invalid_entry };
  const checkpointFile = checkpointPath(dir);
  if (!fs.existsSync(checkpointFile)) return { valid: true, checkpoints: 0, latest: null };
  const auditHashes = readAuditHashes(dir);
  const lines = fs.readFileSync(checkpointFile, "utf8").trim().split("\n").filter(Boolean);
  let previous = "0".repeat(64);
  for (let index = 0; index < lines.length; index += 1) {
    let record;
    try { record = JSON.parse(lines[index]); }
    catch { return invalidCheckpoint(lines.length, index, "invalid_json"); }
    let verified;
    try { verified = verifyCheckpointRecord(record, publicKey, { previousCheckpointHash: previous }); }
    catch (error) { return invalidCheckpoint(lines.length, index, error.code ?? "checkpoint_invalid"); }
    if (auditHashes[verified.entries] !== verified.head_hash) return invalidCheckpoint(lines.length, index, "audit_head_mismatch");
    previous = verified.checkpoint_hash;
  }
  return { valid: true, checkpoints: lines.length, latest: previous };
}

export function readAuditCheckpoints(dir) {
  const file = checkpointPath(dir);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

export function verifyCheckpointRecord(record, publicKey, { previousCheckpointHash } = {}) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw checkpointError("invalid_record");
  let verificationKey;
  try { verificationKey = publicKey instanceof crypto.KeyObject && publicKey.type === "public" ? publicKey : crypto.createPublicKey(publicKey); }
  catch { throw checkpointError("public_key_invalid"); }
  if (verificationKey.asymmetricKeyType !== "ed25519") throw checkpointError("public_key_invalid");
  const statement = {
    version: record.version,
    created_at: record.created_at,
    entries: record.entries,
    head_hash: record.head_hash,
    previous_checkpoint_hash: record.previous_checkpoint_hash
  };
  if (statement.version !== 1 || !Number.isFinite(Date.parse(statement.created_at))) throw checkpointError("invalid_statement");
  if (!Number.isInteger(statement.entries) || statement.entries < 0 || !/^[0-9a-f]{64}$/.test(statement.head_hash ?? "") || !/^[0-9a-f]{64}$/.test(statement.previous_checkpoint_hash ?? "")) throw checkpointError("invalid_statement");
  if (previousCheckpointHash !== undefined && statement.previous_checkpoint_hash !== previousCheckpointHash) throw checkpointError("checkpoint_chain_invalid");
  if (record.public_key_fingerprint !== publicKeyFingerprint(verificationKey)) throw checkpointError("public_key_mismatch");
  if (typeof record.signature !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(record.signature)) throw checkpointError("signature_encoding_invalid");
  let signatureValid = false;
  try {
    const signature = Buffer.from(record.signature, "base64");
    signatureValid = signature.length === 64 && crypto.verify(null, checkpointBytes(statement), verificationKey, signature);
  } catch {}
  if (!signatureValid) throw checkpointError("signature_invalid");
  const copy = { ...statement, public_key_fingerprint: record.public_key_fingerprint, signature: record.signature };
  if (digest(copy) !== record.checkpoint_hash) throw checkpointError("checkpoint_hash_invalid");
  return { ...copy, checkpoint_hash: record.checkpoint_hash };
}

export function publicKeyFingerprint(publicKey) {
  const key = publicKey instanceof crypto.KeyObject && publicKey.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  const der = key.export({ type: "spki", format: "der" });
  return `SHA256:${crypto.createHash("sha256").update(der).digest("base64url")}`;
}

function checkpointBytes(statement) {
  return Buffer.from(JSON.stringify(statement));
}

function readAuditHashes(dir) {
  const hashes = ["0".repeat(64)];
  const file = auditPath(dir);
  if (!fs.existsSync(file)) return hashes;
  for (const line of fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean)) hashes.push(JSON.parse(line).hash);
  return hashes;
}

function invalidCheckpoint(total, index, reason) {
  return { valid: false, checkpoints: total, invalid_checkpoint: index + 1, reason };
}

function checkpointError(code) {
  const error = new Error(`Audit checkpoint is invalid: ${code}`);
  error.code = code;
  return error;
}

function assertPrivateKey(file) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Audit checkpoint key must be a regular file");
  if (uid !== undefined && stat.uid !== uid) throw new Error("Audit checkpoint key is not owned by the current user");
  if ((stat.mode & 0o077) !== 0) throw new Error("Audit checkpoint key permissions are too permissive");
}

function acquireLock(lock) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const fd = fs.openSync(lock, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, created_at: Date.now() }));
      fs.closeSync(fd);
      return;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      recoverStaleLock(lock);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  throw new Error(`Audit log is busy: ${lock}`);
}

function recoverStaleLock(lock) {
  try {
    const lease = JSON.parse(fs.readFileSync(lock, "utf8"));
    if (!Number.isInteger(lease.pid) || Date.now() - lease.created_at < 10_000) return;
    try {
      process.kill(lease.pid, 0);
    } catch (error) {
      if (error.code === "ESRCH") fs.unlinkSync(lock);
    }
  } catch {}
}
