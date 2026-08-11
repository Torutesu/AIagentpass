import crypto from "node:crypto";
import fs from "node:fs";
import { anchorReceiptPath } from "./config.mjs";
import { readAuditCheckpoints, verifyAuditCheckpoints } from "./audit.mjs";
import { verifyAnchorReceipt } from "./anchor.mjs";

const MAX_RESPONSE_BYTES = 512 * 1024;
const ZERO_HASH = "0".repeat(64);

export async function anchorPendingCheckpoints(config, dir, { fetchImpl = fetch, allowHttp = false } = {}) {
  if (!config.audit_anchor) throw new Error("No audit anchor is configured");
  const lock = `${anchorReceiptPath(dir)}.lock`;
  const lease = acquireLock(lock);
  try {
    const localVerification = verifyAuditCheckpoints(config.audit_signing.public_key, dir);
    if (!localVerification.valid) throw new Error("Local audit checkpoints are invalid");
    const checkpoints = readAuditCheckpoints(dir);
    if (!checkpoints.length) throw new Error("No audit checkpoint exists");
    const receipts = readAnchorReceipts(dir);
    verifyStoredReceipts(receipts, checkpoints, config.audit_anchor);
    const anchored = [];
    let previousReceiptHash = receipts.at(-1)?.receipt_hash ?? ZERO_HASH;
    for (let index = receipts.length; index < checkpoints.length; index += 1) {
      const receipt = await postCheckpoint(config.audit_anchor, checkpoints[index], { fetchImpl, allowHttp });
      const verified = verifyAnchorReceipt(receipt, config.audit_anchor.public_key, { tenant: config.audit_anchor.tenant, checkpointHash: checkpoints[index].checkpoint_hash, previousReceiptHash });
      if (verified.index !== index + 1) throw new Error("Anchor receipt index does not match local checkpoint order");
      appendReceipt(verified, dir);
      anchored.push(verified);
      previousReceiptHash = verified.receipt_hash;
    }
    return { anchored: anchored.length, receipts: receipts.length + anchored.length, latest: previousReceiptHash === ZERO_HASH ? null : previousReceiptHash };
  } finally {
    releaseLock(lock, lease);
  }
}

export function verifyStoredAnchorReceipts(config, dir) {
  if (!config.audit_anchor) return { valid: true, receipts: 0, latest: null };
  const localVerification = verifyAuditCheckpoints(config.audit_signing.public_key, dir);
  if (!localVerification.valid) throw new Error("Local audit checkpoints are invalid");
  const checkpoints = readAuditCheckpoints(dir);
  const receipts = readAnchorReceipts(dir);
  verifyStoredReceipts(receipts, checkpoints, config.audit_anchor);
  return { valid: true, checkpoints: checkpoints.length, receipts: receipts.length, pending: checkpoints.length - receipts.length, latest: receipts.at(-1)?.receipt_hash ?? null };
}

export function readAnchorReceipts(dir) {
  const file = anchorReceiptPath(dir);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

async function postCheckpoint(anchor, checkpoint, { fetchImpl, allowHttp }) {
  const base = new URL(anchor.url.endsWith("/") ? anchor.url : `${anchor.url}/`);
  if (base.protocol !== "https:" && !(allowHttp && base.protocol === "http:")) throw new Error("Audit anchor requires HTTPS");
  const endpoint = new URL(`v1/checkpoints/${encodeURIComponent(anchor.tenant)}`, base);
  const response = await fetchImpl(endpoint, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ checkpoint })
  });
  if (!response.ok) {
    const detail = await boundedResponse(response).catch(() => null);
    throw new Error(`Audit anchor returned HTTP ${response.status}${detail?.error ? `: ${detail.error}` : ""}`);
  }
  const parsed = await boundedResponse(response);
  if (!parsed?.receipt) throw new Error("Audit anchor response is missing a receipt");
  return parsed.receipt;
}

async function boundedResponse(response) {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > MAX_RESPONSE_BYTES) throw new Error("Audit anchor response is too large");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > MAX_RESPONSE_BYTES) throw new Error("Audit anchor response size is invalid");
  try { return JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("Audit anchor response contains invalid JSON"); }
}

function verifyStoredReceipts(receipts, checkpoints, anchor) {
  if (receipts.length > checkpoints.length) throw new Error("Anchor receipt log is longer than the local checkpoint log");
  let previous = ZERO_HASH;
  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = verifyAnchorReceipt(receipts[index], anchor.public_key, { tenant: anchor.tenant, checkpointHash: checkpoints[index].checkpoint_hash, previousReceiptHash: previous });
    if (receipt.index !== index + 1) throw new Error("Anchor receipt index is invalid");
    previous = receipt.receipt_hash;
  }
}

function appendReceipt(receipt, dir) {
  const file = anchorReceiptPath(dir);
  const fd = fs.openSync(file, "a", 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(receipt)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(file, 0o600);
}

function acquireLock(lock) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const lease = { pid: process.pid, nonce: crypto.randomBytes(16).toString("hex"), created_at: Date.now() };
    try {
      const fd = fs.openSync(lock, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify(lease));
      fs.closeSync(fd);
      return lease;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let existing;
      try { existing = JSON.parse(fs.readFileSync(lock, "utf8")); } catch { throw new Error("Audit anchor receipt lock is invalid; inspect it before removal"); }
      if (!Number.isInteger(existing.pid)) throw new Error("Audit anchor receipt lock is invalid; inspect it before removal");
      try {
        process.kill(existing.pid, 0);
        throw new Error("Another audit anchor operation is running");
      } catch (probeError) {
        if (probeError.code !== "ESRCH") throw probeError;
        const stat = fs.lstatSync(lock);
        const uid = process.getuid?.();
        if (!stat.isFile() || stat.isSymbolicLink() || (uid !== undefined && stat.uid !== uid)) throw new Error("Refusing to replace an unsafe audit anchor receipt lock");
        fs.unlinkSync(lock);
      }
    }
  }
  throw new Error("Unable to acquire the audit anchor receipt lock");
}

function releaseLock(lock, lease) {
  try {
    const current = JSON.parse(fs.readFileSync(lock, "utf8"));
    if (current.pid === lease.pid && current.nonce === lease.nonce) fs.unlinkSync(lock);
  } catch {}
}
