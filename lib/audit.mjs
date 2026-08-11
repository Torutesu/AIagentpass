import crypto from "node:crypto";
import fs from "node:fs";
import { auditPath, secureMkdir } from "./config.mjs";

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function audit(event, dir) {
  secureMkdir(dir);
  const file = auditPath(dir);
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
}

export function verifyAudit(dir) {
  const file = auditPath(dir);
  if (!fs.existsSync(file)) return { valid: true, entries: 0 };
  const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
  let previous = "0".repeat(64);
  for (let index = 0; index < lines.length; index += 1) {
    const record = JSON.parse(lines[index]);
    const expected = record.hash;
    const copy = { ...record };
    delete copy.hash;
    if (record.previous_hash !== previous || digest(copy) !== expected) {
      return { valid: false, entries: lines.length, invalid_entry: index + 1 };
    }
    previous = expected;
  }
  return { valid: true, entries: lines.length };
}
