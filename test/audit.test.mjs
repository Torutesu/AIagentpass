import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { audit, verifyAudit } from "../lib/audit.mjs";

test("audit log is hash chained and detects tampering", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-audit-"));
  audit({ operation: "test.one", decision: "allow" }, dir);
  audit({ operation: "test.two", decision: "deny" }, dir);
  assert.deepEqual(verifyAudit(dir), { valid: true, entries: 2 });
  const file = path.join(dir, "audit.jsonl");
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  lines[0] = lines[0].replace("test.one", "tampered");
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
  assert.equal(verifyAudit(dir).valid, false);
});
