import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
const root = path.resolve("contracts/postgres");
test("maintenance migrations occupy the reserved contiguous range", () => {
  const names = fs.readdirSync(root).filter((name) => /^(012[7-9]|013[0-6])_.*\.sql$/.test(name)).sort();
  assert.equal(names.length, 10);
  assert.deepEqual(names.map((name) => Number(name.slice(0, 4))), [127,128,129,130,131,132,133,134,135,136]);
});
test("maintenance authority is function-only and advisory/effect state is immutable by app", () => {
  const sql = names => names.map((name) => fs.readFileSync(path.join(root, name), "utf8")).join("\n");
  const text = sql(fs.readdirSync(root).filter((name) => /^(012[7-9]|013[0-6])_.*\.sql$/.test(name)));
  assert.match(text, /SECURITY DEFINER/);
  assert.match(text, /REVOKE ALL ON FUNCTION[\s\S]*agentpass_app/);
  assert.match(text, /REVOKE ALL ON public\.maintenance_advisories[\s\S]*agentpass_app/);
  assert.match(text, /compromised_at IS NULL/);
  assert.match(text, /UNIQUE\(job_id,effect_kind,idempotency_key\)/);
});
