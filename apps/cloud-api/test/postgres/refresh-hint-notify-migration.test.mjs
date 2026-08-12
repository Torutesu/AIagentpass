import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0014_refresh_hint_notify.sql", import.meta.url);

test("0014 publishes only routing metadata on the notifier's static channel after outbox insert", async () => {
  const sql = await fs.readFile(migrationUrl, "utf8");
  assert.match(sql, /pg_notify\('agentpass_refresh_hint_v1'/u);
  assert.match(sql, /'organization_id', NEW\.organization_id/u);
  assert.match(sql, /'device_id', NEW\.device_id/u);
  assert.match(sql, /'desired_generation', NEW\.desired_generation/u);
  assert.match(sql, /AFTER INSERT ON device_refresh_outbox/u);
  assert.doesNotMatch(sql, /nonce|digest|secret|signature|policy_scope/iu);
});
