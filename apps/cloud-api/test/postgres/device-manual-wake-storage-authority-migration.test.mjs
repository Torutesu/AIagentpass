import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0114_device_manual_wake_storage_authority.sql", import.meta.url);

test("0114 grants the online role only the manual wake ledger boundary", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.device_manual_wake_events,[\s\S]*public\.device_manual_wake_requests/u);
  assert.match(sql, /GRANT SELECT, INSERT, UPDATE ON TABLE public\.device_manual_wake_events,[\s\S]*public\.device_manual_wake_requests TO agentpass_app/u);
  assert.match(sql, /GRANT SELECT ON TABLE public\.memberships TO agentpass_app/u);
  assert.doesNotMatch(sql, /GRANT .* ON TABLE public\.(?:human_sessions|webauthn_credentials|webauthn_challenges)/u);
});
