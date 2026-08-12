import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0015_refresh_state_rollover.sql", import.meta.url);

test("0015 starts each desired generation with clean delivery observations", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /advances_generation := request_desired_generation > existing_state\.desired_generation/u);
  assert.match(sql, /refresh_state = CASE WHEN advances_generation THEN 'pending'/u);
  assert.match(sql, /last_delivered_at = CASE WHEN advances_generation THEN NULL/u);
  assert.match(sql, /last_observed_at = CASE WHEN advances_generation THEN NULL/u);
  assert.match(sql, /last_error_code = CASE WHEN advances_generation THEN NULL/u);
  assert.match(sql, /request_desired_generation < existing_state\.desired_generation/u);
});
