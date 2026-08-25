import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(new URL('../../../../', import.meta.url).pathname);
const dir = path.join(root, 'contracts/postgres');
const files = Array.from({ length: 8 }, (_, i) => `${String(119 + i).padStart(4, '0')}_`);

test('SSC Wave 1 Lane A has a contiguous transactional 0119-0126 migration range', async () => {
  const names = (await fs.readdir(dir)).filter((n) => /^01(?:1[9]|2[0-6])_.*\.sql$/.test(n)).sort();
  assert.equal(names.length, 8);
  for (const prefix of files) {
    const name = names.find((n) => n.startsWith(prefix));
    assert.ok(name, `missing migration ${prefix}`);
    const sql = await fs.readFile(path.join(dir, name), 'utf8');
    assert.match(sql, /^BEGIN;/);
    assert.match(sql, /COMMIT;\s*$/);
    assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE\s/i);
    assert.match(sql, /organization_id/);
  }
});

test('authority functions are SECURITY DEFINER and direct DML is revoked', async () => {
  const sql = await Promise.all(files.map(async (prefix) => {
    const name = (await fs.readdir(dir)).find((n) => n.startsWith(prefix));
    return fs.readFile(path.join(dir, name), 'utf8');
  })).then((parts) => parts.join('\n'));
  for (const fn of ['reserve_app', 'reserve_release', 'reserve_provider_operation', 'approve', 'reconcile_deployment', 'activate_route', 'suspend', 'expire', 'rollback', 'delete_reservation']) {
    assert.match(sql, new RegExp(`agentpass_small_software_${fn}`));
  }
  assert.match(sql, /SECURITY DEFINER/);
  assert.match(sql, /REVOKE ALL ON TABLE[\s\S]*small_software_apps/);
});
