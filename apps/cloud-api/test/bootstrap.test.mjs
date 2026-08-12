import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { bootstrapCloud } from "../src/bootstrap.mjs";
import { createCloudStore } from "../src/store.mjs";

test("bootstrap creates one owner, one-time token output, and protected credentials", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-bootstrap-parent-"));
  const outputDir = path.join(root, "cloud");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = await bootstrapCloud({ outputDir, organizationName: "Acme", principalId: "siwc-user-1" });
  assert.match(result.api_token, /^ap_/);
  assert.equal(fs.statSync(result.token_records_path).mode & 0o777, 0o600);
  assert.equal(fs.statSync(result.bundle_private_key_path).mode & 0o777, 0o600);
  const store = await createCloudStore({ dataDir: result.data_dir });
  assert.equal((await store.getOrganization({ organizationId: result.organization_id })).name, "Acme");
  assert.equal((await store.listMemberships({ organizationId: result.organization_id }))[0].role, "owner");
  await store.close();
  await assert.rejects(bootstrapCloud({ outputDir, organizationName: "Other", principalId: "siwc-user-2" }));
});
