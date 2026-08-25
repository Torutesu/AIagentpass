import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runSmallSoftwareCli } from "../../../lib/small-software-cli.mjs";

async function fixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-ssc-"));
  await fs.writeFile(path.join(root, "agentpass.app.json"), JSON.stringify({ version: 1, kind: "agentpass.app-manifest", name: "demo", runtime: "cloudflare-worker", entrypoint: "worker.js", data: [], egress: [], connections: [], schedules: [] }));
  await fs.writeFile(path.join(root, "worker.js"), "export default {};\n");
  return root;
}

test("small software CLI emits bounded plan-only inspect/bundle/prepare/publish results", async () => {
  const root = await fixture();
  const inspect = runSmallSoftwareCli("inspect", ["--path", root]);
  assert.equal(inspect.status, "plan_only");
  assert.equal(inspect.manifest.value.name, "demo");
  assert.match(inspect.file_inventory_digest, /^[0-9a-f]{64}$/);
  assert.equal(runSmallSoftwareCli("bundle", ["--path", root]).mutation, "none");
  assert.equal(runSmallSoftwareCli("prepare", ["--path", root]).approval_required, true);
  assert.equal(runSmallSoftwareCli("publish", ["--path", root, "--plan-only"]).deployment, "not_started");
});

test("small software CLI rejects live publish and unsafe symlinks", async () => {
  const root = await fixture();
  assert.throws(() => runSmallSoftwareCli("publish", ["--path", root]), /--plan-only/);
  await fs.symlink(path.join(root, "worker.js"), path.join(root, "link.js"));
  assert.throws(() => runSmallSoftwareCli("inspect", ["--path", root]), /symlinks/);
});
