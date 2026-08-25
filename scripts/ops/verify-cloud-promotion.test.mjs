import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const script = new URL("./verify-cloud-promotion.mjs", import.meta.url).pathname;

test("promotion verifier requires both deployment and KMS evidence inputs", async () => {
  await assert.rejects(run(process.execPath, [script]), (error) => {
    assert.equal(error.code, 2);
    assert.equal(error.stderr, "cloud-promotion-verify: invalid_arguments\n");
    return true;
  });
});
