import fs from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { normalGitSigningContract, runNormalGitSigningHarness } from "./normal-git-signing-harness.mjs";

test("real Git commit -S uses the one-payload AgentPass helper contract", () => {
  const result = runNormalGitSigningHarness();
  try {
    assert.ok(result.commit.includes("-----BEGIN SSH SIGNATURE-----"));
    assert.equal(result.invocations.length, 1);
    const [args] = result.invocations;
    assert.equal(args.length, normalGitSigningContract.argumentCount);
    assert.deepEqual(args.slice(0, 6), normalGitSigningContract.arguments.slice(0, 6));
    assert.ok(args[6].startsWith("/"));
    assert.equal(args.some((value) => normalGitSigningContract.sessionArgumentsForbidden.includes(value)), false);
    // Git must receive an opaque marker, never a private-key path or key data.
    assert.equal(args[5], "agentpass-managed");
    assert.notEqual(args[5], pathFromFixture(result.root));
  } finally {
    fs.rmSync(result.root, { recursive: true, force: true });
  }
});

test("the normal Git harness keeps the versioned session entrypoint separate", () => {
  assert.deepEqual(normalGitSigningContract.arguments.slice(0, 6), [
    "-Y", "sign", "-n", "git", "-f", "agentpass-managed",
  ]);
  assert.deepEqual(normalGitSigningContract.sessionArgumentsForbidden, ["--protocol", "--payload"]);
});

test("normal Git signing fails closed for a caller-supplied key path", () => {
  assert.throws(
    () => runNormalGitSigningHarness({ signerReference: "/tmp/attacker-private-key" }),
    /invalid AgentPass Git signing invocation/,
  );
});

function pathFromFixture(root) {
  return `${root}/fixture-signing-key`;
}
