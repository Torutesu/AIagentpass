import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { readGitSigningInvocation, writeGitSignature } from "../lib/git-signing.mjs";

test("Git signing adapter reads the final payload file and writes its .sig sibling", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-git-sign-"));
  const payloadPath = path.join(directory, "payload");
  fs.writeFileSync(payloadPath, "commit payload", { mode: 0o600 });
  const invocation = readGitSigningInvocation(["-Y", "sign", "-n", "git", "-f", "/tmp/public-key", payloadPath]);
  assert.equal(invocation.payload.toString(), "commit payload");
  assert.deepEqual(invocation.brokerArgs, ["-Y", "sign", "-n", "git", "-f", "/tmp/public-key"]);
  writeGitSignature(payloadPath, Buffer.from("signature"));
  assert.equal(fs.readFileSync(`${payloadPath}.sig`, "utf8"), "signature");
});

test("Git signing adapter rejects relative and symlink payload paths", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-git-sign-"));
  const payloadPath = path.join(directory, "payload");
  const linkPath = path.join(directory, "link");
  fs.writeFileSync(payloadPath, "payload");
  fs.symlinkSync(payloadPath, linkPath);
  assert.throws(() => readGitSigningInvocation(["relative"]), /absolute/);
  assert.throws(() => readGitSigningInvocation([linkPath]), /regular/);
});

test("agent identity signing rejects a symlinked private key", async () => {
  const { signRequest } = await import("../lib/identity.mjs");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-identity-"));
  const target = path.join(directory, "key.pem");
  const link = path.join(directory, "link.pem");
  fs.writeFileSync(target, "not a key", { mode: 0o600 });
  fs.symlinkSync(target, link);
  assert.throws(() => signRequest({ operation: "test" }, link), /regular file/);
});
