import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const source = fs.readFileSync(path.join(root, "native/macos/Sources/AgentPassNativeService/main.swift"), "utf8");

test("native service verifies the frozen XPC contract before opening listeners", () => {
  const configuration = source.indexOf("let configuration = try ServiceConfiguration.load");
  const verification = source.indexOf("try AgentPassNativeXPCContract.verifyRuntimeSurface()", configuration);
  const listener = source.indexOf("let managementListener = NSXPCListener", configuration);
  const resume = source.indexOf("managementListener.resume()", listener);
  assert.ok(configuration >= 0 && verification > configuration && listener > verification && resume > listener);
  assert.equal(source.match(/AgentPassNativeXPCContract\.verifyRuntimeSurface\(\)/g)?.length, 1);
});
