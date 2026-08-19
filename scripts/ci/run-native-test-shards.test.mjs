import assert from "node:assert/strict";
import test from "node:test";
import { NATIVE_TEST_TARGETS, nativeShardCommand, nativeTestIdentifierCommand, runNativeTestShards } from "./run-native-test-shards.mjs";

test("keeps the native shard inventory closed and target filters exact", () => {
  assert.deepEqual([...NATIVE_TEST_TARGETS], [
    "AgentPassAppTests",
    "AgentPassNativeCoreTests",
    "AgentPassNativeServiceSupportTests",
    "AgentPassNativeServiceTests",
    "AgentPassOnboardingUITests",
    "AgentPassQualificationGrantClientTests"
  ]);
  const command = nativeShardCommand("AgentPassNativeCoreTests");
  assert.equal(command.command, process.execPath);
  assert.deepEqual(command.args.slice(-2), ["--filter", "^AgentPassNativeCoreTests\\."]);
  assert.throws(() => nativeShardCommand("NotARealTarget"), /unknown native test target/u);
  assert.match(nativeTestIdentifierCommand("AgentPassNativeServiceTests.hostEndpointRequiresDedicatedSignerByDefault").args.at(-1), /^\^AgentPassNativeServiceTests\\\.hostEndpointRequiresDedicatedSignerByDefault\$$/u);
});

test("runs every native target as an independent bounded child and aggregates failures", async () => {
  const calls = [];
  const results = await runNativeTestShards({
    cwd: "/repo",
    timeoutMs: 1234,
    run: async (command, args, options) => {
      calls.push({ command, args, options });
      return { exitCode: args.some((value) => value.includes("AgentPassNativeServiceTests")) ? 9 : 0, reason: "test" };
    },
    listTests: async () => []
  });
  assert.equal(calls.length, NATIVE_TEST_TARGETS.length);
  assert.deepEqual(results.map((result) => result.target), [...NATIVE_TEST_TARGETS]);
  assert.equal(results.filter((result) => result.exitCode !== 0).length, 1);
  assert.ok(calls.every((call) => call.options.cwd === "/repo" && call.options.timeoutMs === 1234));
});

test("recovers a crashed shard only after every listed test passes independently", async () => {
  const calls = [];
  const results = await runNativeTestShards({
    run: async (command, args) => {
      calls.push(args);
      const filter = args.at(-1);
      return { exitCode: filter === "^AgentPassNativeServiceTests\\." ? 11 : 0, reason: "test" };
    },
    listTests: async ({ target }) => target === "AgentPassNativeServiceTests"
      ? ["AgentPassNativeServiceTests.hostEndpointRequiresDedicatedSignerByDefault"]
      : []
  });
  const service = results.find((result) => result.target === "AgentPassNativeServiceTests");
  assert.equal(service.exitCode, 0);
  assert.equal(service.recovered, true);
  assert.equal(service.fallbackCount, 1);
  assert.equal(calls.length, NATIVE_TEST_TARGETS.length + 1);
});
