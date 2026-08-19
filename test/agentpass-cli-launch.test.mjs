import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { FIXED_NATIVE_HOST_LAUNCHER, launchAgentLifecycle } from "../lib/agent-lifecycle-cli.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, "bin", "agentpass.mjs");

function run(...arguments_) {
  return spawnSync(process.execPath, [cli, ...arguments_], {
    encoding: "utf8",
    env: { ...process.env, AGENTPASS_SESSION: "environment-secret-that-must-be-ignored" }
  });
}

test("launch accepts the bounded public arguments, then remains fail-closed without a native Host", () => {
  const result = run("launch", "--agent", "claude-code", "--project", "/tmp/project", "--ttl", "600");

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_NOT_AVAILABLE",
      message: "The process-bound Agent lifecycle is not available in this build"
    }
  });
});

test("launch contract failures remain stable fail-closed JSON and never echo forbidden values", () => {
  const secret = "launch-secret-must-not-appear";
  const result = run("launch", "--agent", "claude-code", "--token", secret);

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_NOT_AVAILABLE",
      message: "The process-bound Agent lifecycle is not available in this build"
    }
  });
  assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false);
});

test("launch rejects noncanonical input before the unavailable lifecycle response", () => {
  const result = run("launch", "--agent", "claude-code", "--project", "/tmp/project/../other");

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.operation, "launch");
  assert.equal(output.error.code, "AGENT_LIFECYCLE_NOT_AVAILABLE");
  assert.equal(output.error.message.includes("/tmp/project/../other"), false);
});

test("help remains successful and unknown commands remain usage failures", () => {
  const help = run("--help");
  assert.equal(help.status, 0);
  assert.match(help.stdout, /^AgentPass 0\.18\.0/u);
  assert.equal(help.stderr, "");

  const unknown = run("not-a-command");
  assert.equal(unknown.status, 2);
  assert.equal(unknown.stdout, "");
  assert.equal(unknown.stderr, "agentpass: unknown command\n");
});

function trustedLauncherStat(file) {
  if (file !== FIXED_NATIVE_HOST_LAUNCHER) {
    return {
      isFile: () => false,
      isDirectory: () => true,
      isSymbolicLink: () => false,
      nlink: 1,
      uid: 0,
      mode: 0o40755
    };
  }
  return {
    isFile: () => true,
    isSymbolicLink: () => false,
    nlink: 1,
    uid: 0,
    mode: 0o100755
  };
}

test("macOS lifecycle invokes only the fixed Native Host with the canonical project and inherited FD3", () => {
  const calls = [];
  const result = launchAgentLifecycle(
    { agent: "claude-code", project: "/tmp/project", ttl_seconds: 600 },
    {
      platform: "darwin",
      lstat: (file) => trustedLauncherStat(file),
      handoffAvailable: true,
      run: (launcher, launchArgs) => {
        calls.push({ launcher, launchArgs });
        return {
          status: 0,
          stdout: '{"error":null,"ok":true,"operation":"host-launch","status":"active"}\n{"error":null,"ok":true,"operation":"host-launch","status":"closed"}\n'
        };
      }
    }
  );

  assert.deepEqual(result, { ok: true, operation: "launch", status: "closed" });
  assert.deepEqual(calls, [{ launcher: FIXED_NATIVE_HOST_LAUNCHER, launchArgs: ["launch", "/tmp/project"] }]);
});

test("macOS lifecycle fails closed when the one-time FD3 handoff is absent", () => {
  const result = launchAgentLifecycle(
    { agent: "claude-code", project: "/tmp/project", ttl_seconds: 600 },
    { platform: "darwin", lstat: (file) => trustedLauncherStat(file), handoffAvailable: false }
  );

  assert.deepEqual(result, {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_HANDOFF_NOT_AVAILABLE",
      message: "The one-time Native Host handoff is not available"
    }
  });
});

test("macOS lifecycle rejects launcher substitution and malformed Host output", () => {
  const untrusted = launchAgentLifecycle(
    { agent: "claude-code", project: "/tmp/project", ttl_seconds: 600 },
    { platform: "darwin", launcher: "/tmp/agentpass-native-agent-host", lstat: (file) => trustedLauncherStat(file), handoffAvailable: true }
  );
  assert.equal(untrusted.error.code, "AGENT_LIFECYCLE_NATIVE_HOST_REJECTED");

  const malformed = launchAgentLifecycle(
    { agent: "claude-code", project: "/tmp/project", ttl_seconds: 600 },
    {
      platform: "darwin",
      lstat: (file) => trustedLauncherStat(file),
      handoffAvailable: true,
      run: () => ({ status: 0, stdout: '{"error":null,"ok":true,"operation":"host-launch","status":"active"}\n' })
    }
  );
  assert.deepEqual(malformed, {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_NATIVE_HOST_REJECTED",
      message: "The Native Host returned an invalid launch result"
    }
  });
});

test("macOS lifecycle rejects a replaceable Native Host ancestry", () => {
  const replacedDirectory = "/Applications/AgentPass.app/Contents/Library";
  const result = launchAgentLifecycle(
    { agent: "claude-code", project: "/tmp/project", ttl_seconds: 600 },
    {
      platform: "darwin",
      lstat: (file) => file === replacedDirectory
        ? { isFile: () => false, isDirectory: () => false, isSymbolicLink: () => true, nlink: 1, uid: 0, mode: 0o120777 }
        : trustedLauncherStat(file),
      handoffAvailable: true
    }
  );
  assert.equal(result.error.code, "AGENT_LIFECYCLE_NATIVE_HOST_REJECTED");
});
