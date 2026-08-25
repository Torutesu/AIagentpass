import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const CHILD = fileURLToPath(new URL("./owner-recovery-provider-acceptance-child.mjs", import.meta.url));
const ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

export function launchOwnerRecoveryProviderAcceptanceChild({ databaseUrl, binding, leaseMs = 1_000, deadlineMs = 10_000 } = {}) {
  if (typeof databaseUrl !== "string" || !/^postgres(?:ql)?:/u.test(databaseUrl)) throw new TypeError("database URL is invalid");
  if (!binding || typeof binding.binding_id !== "string" || !Number.isSafeInteger(binding.key_version) || typeof binding.binding_digest !== "string") throw new TypeError("provider binding is invalid");
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 5 * 60_000) throw new TypeError("lease is invalid");
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 100 || deadlineMs > 60_000) throw new TypeError("deadline is invalid");

  const child = spawn(process.execPath, [
    CHILD,
    `--binding-id=${binding.binding_id}`,
    `--key-version=${binding.key_version}`,
    `--binding-digest=${binding.binding_digest}`,
    `--lease-ms=${leaseMs}`
  ], { cwd: ROOT, env: { NODE_ENV: "test", AGENTPASS_TEST_DATABASE_URL: databaseUrl }, shell: false, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let stdout = "";
  let stderrBytes = 0;
  let settled = false;
  let deadline;
  const messages = [];
  const waiters = [];

  const finish = (error) => {
    while (waiters.length > 0) waiters.shift().reject(error);
  };
  const accept = (message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) return fail();
    const expected = message.type === "ready"
      ? Object.keys(message).length === 1
      : message.type === "accepted"
        ? Object.keys(message).length === 2 && typeof message.duplicate === "boolean"
        : message.type === "error" && Object.keys(message).length === 1;
    if (!expected) return fail();
    const waiterIndex = waiters.findIndex((waiter) => waiter.type === message.type);
    if (waiterIndex >= 0) waiters.splice(waiterIndex, 1)[0].resolve(message);
    else if (message.type === "error") finish(new Error("acceptance child failed"));
    else messages.push(message);
  };
  const fail = () => {
    if (settled) return;
    finish(new Error("acceptance child protocol failed"));
    child.kill("SIGKILL");
  };

  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString("utf8");
    if (Buffer.byteLength(stdout, "utf8") > 8 * 1024) return fail();
    let newline;
    while ((newline = stdout.indexOf("\n")) >= 0) {
      const line = stdout.slice(0, newline);
      stdout = stdout.slice(newline + 1);
      if (Buffer.byteLength(line, "utf8") > 2 * 1024) return fail();
      try { accept(JSON.parse(line)); } catch { fail(); return; }
    }
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > 8 * 1024) fail();
  });
  const exit = new Promise((resolve) => child.once("close", (code, signal) => {
    settled = true;
    clearTimeout(deadline);
    finish(new Error("acceptance child exited"));
    resolve(Object.freeze({ code, signal }));
  }));
  deadline = setTimeout(() => fail(), deadlineMs);
  deadline.unref?.();

  return Object.freeze({
    send() {
      if (settled || !child.stdin.writable) throw new Error("acceptance child is closed");
      child.stdin.write('{"type":"run"}\n');
    },
    waitForMessage(type) {
      const index = messages.findIndex((message) => message.type === type);
      if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]);
      return new Promise((resolve, reject) => waiters.push({ type, resolve, reject }));
    },
    kill() {
      if (!settled) child.kill("SIGKILL");
      return exit;
    },
    waitForExit: () => exit
  });
}
