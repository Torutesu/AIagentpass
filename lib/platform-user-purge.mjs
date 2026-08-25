import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ISSUED = new WeakMap();
const CONFIRMATION = "PURGE_USER_STATE";
const MAX_ENTRIES = 10_000;
const MAX_BYTES = 1024 * 1024 * 1024;

export const USER_PURGE_CODES = Object.freeze({
  PLAN_READY: "USER_STATE_PURGE_PLAN_READY",
  COMPLETE: "USER_STATE_PURGE_COMPLETE",
  NOOP: "USER_STATE_PURGE_NOOP",
  INVALID_PLAN: "INVALID_USER_STATE_PURGE_PLAN",
  INVALID_TARGET: "INVALID_USER_STATE_PURGE_TARGET",
  UNSAFE_TARGET: "UNSAFE_USER_STATE_PURGE_TARGET",
  CONFIRMATION_REQUIRED: "USER_STATE_PURGE_CONFIRMATION_REQUIRED",
});

export class UserStatePurgeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "UserStatePurgeError";
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new UserStatePurgeError(code, message);
};

const absent = (filesystem, target) => {
  try {
    return filesystem.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
};

const identity = (stat) => ({
  dev: Number(stat.dev),
  ino: Number(stat.ino),
  mode: Number(stat.mode),
  nlink: Number(stat.nlink),
  size: Number(stat.size),
  mtime_ms: Number(stat.mtimeMs),
});

function inspectTree(filesystem, root, owner) {
  const entries = [];
  let bytes = 0;
  const visit = (target, relative) => {
    if (entries.length >= MAX_ENTRIES)
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "AgentPass user state contains too many entries",
      );
    const stat = filesystem.lstatSync(target);
    if (
      stat.isSymbolicLink() ||
      stat.uid !== owner ||
      (stat.mode & 0o022) !== 0
    ) {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        `AgentPass user state has an unsafe entry: ${relative || "."}`,
      );
    }
    if (!stat.isDirectory() && !stat.isFile()) {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        `AgentPass user state has an unsupported entry: ${relative || "."}`,
      );
    }
    if (stat.isFile() && stat.nlink !== 1) {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        `AgentPass user state has a multiply-linked file: ${relative}`,
      );
    }
    bytes += stat.isFile() ? stat.size : 0;
    if (bytes > MAX_BYTES)
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "AgentPass user state is too large to purge safely",
      );
    entries.push({
      path: relative,
      type: stat.isDirectory() ? "directory" : "file",
      ...identity(stat),
    });
    if (stat.isDirectory()) {
      const names = filesystem.readdirSync(target).sort();
      for (const name of names) {
        if (
          !name ||
          name === "." ||
          name === ".." ||
          name.includes("/") ||
          name.includes("\0")
        ) {
          fail(
            USER_PURGE_CODES.UNSAFE_TARGET,
            "AgentPass user state contains an invalid name",
          );
        }
        visit(
          path.join(target, name),
          relative ? path.join(relative, name) : name,
        );
      }
    }
  };
  visit(root, "");
  return Object.freeze({ entries, bytes, root: entries[0] });
}

const digestPlan = (plan) =>
  crypto.createHash("sha256").update(JSON.stringify(plan)).digest("hex");

function context(options = {}) {
  const filesystem = options.fs ?? fs;
  const uid = options.uid ?? process.getuid?.();
  const homeDir = path.resolve(options.homeDir ?? os.homedir());
  if (!Number.isSafeInteger(uid) || uid < 0 || !path.isAbsolute(homeDir)) {
    fail(
      USER_PURGE_CODES.INVALID_TARGET,
      "Current-user purge identity is invalid",
    );
  }
  const home = filesystem.lstatSync(homeDir);
  if (!home.isDirectory() || home.isSymbolicLink() || home.uid !== uid) {
    fail(USER_PURGE_CODES.UNSAFE_TARGET, "Current-user home is not trusted");
  }
  return { filesystem, uid, homeDir, target: path.join(homeDir, ".agentpass") };
}

export function planUserStatePurge(options = {}) {
  const value = context(options);
  const stat = absent(value.filesystem, value.target);
  const snapshot = stat
    ? inspectTree(value.filesystem, value.target, value.uid)
    : null;
  const plan = Object.freeze({
    version: 1,
    operation: "purge-user-state",
    dryRun: true,
    code: USER_PURGE_CODES.PLAN_READY,
    target: value.target,
    state: snapshot ? "present" : "absent",
    entry_count: snapshot?.entries.length ?? 0,
    byte_count: snapshot?.bytes ?? 0,
    preserves: [
      "Secure Enclave and system-owned AgentPass state",
      "Cloud audit history",
    ],
  });
  ISSUED.set(plan, { digest: digestPlan(plan), snapshot });
  return plan;
}

export function executeUserStatePurge(plan, options = {}) {
  const issued = ISSUED.get(plan);
  if (
    !issued ||
    issued.digest !== digestPlan(plan) ||
    plan?.operation !== "purge-user-state" ||
    plan?.dryRun !== true
  ) {
    fail(
      USER_PURGE_CODES.INVALID_PLAN,
      "Current-user purge plan was not issued by this process or was modified",
    );
  }
  if (options.confirm !== CONFIRMATION) {
    fail(
      USER_PURGE_CODES.CONFIRMATION_REQUIRED,
      `Current-user purge requires --confirm ${CONFIRMATION}`,
    );
  }
  const value = context(options);
  if (value.target !== plan.target)
    fail(
      USER_PURGE_CODES.INVALID_PLAN,
      "Current-user purge target changed after preview",
    );
  if (!issued.snapshot) {
    if (absent(value.filesystem, value.target))
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "AgentPass user state appeared after preview",
      );
    return Object.freeze({
      version: 1,
      operation: plan.operation,
      code: USER_PURGE_CODES.NOOP,
      removed: false,
      target: value.target,
    });
  }
  const live = inspectTree(value.filesystem, value.target, value.uid);
  if (JSON.stringify(live) !== JSON.stringify(issued.snapshot)) {
    fail(
      USER_PURGE_CODES.UNSAFE_TARGET,
      "AgentPass user state changed after preview",
    );
  }
  const suffix = (options.randomBytes ?? crypto.randomBytes)(16).toString(
    "hex",
  );
  if (!/^[0-9a-f]{32}$/u.test(suffix))
    fail(USER_PURGE_CODES.INVALID_TARGET, "Purge quarantine nonce is invalid");
  const quarantine = path.join(
    value.homeDir,
    `.agentpass.agentpass-purge-${suffix}`,
  );
  if (absent(value.filesystem, quarantine))
    fail(USER_PURGE_CODES.UNSAFE_TARGET, "Purge quarantine already exists");
  value.filesystem.renameSync(value.target, quarantine);
  let moved;
  try {
    moved = inspectTree(value.filesystem, quarantine, value.uid);
    if (JSON.stringify(moved) !== JSON.stringify(issued.snapshot)) {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "AgentPass user state was substituted during quarantine",
      );
    }
    if (absent(value.filesystem, value.target))
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "AgentPass user state reappeared during purge",
      );
    value.filesystem.rmSync(quarantine, { recursive: true, force: false });
  } catch (error) {
    try {
      if (
        absent(value.filesystem, quarantine) &&
        !absent(value.filesystem, value.target)
      ) {
        value.filesystem.renameSync(quarantine, value.target);
      }
    } catch {}
    throw error;
  }
  if (
    absent(value.filesystem, quarantine) ||
    absent(value.filesystem, value.target)
  ) {
    fail(
      USER_PURGE_CODES.UNSAFE_TARGET,
      "Current-user purge postcondition failed",
    );
  }
  return Object.freeze({
    version: 1,
    operation: plan.operation,
    code: USER_PURGE_CODES.COMPLETE,
    removed: true,
    target: value.target,
    removed_entries: moved.entries.length,
  });
}

export async function runUserStatePurge(options = {}) {
  const plan = planUserStatePurge(options);
  if (options.execute !== true) return plan;
  if (options.native?.enabled === true) {
    if (
      typeof options.agentId !== "string" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(options.agentId) ||
      typeof options.requestNative !== "function"
    ) {
      fail(
        USER_PURGE_CODES.INVALID_TARGET,
        "Native current-user purge requires an exact Agent identity and broker",
      );
    }
    const response = await options.requestNative(
      { operation: "native.session.revoke-agent", agent_id: options.agentId },
      { native: options.native, timeoutMs: 30_000 },
    );
    if (!response || typeof response.stdout_base64 !== "string") {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "Native Agent session revocation returned an invalid response",
      );
    }
    let revoked;
    try {
      revoked = JSON.parse(
        Buffer.from(response.stdout_base64, "base64").toString("utf8"),
      );
    } catch {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "Native Agent session revocation returned invalid JSON",
      );
    }
    if (
      !revoked ||
      typeof revoked !== "object" ||
      Array.isArray(revoked) ||
      JSON.stringify(Object.keys(revoked).sort()) !==
        JSON.stringify(["generation", "revoked_sessions"]) ||
      !Number.isSafeInteger(revoked.generation) ||
      revoked.generation < 0 ||
      !Number.isSafeInteger(revoked.revoked_sessions) ||
      revoked.revoked_sessions < 0
    ) {
      fail(
        USER_PURGE_CODES.UNSAFE_TARGET,
        "Native Agent session revocation payload is invalid",
      );
    }
  }
  return executeUserStatePurge(plan, options);
}

export const USER_STATE_PURGE_CONFIRMATION = CONFIRMATION;
