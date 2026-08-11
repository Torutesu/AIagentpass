#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { audit, verifyAudit } from "../lib/audit.mjs";
import { auditPath, defaultConfigDir, loadConfig, loadSession, loadState, saveConfig, saveSession, saveState } from "../lib/config.mjs";
import { evaluateRequest, evaluateSignRequest } from "../lib/policy.mjs";

const [, , command, ...args] = process.argv;

function usage() {
  console.log(`AgentPass 0.2.0

Commands:
  init [dir]        create a secure local policy
  status            show policy and revocation status
  check             evaluate the current repository
  doctor            check local prerequisites
  session start     issue a short-lived agent session token
  revoke            immediately deny all operations
  restore           re-enable operations after revocation
  git-sign [args]   policy-check then delegate to ssh-keygen
  audit [--verify]  print or verify the tamper-evident audit log
`);
}

function git(gitArgs, optional = false) {
  const result = spawnSync("git", gitArgs, { encoding: "utf8" });
  if (result.status !== 0) {
    if (optional) return "";
    throw new Error(result.stderr.trim() || `git ${gitArgs.join(" ")} failed`);
  }
  return result.stdout.trim();
}

function init() {
  const dir = path.resolve(args[0] ?? defaultConfigDir);
  if (fs.existsSync(path.join(dir, "config.json"))) throw new Error(`Already initialized: ${dir}`);
  saveConfig({
    version: 2,
    agent: { name: process.env.AGENTPASS_AGENT ?? "coding-agent" },
    operations: ["git.commit.sign"],
    repositories: [git(["rev-parse", "--show-toplevel"], true) || process.cwd()],
    branches: { allow: ["feature/*", "fix/*", "chore/*"], deny: ["main", "master", "production"] },
    remotes: { allow: ["git@github.com:*", "https://github.com/*", "ssh://git@github.com/*"] },
    signing: { key: "~/.ssh/id_git_sign", provider: "/usr/lib/ssh-keychain.dylib" },
    session: { required: false, ttl_seconds: 3600 }
  }, dir);
  saveState({ revoked: false, generation: 0 }, dir);
  audit({ operation: "config.init", decision: "allow", agent: process.env.AGENTPASS_AGENT ?? "coding-agent" }, dir);
  console.log(`Initialized ${dir}`);
}

function context(config) {
  const root = git(["rev-parse", "--show-toplevel"]);
  const session = loadSession();
  const supplied = process.env.AGENTPASS_SESSION;
  const sessionValid = Boolean(session && supplied && crypto.createHash("sha256").update(supplied).digest("hex") === session.token_hash && Date.now() < Date.parse(session.expires_at) && session.generation === loadState().generation);
  return {
    cwd: root,
    branch: git(["branch", "--show-current"], true) || "HEAD",
    remote: git(["remote", "get-url", "origin"], true),
    revoked: loadState().revoked,
    policy: { ...config, session: { ...config.session, valid: sessionValid } }
  };
}

function sessionStart() {
  const config = loadConfig();
  const ttl = Math.max(60, Math.min(Number(args[1] ?? config.session?.ttl_seconds ?? 3600), 86400));
  const token = crypto.randomBytes(32).toString("base64url");
  const state = loadState();
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  saveSession({ token_hash: crypto.createHash("sha256").update(token).digest("hex"), expires_at: expiresAt, generation: state.generation });
  audit({ operation: "session.start", decision: "allow", expires_at: expiresAt, generation: state.generation }, defaultConfigDir);
  console.log(token);
  console.error(`Session expires at ${expiresAt}`);
}

function check() {
  const config = loadConfig();
  const result = evaluateSignRequest(context(config));
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: process.cwd() }, defaultConfigDir);
  console.log(JSON.stringify(result, null, 2));
  if (!result.allowed) process.exitCode = 1;
}

function status() {
  const config = loadConfig();
  const state = loadState();
  console.log(JSON.stringify({
    version: config.version,
    agent: config.agent,
    operations: config.operations,
    repositories: config.repositories,
    revoked: state.revoked,
    generation: state.generation,
    audit: auditPath()
  }, null, 2));
}

function revoke() {
  loadConfig();
  const state = loadState();
  saveState({ ...state, revoked: true, generation: (state.generation ?? 0) + 1, revoked_at: new Date().toISOString() });
  audit({ operation: "control.revoke", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("All AgentPass operations revoked.");
}

function restore() {
  loadConfig();
  const state = loadState();
  saveState({ ...state, revoked: false, generation: (state.generation ?? 0) + 1, restored_at: new Date().toISOString() });
  audit({ operation: "control.restore", decision: "allow", generation: state.generation + 1 }, defaultConfigDir);
  console.log("AgentPass operations restored.");
}

function doctor() {
  const checks = [
    { name: "node", ok: Number(process.versions.node.split(".")[0]) >= 20, detail: process.versions.node },
    { name: "platform", ok: process.platform === "darwin", detail: `${process.platform}/${process.arch}` },
    { name: "git", ok: Boolean(spawnSync("git", ["--version"], { encoding: "utf8" }).stdout), detail: git(["--version"], true) },
    { name: "ssh-keygen", ok: fs.existsSync("/usr/bin/ssh-keygen"), detail: "/usr/bin/ssh-keygen" },
    { name: "config", ok: fs.existsSync(path.join(defaultConfigDir, "config.json")), detail: defaultConfigDir }
  ];
  console.log(JSON.stringify({ ok: checks.every((check) => check.ok), checks }, null, 2));
  if (!checks.every((check) => check.ok)) process.exitCode = 1;
}

function gitSign(signArgs = args) {
  const config = loadConfig();
  const ctx = context(config);
  const result = evaluateSignRequest(ctx);
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: ctx.cwd, branch: ctx.branch, remote: ctx.remote }, defaultConfigDir);
  if (!result.allowed) throw new Error(`Denied by policy: ${result.reason}`);

  const provider = config.signing?.provider || "/usr/lib/ssh-keychain.dylib";
  const child = spawnSync("/usr/bin/ssh-keygen", signArgs, {
    stdio: "inherit",
    env: { ...process.env, SSH_SK_PROVIDER: provider, AGENTPASS_POLICY_DECISION: "allow" }
  });
  process.exitCode = child.status ?? 1;
}

try {
  if (command === "init") init();
  else if (command === "check") check();
  else if (command === "status") status();
  else if (command === "doctor") doctor();
  else if (command === "session" && args[0] === "start") sessionStart();
  else if (command === "revoke") revoke();
  else if (command === "restore") restore();
  else if (command === "git-sign") gitSign();
  else if (command === "-Y") gitSign([command, ...args]);
  else if (command === "audit") {
    if (args.includes("--verify")) console.log(JSON.stringify(verifyAudit(defaultConfigDir), null, 2));
    else console.log(fs.existsSync(auditPath()) ? fs.readFileSync(auditPath(), "utf8") : "");
  } else usage();
} catch (error) {
  console.error(`agentpass: ${error.message}`);
  process.exitCode = 1;
}
