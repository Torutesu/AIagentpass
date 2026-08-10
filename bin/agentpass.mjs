#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { auditPath, defaultConfigDir, loadConfig, saveConfig } from "../lib/config.mjs";
import { audit } from "../lib/audit.mjs";
import { evaluateSignRequest } from "../lib/policy.mjs";

const [, , command, ...args] = process.argv;

function usage() {
  console.log(`AgentPass 0.1.0\n\nCommands:\n  init [dir]       create a local policy\n  check            evaluate the current repository\n  git-sign [args]  policy-check then delegate to ssh-keygen\n  audit            print the local audit log\n`);
}

function git(args) {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
  return result.stdout.trim();
}

function init() {
  const dir = path.resolve(args[0] ?? defaultConfigDir);
  if (fs.existsSync(path.join(dir, "config.json"))) throw new Error(`Already initialized: ${dir}`);
  saveConfig({
    version: 1,
    agent: { name: process.env.AGENTPASS_AGENT ?? "coding-agent" },
    repositories: [process.cwd()],
    branches: { allow: ["feature/*", "fix/*", "chore/*"], deny: ["main", "master", "production"] },
    remotes: { allow: ["git@github.com:*", "https://github.com/*"] },
    signing: { key: "~/.ssh/id_git_sign", provider: "/usr/lib/ssh-keychain.dylib" }
  }, dir);
  console.log(`Initialized ${dir}`);
}

function context(config) {
  const cwd = process.cwd();
  return {
    cwd,
    branch: git(["branch", "--show-current"]),
    remote: git(["remote", "get-url", "origin"]),
    policy: config
  };
}

function check() {
  const config = loadConfig();
  const result = evaluateSignRequest(context(config));
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: process.cwd() }, defaultConfigDir);
  console.log(JSON.stringify(result, null, 2));
  if (!result.allowed) process.exitCode = 1;
}

function gitSign(signArgs = args) {
  const config = loadConfig();
  const ctx = context(config);
  const result = evaluateSignRequest(ctx);
  audit({ operation: "git.commit.sign", decision: result.allowed ? "allow" : "deny", reason: result.reason, cwd: ctx.cwd, branch: ctx.branch, remote: ctx.remote }, defaultConfigDir);
  if (!result.allowed) throw new Error(`Denied by policy: ${result.reason}`);

  const key = config.signing?.key?.replace(/^~\//, `${os.homedir()}/`);
  const provider = config.signing?.provider || "/usr/lib/ssh-keychain.dylib";
  const child = spawnSync("/usr/bin/ssh-keygen", signArgs, {
    stdio: "inherit",
    env: { ...process.env, SSH_SK_PROVIDER: provider, AGENTPASS_POLICY_DECISION: "allow", AGENTPASS_SIGNING_KEY: key }
  });
  process.exitCode = child.status ?? 1;
}

try {
  if (command === "init") init();
  else if (command === "check") check();
  else if (command === "git-sign") gitSign();
  else if (command === "-Y") gitSign([command, ...args]);
  else if (command === "audit") console.log(fs.existsSync(auditPath()) ? fs.readFileSync(auditPath(), "utf8") : "");
  else usage();
} catch (error) {
  console.error(`agentpass: ${error.message}`);
  process.exitCode = 1;
}
