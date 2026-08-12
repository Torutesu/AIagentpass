import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(projectRoot, "bin", "agentpass.mjs");
const daemon = path.join(projectRoot, "bin", "agentpassd.mjs");
const signingProgram = path.join(projectRoot, "bin", "agentpass-git-sign.mjs");

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { encoding: "utf8", ...options });
  if (result.status !== 0) throw new Error(result.stderr || `${program} failed`);
  return result.stdout.trim();
}

// This launches several Node, Git, and ssh-keygen processes. Keep enough headroom
// for the full parallel suite on slower CI runners while retaining a hard bound.
test("Git creates a signed commit through the AgentPass broker", { timeout: 30_000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-e2e-"));
  const testHome = path.join(root, "home");
  const repo = path.join(root, "repo");
  fs.mkdirSync(testHome);
  fs.mkdirSync(repo);
  const env = { ...process.env, HOME: testHome };

  run("git", ["-C", repo, "init", "-b", "main"]);
  run("git", ["-C", repo, "switch", "-c", "feature/e2e"]);
  run("git", ["-C", repo, "remote", "add", "origin", "git@github.com:example/e2e.git"]);
  run("git", ["-C", repo, "config", "user.name", "AgentPass Test"]);
  run("git", ["-C", repo, "config", "user.email", "agentpass@example.com"]);
  run(process.execPath, [cli, "init"], { cwd: repo, env });

  const key = path.join(root, "software-signing-key");
  run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key]);
  const configPath = path.join(testHome, ".agentpass", "config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  config.signing.key = key;
  config.signing.provider = "/usr/lib/ssh-keychain.dylib";
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });

  const addedAgent = JSON.parse(run(process.execPath, [cli, "agent", "add", "e2e-agent"], { cwd: repo, env }));
  run(process.execPath, [cli, "agent", "scope", addedAgent.id, "--operation", "git.commit.sign", "--repository", repo, "--branch", "feature/*", "--remote", "git@github.com:example/e2e.git"], { cwd: repo, env });
  run(process.execPath, [cli, "agent", "set-default", addedAgent.id], { cwd: repo, env });
  assert.match(run(process.execPath, [cli, "agent", "list"], { cwd: repo, env }), /e2e-agent/);

  const controlKeys = JSON.parse(run(process.execPath, [cli, "control", "keygen", path.join(root, "offline-control")], { cwd: repo, env }));
  run(process.execPath, [cli, "control", "trust", controlKeys.public_file], { cwd: repo, env });
  const controlBundle = run(process.execPath, [cli, "control", "sign", "--key", controlKeys.private_file, "--sequence", "1", "--expires", new Date(Date.now() + 60 * 60 * 1000).toISOString()], { cwd: repo, env });
  const controlBundleFile = path.join(root, "control.bundle.json");
  fs.writeFileSync(controlBundleFile, `${controlBundle}\n`, { mode: 0o600 });
  run(process.execPath, [cli, "control", "apply", controlBundleFile], { cwd: repo, env });
  assert.match(run(process.execPath, [cli, "control", "status"], { cwd: repo, env }), /"sequence": 1/);

  const session = run(process.execPath, [cli, "session", "start", "300"], { cwd: repo, env });
  const broker = spawn(process.execPath, [daemon], { cwd: repo, env, stdio: ["ignore", "pipe", "pipe"] });
  const socket = path.join(testHome, ".agentpass", "agentpass.sock");
  try {
    await waitForSocket(socket, broker);
    run("git", ["-C", repo, "config", "gpg.format", "ssh"]);
    run("git", ["-C", repo, "config", "user.signingkey", `${key}.pub`]);
    run("git", ["-C", repo, "config", "gpg.ssh.program", signingProgram]);
    run("git", ["-C", repo, "config", "commit.gpgsign", "true"]);
    fs.writeFileSync(path.join(repo, "README.md"), "signed through AgentPass\n");
    run("git", ["-C", repo, "add", "README.md"]);
    run("git", ["-C", repo, "commit", "-m", "Signed commit"], { env: { ...env, AGENTPASS_SESSION: session } });
    const commit = run("git", ["-C", repo, "cat-file", "-p", "HEAD"]);
    assert.match(commit, /BEGIN SSH SIGNATURE/);
    const checkpoint = JSON.parse(run(process.execPath, [cli, "audit", "checkpoint"], { cwd: repo, env }));
    assert.equal(checkpoint.entries > 0, true);
    const verification = JSON.parse(run(process.execPath, [cli, "audit", "--verify"], { cwd: repo, env }));
    assert.equal(verification.valid, true);
  } finally {
    broker.kill("SIGTERM");
    await new Promise((resolve) => broker.once("exit", resolve));
  }
});

async function waitForSocket(socket, broker) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (fs.existsSync(socket)) return;
    if (broker.exitCode !== null) throw new Error("Broker exited before creating its socket");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("Broker socket did not appear");
}
