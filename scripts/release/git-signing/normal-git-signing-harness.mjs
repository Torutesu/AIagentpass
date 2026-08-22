import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const GIT_NAMESPACE = "git";
const FIXED_SIGNER_REFERENCE = "agentpass-managed";

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${program} ${args.join(" ")} failed: ${result.stderr || "unknown error"}`);
  }
  return result.stdout;
}

function writeFixtureSigningProgram({ path: programPath, logPath, privateKeyPath }) {
  const source = `#!/usr/bin/env node
import fs from "node:fs";
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(logPath)}, JSON.stringify(args) + "\\n", { mode: 0o600 });

// This fixture models the native helper boundary: one Git invocation, the
// fixed opaque signer reference, and one absolute payload. It intentionally
// rejects every session-shaped or key-selecting invocation.
if (args.length !== 7 || args[0] !== "-Y" || args[1] !== "sign" ||
    args[2] !== "-n" || args[3] !== ${JSON.stringify(GIT_NAMESPACE)} ||
    args[4] !== "-f" || args[5] !== ${JSON.stringify(FIXED_SIGNER_REFERENCE)} ||
    typeof args[6] !== "string" || !args[6].startsWith("/") ||
    args.some((value) => value === "--protocol" || value === "--payload")) {
  process.stderr.write("invalid AgentPass Git signing invocation\\n");
  process.exit(64);
}

// The test key is private fixture state and is never passed by Git. The
// production helper performs an equivalent broker-side key selection.
const mapped = args.slice();
mapped[5] = ${JSON.stringify(privateKeyPath)};
const result = spawnSync("ssh-keygen", mapped, { stdio: "inherit" });
if (result.error) {
  process.stderr.write(String(result.error));
  process.exit(127);
}
process.exit(result.status ?? 1);
`;
  fs.writeFileSync(programPath, source, { mode: 0o700 });
  fs.chmodSync(programPath, 0o700);
}

function readInvocationLog(logPath) {
  return fs.readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

/**
 * Execute a real Git SSH-signed commit through a one-payload gpg.ssh.program.
 *
 * The returned invocation list is evidence of Git's actual argv contract. The
 * helper fixture deliberately maps only the fixed opaque signer reference to
 * a temporary test key; it never accepts a caller-supplied key path.
 */
export function runNormalGitSigningHarness({ signerReference = FIXED_SIGNER_REFERENCE } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-git-signing-"));
  const home = path.join(root, "home");
  const repository = path.join(root, "repository");
  const keyPath = path.join(root, "fixture-signing-key");
  const programPath = path.join(root, "gpg-ssh-program.mjs");
  const invocationLogPath = path.join(root, "invocations.jsonl");
  fs.mkdirSync(home);
  fs.mkdirSync(repository);
  fs.writeFileSync(invocationLogPath, "", { mode: 0o600 });

  const env = {
    ...process.env,
    HOME: home,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };

  try {
    run("git", ["-C", repository, "init", "-q", "-b", "main"], { env });
    run("git", ["-C", repository, "config", "user.name", "AgentPass Git Harness"], { env });
    run("git", ["-C", repository, "config", "user.email", "agentpass-harness@example.invalid"], { env });
    run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath], { env });
    writeFixtureSigningProgram({ path: programPath, logPath: invocationLogPath, privateKeyPath: keyPath });

    run("git", ["-C", repository, "config", "gpg.format", "ssh"], { env });
    run("git", ["-C", repository, "config", "commit.gpgsign", "true"], { env });
    run("git", ["-C", repository, "config", "user.signingkey", signerReference], { env });
    run("git", ["-C", repository, "config", "gpg.ssh.program", programPath], { env });
    fs.writeFileSync(path.join(repository, "README.md"), "signed by the AgentPass Git harness\n");
    run("git", ["-C", repository, "add", "README.md"], { env });
    run("git", ["-C", repository, "commit", "-q", "-m", "AgentPass normal Git signing"], { env });

    const commit = run("git", ["-C", repository, "cat-file", "-p", "HEAD"], { env });
    if (!commit.includes("-----BEGIN SSH SIGNATURE-----")) {
      throw new Error("Git commit did not contain an SSH signature");
    }

    return {
      commit,
      invocations: readInvocationLog(invocationLogPath),
      repository,
      root,
    };
  } catch (error) {
    fs.rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

export const normalGitSigningContract = Object.freeze({
  argumentCount: 7,
  arguments: ["-Y", "sign", "-n", GIT_NAMESPACE, "-f", FIXED_SIGNER_REFERENCE, "<absolute-payload>"],
  sessionArgumentsForbidden: ["--protocol", "--payload"],
});
