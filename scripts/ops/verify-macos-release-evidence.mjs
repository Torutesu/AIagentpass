import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

const [evidence, inventory, artifactRoot, evidenceRoot] = process.argv.slice(2);
if (!evidence || !inventory || !artifactRoot || !evidenceRoot) {
  process.stdout.write(`${JSON.stringify({ status: "unknown", reason: "evidence_path_missing" })}\n`);
  process.stderr.write("macOS release evidence is unknown: usage requires evidence, inventory, artifact root, and evidence root\n");
  process.exitCode = 2;
} else {
  const verifier = resolve(dirname(new URL(import.meta.url).pathname), "../../native/macos/scripts/verify-distribution-evidence.mjs");
  const result = spawnSync(process.execPath, [verifier, evidence, inventory, artifactRoot, evidenceRoot], { encoding: "utf8" });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exitCode = result.status ?? 1;
}
