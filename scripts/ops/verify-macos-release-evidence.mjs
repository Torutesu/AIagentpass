import { spawnSync } from "node:child_process";
import { lstatSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

const [evidence, inventory, artifactRoot, evidenceRoot, verification, expectedTeam] = process.argv.slice(2);
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const normalizedAbsolute = (value, label) => {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0") || resolve(value) !== value) throw new Error(`${label} must be a normalized absolute path`);
  return value;
};
const preflightFile = (value, label) => {
  const file = normalizedAbsolute(value, label);
  let stat;
  try { stat = lstatSync(file, { bigint: true }); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n) throw new Error(`${label} is not a regular single-link file`);
};
const preflightDirectory = (value, label) => {
  const directory = normalizedAbsolute(value, label);
  let stat;
  try { stat = lstatSync(directory, { bigint: true }); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} is not a real directory`);
};
const preflightInputs = () => {
  preflightFile(evidence, "distribution evidence");
  preflightFile(inventory, "artifact inventory");
  preflightFile(verification, "independent verification evidence");
  preflightDirectory(artifactRoot, "artifact root");
  preflightDirectory(evidenceRoot, "evidence root");
  if (expectedTeam !== undefined && !TEAM_ID.test(expectedTeam)) throw new Error("expected Team ID is invalid");
};
if (!evidence || !inventory || !artifactRoot || !evidenceRoot || !verification) {
  process.stdout.write(`${JSON.stringify({ status: "unknown", reason: "evidence_path_missing" })}\n`);
  process.stderr.write("macOS release evidence is unknown: usage requires evidence, inventory, artifact root, and evidence root\n");
  process.exitCode = 2;
} else {
  try { preflightInputs(); } catch (error) {
    process.stderr.write(`macOS release evidence preflight refused: ${error.message}\n`);
    process.exitCode = 2;
    process.exit();
  }
  const verifier = resolve(dirname(new URL(import.meta.url).pathname), "../../native/macos/scripts/verify-distribution-evidence.mjs");
  const result = spawnSync(process.execPath, [verifier, evidence, inventory, artifactRoot, evidenceRoot, verification, ...(expectedTeam === undefined ? [] : [expectedTeam])], { encoding: "utf8" });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exitCode = result.status ?? 1;
}
