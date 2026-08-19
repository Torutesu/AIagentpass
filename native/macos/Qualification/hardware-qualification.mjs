import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const MAX_OUTPUT = 128 * 1024;
const CHECKS = ["launchd_host_child_identity", "nsxpc", "crash_restart"];
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
export const canonicalJSON = (value) => `${JSON.stringify(canonical(value))}\n`;
const fail = (message) => { throw new Error(message); };
const exact = (value, keys, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} has unexpected fields`); };
const commandResult = (command, label) => {
  if (!path.isAbsolute(command) || command.includes("\0")) fail(`${label} must be an absolute executable path`);
  const result = spawnSync(command, [], { cwd: "/", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }, encoding: "buffer", timeout: 60_000, maxBuffer: MAX_OUTPUT });
  const stdout = Buffer.from(result.stdout ?? ""); const stderr = Buffer.from(result.stderr ?? "");
  if (result.error || result.status !== 0 || result.signal || stdout.length === 0) fail(`${label} did not pass`);
  let observed; try { observed = JSON.parse(stdout.toString("utf8")); } catch { fail(`${label} did not emit JSON`); }
  if (!observed || observed.status !== "passed" || typeof observed.observed !== "object" || Array.isArray(observed.observed)) fail(`${label} emitted a non-passing result`);
  return { status: "passed", exit_code: 0, stdout_sha256: sha256(stdout), stderr_sha256: sha256(stderr), observed };
};

const validateObserved = (name, observed) => {
  const required = {
    launchd_host_child_identity: ["service_label", "host_pid", "child_pid", "host_identity", "child_identity", "identity_match"],
    nsxpc: ["mach_service", "connection_accepted", "authorized_client", "wrong_identity_denied"],
    crash_restart: ["initial_pid", "crash_signal", "restarted_pid", "restart_count", "state_recovered"]
  }[name];
  exact(observed, required, `${name} observed evidence`);
  if (name === "launchd_host_child_identity" && (typeof observed.service_label !== "string" || !Number.isSafeInteger(observed.host_pid) || !Number.isSafeInteger(observed.child_pid) || !observed.host_identity || !observed.child_identity || observed.identity_match !== true)) fail(`${name} observed evidence is incomplete`);
  if (name === "nsxpc" && (typeof observed.mach_service !== "string" || observed.connection_accepted !== true || observed.authorized_client !== true || observed.wrong_identity_denied !== true)) fail(`${name} observed evidence is incomplete`);
  if (name === "crash_restart" && (!Number.isSafeInteger(observed.initial_pid) || typeof observed.crash_signal !== "string" || !Number.isSafeInteger(observed.restarted_pid) || !Number.isSafeInteger(observed.restart_count) || observed.restart_count < 1 || observed.state_recovered !== true)) fail(`${name} observed evidence is incomplete`);
};

function machine() {
  if (process.platform !== "darwin") fail("hardware qualification requires macOS");
  const architecture = os.arch() === "arm64" ? "arm64" : os.arch() === "x64" ? "x86_64" : null;
  if (!architecture) fail("unsupported macOS architecture");
  const sysctl = (name) => { const r = spawnSync("/usr/sbin/sysctl", ["-n", name], { encoding: "utf8" }); if (r.status !== 0) fail(`sysctl ${name} failed`); return r.stdout.trim(); };
  const model = sysctl("hw.model"); const version = sysctl("kern.osproductversion"); const build = sysctl("kern.osversion");
  return { architecture, hardware_class: architecture === "arm64" ? "apple_silicon" : "intel", model_identifier: model, os_version: version, os_build: build };
}

function signedArtifact(artifactPath) {
  if (!path.isAbsolute(artifactPath) || !fs.existsSync(artifactPath)) fail("artifact is missing");
  const stat = fs.lstatSync(artifactPath); if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0) fail("artifact is not a protected regular file");
  const bytes = fs.readFileSync(artifactPath); const digest = sha256(bytes);
  const verify = spawnSync("/usr/bin/codesign", ["--verify", "--strict", artifactPath], { encoding: "utf8" }); if (verify.status !== 0) fail("artifact signature verification failed");
  const detail = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=4", artifactPath], { encoding: "utf8" }); if (detail.status !== 0) fail("artifact signature inspection failed");
  const text = `${detail.stdout}\n${detail.stderr}`;
  const identifier = text.match(/^Identifier=(.+)$/mu)?.[1]; const team = text.match(/^TeamIdentifier=(.+)$/mu)?.[1];
  const cdhashes = [...text.matchAll(/^CDHash=(.+)$/gmu)].map((match) => match[1]);
  if (!identifier || !/^[A-Z0-9]{10}$/u.test(team ?? "") || cdhashes.length === 0 || cdhashes.some((item) => !/^[0-9a-f]{40}$/u.test(item))) fail("artifact signature identity is incomplete");
  return { path: artifactPath, bytes: bytes.length, sha256: digest, signed: true, identifier, team_id: team, cdhashes };
}

export function qualify({ artifact, sourceCommit, expectedArchitecture = null, launchdProbe, nsxpcProbe, crashRestartProbe } = {}) {
  if (!COMMIT.test(sourceCommit ?? "")) fail("source commit must be a full lowercase SHA-1");
  const checks = {
    launchd_host_child_identity: commandResult(launchdProbe, "launchd host-child probe"),
    nsxpc: commandResult(nsxpcProbe, "NSXPC probe"),
    crash_restart: commandResult(crashRestartProbe, "crash/restart probe")
  };
  const report = { schema_version: 1, kind: "agentpass.macos.hardware-qualification", source_commit: sourceCommit, artifact: signedArtifact(artifact), machine: machine(), checks, qualified: true };
  if (expectedArchitecture !== null && report.machine.architecture !== expectedArchitecture) fail("runner architecture does not match the requested qualification lane");
  validate(report);
  return report;
}

export function validate(report) {
  exact(report, ["schema_version", "kind", "source_commit", "artifact", "machine", "checks", "qualified"], "report");
  if (report.schema_version !== 1 || report.kind !== "agentpass.macos.hardware-qualification" || !COMMIT.test(report.source_commit) || report.qualified !== true) fail("report is not a qualified v1 report");
  exact(report.artifact, ["path", "bytes", "sha256", "signed", "identifier", "team_id", "cdhashes"], "artifact");
  if (!path.isAbsolute(report.artifact.path) || !Number.isSafeInteger(report.artifact.bytes) || report.artifact.bytes <= 0 || !DIGEST.test(report.artifact.sha256) || report.artifact.signed !== true || !/^[A-Z0-9]{10}$/u.test(report.artifact.team_id) || !Array.isArray(report.artifact.cdhashes) || report.artifact.cdhashes.length === 0 || report.artifact.cdhashes.some((item) => !/^[0-9a-f]{40}$/u.test(item))) fail("artifact evidence is invalid");
  exact(report.machine, ["architecture", "hardware_class", "model_identifier", "os_version", "os_build"], "machine");
  if (!["arm64", "x86_64"].includes(report.machine.architecture) || (report.machine.architecture === "arm64" ? report.machine.hardware_class !== "apple_silicon" : report.machine.hardware_class !== "intel")) fail("machine identity is inconsistent");
  exact(report.checks, CHECKS, "checks");
  for (const name of CHECKS) { const check = report.checks[name]; exact(check, ["status", "exit_code", "stdout_sha256", "stderr_sha256", "observed"], `${name} check`); if (check.status !== "passed" || check.exit_code !== 0 || !DIGEST.test(check.stdout_sha256) || !DIGEST.test(check.stderr_sha256) || !check.observed || typeof check.observed !== "object" || Array.isArray(check.observed)) fail(`${name} check is not passing evidence`); validateObserved(name, check.observed); }
  return report;
}

export function verifyFile(reportPath) {
  const bytes = fs.readFileSync(reportPath); const report = JSON.parse(bytes.toString("utf8"));
  if (canonicalJSON(report) !== bytes.toString("utf8")) fail("report is not canonical JSON");
  validate(report);
  const artifact = fs.readFileSync(report.artifact.path); if (artifact.length !== report.artifact.bytes || sha256(artifact) !== report.artifact.sha256) fail("artifact digest does not match evidence");
  return report;
}

function args(values) { const out = {}; for (let i = 0; i < values.length; i += 2) { if (!values[i]?.startsWith("--") || !values[i + 1] || out[values[i].slice(2)]) fail("invalid arguments"); out[values[i].slice(2)] = values[i + 1]; } return out; }
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const value = args(process.argv.slice(2));
    if (value.verify) { verifyFile(path.resolve(value.verify)); process.stdout.write('{"ok":true,"status":"verified"}\n'); }
    else { const report = qualify({ artifact: path.resolve(value.artifact), sourceCommit: value["source-commit"], expectedArchitecture: value["expected-architecture"] ?? null, launchdProbe: path.resolve(value["launchd-probe"]), nsxpcProbe: path.resolve(value["nsxpc-probe"]), crashRestartProbe: path.resolve(value["crash-restart-probe"]) }); fs.writeFileSync(path.resolve(value.output), canonicalJSON(report), { mode: 0o600, flag: "wx" }); process.stdout.write('{"ok":true,"qualified":true}\n'); }
  } catch (error) { process.stderr.write(`macOS hardware qualification refused: ${error.message}\n`); process.exitCode = 1; }
}
