#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const formulaPath = path.join(root, "Formula", "agentpass.rb");
const formula = fs.readFileSync(formulaPath, "utf8");
const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

function requireMatch(pattern, message) {
  assert.match(formula, pattern, message);
}

function requireAbsent(pattern, message) {
  assert.doesNotMatch(formula, pattern, message);
}

assert.match(formula, /^class Agentpass < Formula$/m, "formula class must use the package name");
const escapedVersion = packageJson.version.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");
assert.match(formula, new RegExp(`^  version "${escapedVersion}"$`, "m"), "formula version must match package.json");

const sourceUrl = formula.match(/^  url "([^"]+)"$/m)?.[1];
assert.ok(sourceUrl, "formula must declare a source URL");
const parsedUrl = new URL(sourceUrl);
assert.equal(parsedUrl.protocol, "https:", "source URL must use HTTPS");
assert.equal(parsedUrl.hostname, "github.com", "source URL must use the canonical GitHub host");
assert.match(parsedUrl.pathname, /\/Torutesu\/AIagentpass\/archive\/[0-9a-f]{40}\.tar\.gz$/, "source archive must be pinned to an immutable commit");

const sha256 = formula.match(/^  sha256 "([^"]+)"$/m)?.[1];
assert.match(sha256 ?? "", /^[0-9a-f]{64}$/, "source archive SHA256 must be a complete lowercase digest");
assert.notEqual(sha256, "0".repeat(64), "source archive SHA256 must not be all zeroes");
requireAbsent(/(?:PLACEHOLDER|REPLACE|TODO|INSERT|<SHA256>|xxxxxxxx)/i, "formula must not contain digest placeholders");

requireMatch(/depends_on macos: :sonoma/, "evaluation distribution must be macOS-only");
requireMatch(/depends_on \"node\"/, "runtime Node dependency is required");
requireMatch(/libexec\.install \"bin\", \"lib\"/, "CLI runtime must be copied without npm installation");
requireMatch(/packages\/protocol/, "protocol runtime must be included");
requireMatch(/packages\/capability/, "capability runtime must be included");
requireMatch(/adapters\/mcp-server/, "MCP integration runtime must be included");
requireAbsent(/system\s+\"npm\"|npm\s+(?:install|ci|run\s+build)|yarn\s+install|pnpm\s+install/i, "formula must not install or build through a package manager");
requireAbsent(/native\/macos|AgentPass\.app/, "Homebrew evaluation formula must not install the production native app");

requireMatch(/AGENTPASS_DISTRIBUTION=homebrew-evaluation/, "runtime must identify the Homebrew evaluation channel");
requireMatch(/AGENTPASS_PRODUCTION_XPC_BOUNDARY=unavailable/, "runtime must explicitly disable production XPC claims");
requireMatch(/channel: \"homebrew\"/, "status and doctor output must identify Homebrew");
requireMatch(/mode: \"evaluation\"/, "status and doctor output must identify evaluation mode");
requireMatch(/production_xpc_boundary: false/, "status and doctor output must disclaim the production XPC boundary");
requireMatch(/signed and notarized PKG/, "formula must direct production users to the verified PKG");
requireMatch(/\[ "\$\{1-\}" = "install" \]/, "evaluation CLI must intercept production installation");
requireMatch(/agentpass-mcp\.mjs" => "agentpass-mcp"/, "MCP executable must be exposed in the Homebrew bin directory");
requireMatch(/agentpass-anchor\.mjs" => "agentpass-anchor"/, "anchor executable must be exposed in the Homebrew bin directory");

requireMatch(/\n  test do\n/, "formula must include a Homebrew smoke test");
requireMatch(/JSON\.parse\(shell_output\("#\{bin\}\/agentpass status"\)\)/, "smoke test must exercise status JSON");
requireMatch(/JSON\.parse\(shell_output\("#\{bin\}\/agentpass doctor", 1\)\)/, "smoke test must exercise doctor JSON");

const ruby = spawnSync("ruby", ["-c", formulaPath], { encoding: "utf8" });
if (ruby.error?.code === "ENOENT") throw new Error("ruby is required for offline Formula syntax validation");
assert.equal(ruby.status, 0, `Formula Ruby syntax failed:\n${ruby.stdout}\n${ruby.stderr}`);

console.log(JSON.stringify({
  ok: true,
  formula: path.relative(root, formulaPath),
  version: packageJson.version,
  source_commit: parsedUrl.pathname.match(/archive\/([0-9a-f]{40})/)?.[1],
  sha256,
  checks: ["immutable-source", "digest", "no-npm-build", "evaluation-caveat", "ruby-syntax", "smoke-test"]
}, null, 2));
