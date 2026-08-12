/*
 * P0-B E2E artifact security gate.
 *
 * CI command:
 *   AGENTPASS_E2E_ARTIFACT_DIR="$PWD/artifacts/e2e" node --test test/p0b-artifact-security.test.mjs
 *
 * The scanner intentionally reports only a relative path and a stable rule
 * code. It never includes matching values, line contents, cookies, tokens, or
 * screenshots in an assertion message.
 */
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ARTIFACT_DIR = process.env.AGENTPASS_E2E_ARTIFACT_DIR
  ?? process.env.E2E_ARTIFACT_DIR
  ?? process.env.AGENTPASS_ARTIFACT_DIR;
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_FILES = 10_000;
const DENYLIST = Object.freeze([
  ["cookie", /(?:^|[\s"'`])(?:cookie|set-cookie|__host-[a-z0-9_-]+)/iu],
  ["csrf", /(?:csrf|xsrf)(?:[_-]?(?:token|secret|value))?/iu],
  ["recent_auth", /(?:recent[_-]?auth|webauthn[_-]?(?:proof|assertion|challenge|response)|clientdatajson|authenticatordata)/iu],
  ["capability", /(?:capability|bearer|access[_-]?token|refresh[_-]?token|authorization)/iu],
  ["nonce", /(?:nonce|ack[_-]?nonce|refresh[_-]?nonce)/iu],
  ["private_key", /(?:private[_-]?key|BEGIN [A-Z0-9 ]*PRIVATE KEY|pkcs8|secret[_-]?key)/iu],
  ["enrollment", /(?:enrollment[_-]?(?:credential|secret|token|proof)|device[_-]?enrollment)/iu],
  ["policy_body", /(?:policy(?:[_-]?(?:body|scope|json|document))?|scope_json|revoked_(?:devices|agents|capabilities))/iu]
]);
const SCANNED_EXTENSIONS = new Set([".json", ".ndjson", ".har", ".html", ".htm", ".log", ".txt", ".trace", ".jsonl", ".csv", ".png", ".jpg", ".jpeg", ".webp", ".gif"]);

export async function scanP0BArtifactDirectory(root) {
  const findings = [];
  const rootPath = await assertSafeRoot(root);
  const queue = [rootPath];
  let files = 0;
  while (queue.length > 0) {
    const current = queue.shift();
    let entries;
    try { entries = await fs.readdir(current, { withFileTypes: true }); }
    catch { findings.push({ code: "io_error", path: path.relative(rootPath, current) || "." }); continue; }
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(rootPath, absolute) || entry.name;
      if (entry.isSymbolicLink()) {
        findings.push({ code: "symlink", path: relative });
        continue;
      }
      if (entry.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (!entry.isFile()) {
        findings.push({ code: "unsupported_entry", path: relative });
        continue;
      }
      files += 1;
      if (files > MAX_FILES) {
        findings.push({ code: "file_limit", path: relative });
        return findings;
      }
      let stat;
      try { stat = await fs.stat(absolute); }
      catch { findings.push({ code: "io_error", path: relative }); continue; }
      if (stat.size > MAX_FILE_BYTES) {
        findings.push({ code: "file_size", path: relative });
        continue;
      }
      const extension = path.extname(entry.name).toLowerCase();
      if (!SCANNED_EXTENSIONS.has(extension)) continue;
      let bytes;
      try { bytes = await fs.readFile(absolute); }
      catch { findings.push({ code: "io_error", path: relative }); continue; }
      // Screenshot files are binary, but EXIF/XMP metadata is often ASCII.
      // Scan both decodings without ever returning the decoded content.
      const text = bytes.includes(0) ? bytes.toString("latin1") : bytes.toString("utf8");
      for (const [code, pattern] of DENYLIST) {
        if (pattern.test(text) || pattern.test(entry.name)) findings.push({ code, path: relative });
      }
    }
  }
  return findings.sort((left, right) => left.path.localeCompare(right.path) || left.code.localeCompare(right.code));
}

async function assertSafeRoot(root) {
  if (typeof root !== "string" || !path.isAbsolute(root)) throw new Error("artifact root is invalid");
  let stat;
  try { stat = await fs.lstat(root); } catch { throw new Error("artifact root is unavailable"); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("artifact root is unsafe");
  return root;
}

test("P0-B artifact scanner rejects browser/network/HTML/log metadata secrets without echoing values", { skip: !ARTIFACT_DIR }, async () => {
  const findings = await scanP0BArtifactDirectory(ARTIFACT_DIR);
  assert.deepEqual(findings, [], safeFindingMessage(findings));
});

test("P0-B artifact scanner detects every denylist class and emits no secret value", async (t) => {
  const directory = await fs.mkdtemp(path.join("/tmp", "agentpass-p0b-artifacts-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.mkdir(path.join(directory, "browser"));
  await fs.writeFile(path.join(directory, "browser", "storage.json"), JSON.stringify({ cookie: "COOKIE_VALUE_SHOULD_NOT_ECHO", csrf_token: "CSRF_VALUE" }));
  await fs.writeFile(path.join(directory, "network.har"), JSON.stringify({ request: { headers: [{ name: "Authorization", value: "BEARER_VALUE" }, { name: "AgentPass-Nonce", value: "NONCE_VALUE" }] } }));
  await fs.writeFile(path.join(directory, "page.html"), "<html data-webauthn-challenge=CHALLENGE_VALUE>policy_scope=POLICY_VALUE</html>");
  await fs.writeFile(path.join(directory, "run.log"), "enrollment_credential=ENROLLMENT_VALUE private_key=PRIVATE_VALUE");
  const findings = await scanP0BArtifactDirectory(directory);
  const codes = new Set(findings.map((finding) => finding.code));
  for (const code of ["cookie", "csrf", "recent_auth", "capability", "nonce", "private_key", "enrollment", "policy_body"]) assert.equal(codes.has(code), true, safeFindingMessage(findings));
  assert.doesNotMatch(safeFindingMessage(findings), /COOKIE_VALUE|CSRF_VALUE|BEARER_VALUE|NONCE_VALUE|CHALLENGE_VALUE|POLICY_VALUE|ENROLLMENT_VALUE|PRIVATE_VALUE/u);
});

test("P0-B artifact scanner fails closed on symlink artifacts", async (t) => {
  const directory = await fs.mkdtemp(path.join("/tmp", "agentpass-p0b-artifacts-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.symlink("/tmp", path.join(directory, "linked"));
  const findings = await scanP0BArtifactDirectory(directory);
  assert.deepEqual(findings, [{ code: "symlink", path: "linked" }]);
});

function safeFindingMessage(findings) {
  return JSON.stringify(findings.map(({ code, path: relativePath }) => ({ code, path: relativePath })));
}
