import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { scanArchives } from "./archive-secret-scan.mjs";

test("supports file URLs and returns deterministic archive member paths", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-test-"));
  try {
    const source = path.join(root, "source");
    fs.mkdirSync(source);
    const plain = path.join(source, "space safe.txt");
    fs.writeFileSync(plain, "safe\n");
    const fileUrl = pathToFileURL(plain);

    assert.deepEqual(scanArchives([fileUrl.href]), scanArchives([plain]));
    assert.deepEqual(scanArchives([fileUrl]), scanArchives([plain]));
    assert.throws(() => scanArchives(["https://example.test/artifact.tar"]), /file scheme/u);
    const queryUrl = new URL(fileUrl.href);
    queryUrl.search = "?download=1";
    assert.throws(() => scanArchives([queryUrl]), /query-free file URL/u);

    const archive = path.join(root, "candidate.tar");
    execFileSync("tar", ["-cf", archive, "-C", source, "space safe.txt"]);
    const first = scanArchives([archive]);
    const second = scanArchives([archive]);
    assert.deepEqual(first, second);
    assert.equal(first.files[0].path, `${archive}::space safe.txt`);
    assert.equal(fs.existsSync(first.files[0].path), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects secrets, links, special entries, opaque archives, and duplicate members", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-test-"));
  try {
    const cleanArchive = path.join(root, "clean.tar");
    writeTar(cleanArchive, [{ name: "manifest.json", data: "{\"ok\":true}\n" }]);
    assert.equal(scanArchives([cleanArchive]).clean, true);

    const secretArchive = path.join(root, "secret.tar");
    writeTar(secretArchive, [{ name: "secret.txt", data: "-----BEGIN PRIVATE KEY-----\n" }]);
    assert.throws(() => scanArchives([secretArchive]), /secret material/u);

    const jsonToken = path.join(root, "json-token.json");
    fs.writeFileSync(jsonToken, '{"access_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}\n');
    assert.throws(() => scanArchives([jsonToken]), /secret material/u);

    for (const [label, type] of [["symlink", "2"], ["hardlink", "1"], ["device", "3"]]) {
      const archive = path.join(root, `${label}.tar`);
      writeTar(archive, [{ name: "entry", type, linkname: "manifest.json" }]);
      assert.throws(() => scanArchives([archive]), /unsupported entry type/u);
    }

    const duplicate = path.join(root, "duplicate.tar");
    writeTar(duplicate, [{ name: "same.txt", data: "one" }, { name: "same.txt", data: "two" }]);
    assert.throws(() => scanArchives([duplicate]), /duplicate or colliding path/u);

    const caseCollision = path.join(root, "case-collision.tar");
    writeTar(caseCollision, [{ name: "Readme.txt", data: "one" }, { name: "readme.txt", data: "two" }]);
    assert.throws(() => scanArchives([caseCollision]), /duplicate or colliding path/u);

    const zip = path.join(root, "candidate.zip");
    fs.writeFileSync(zip, "opaque");
    assert.throws(() => scanArchives([zip]), /opaque archive/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("detects credential-shaped JSON keys across syntax variants without flagging metadata", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-json-test-"));
  try {
    const cases = [
      ["access-token-camel.json", '{ "accessToken" : "short-access-token" }'],
      ["access-token-escaped.json", '{ "access\\u005fToken": "escaped-access-token" }'],
      ["api-token-spaced.json", '{ "API token" : "short-api-token" }'],
      ["api-token-kebab.json", '{ "api-token": "short-api-token" }'],
      ["credential.json", '{ "credential": "agent-credential" }'],
      ["database-url.json", '{ "database_url": "postgres://user:password@example.test/db" }'],
      ["db-url-nfkc.json", '{ "ＤＢ＿ＵＲＬ": "postgresql://user:password@example.test/db" }'],
      ["password-short.json", '{ "password": "pw" }'],
      ["secret-short.json", '{ "secret": "s3cr3t" }']
    ];
    for (const [name, contents] of cases) {
      const file = path.join(root, name);
      fs.writeFileSync(file, contents);
      assert.throws(() => scanArchives([file]), /secret material/u, name);
    }
    const safe = path.join(root, "safe-metadata.json");
    fs.writeFileSync(safe, JSON.stringify({ description: "A message can mention a secret without containing one.", message: "Password and API token are intentionally omitted.", secret_name: "release-secret", access_token: null, apiToken: "placeholder-value", clientSecret: "<redacted>", password: "", secret: false, placeholder: "[REDACTED]", redacted: true }));
    assert.doesNotThrow(() => scanArchives([safe]));
    const legacyText = path.join(root, "legacy.env");
    fs.writeFileSync(legacyText, "ACCESS_TOKEN=short-or-long-enough-for-legacy-detection\n");
    assert.throws(() => scanArchives([legacyText]), /secret material/u);
    const legacyDatabaseUrl = path.join(root, "legacy-database.env");
    fs.writeFileSync(legacyDatabaseUrl, "DATABASE_URL=postgres://user:password@example.test/db\n");
    assert.throws(() => scanArchives([legacyDatabaseUrl]), /secret material/u);
    const legacyCredential = path.join(root, "legacy-credential.env");
    fs.writeFileSync(legacyCredential, "AGENT_CREDENTIAL=short\n");
    assert.throws(() => scanArchives([legacyCredential]), /secret material/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects traversal, platform-ambiguous, and overlong tar member paths before extraction", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-test-"));
  try {
    for (const [index, name] of ["../escape", "/absolute", "C:/drive", "C:drive", "safe\\name", "safe/../secret", "．．/escape"].entries()) {
      const archive = path.join(root, `unsafe-${index}.tar`);
      writeTar(archive, [{ name, data: "safe" }]);
      assert.throws(() => scanArchives([archive]), /unsafe path|invalid member path/u);
    }

    const longName = path.join(root, "long.tar");
    writeTar(longName, [{ name: "a".repeat(128), data: "safe" }]);
    assert.throws(() => scanArchives([longName], { maximumMemberPathBytes: 64 }), /invalid member path/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("enforces deterministic byte, entry, and option limits", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-test-"));
  try {
    const plain = path.join(root, "plain.txt");
    fs.writeFileSync(plain, "safe");
    assert.throws(() => scanArchives([plain], { maximumFileBytes: 3 }), /size limit/u);
    assert.throws(() => scanArchives([plain], { maximumTotalBytes: 3 }), /size limit/u);
    assert.throws(() => scanArchives([plain], { maximumEntries: 0 }), /entry count limit/u);
    for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1.5, "1"]) {
      assert.throws(() => scanArchives([plain], { maximumFileBytes: value }), /safe integer/u);
    }
    assert.throws(() => scanArchives([plain], { maximumFileBytes: null }), /safe integer/u);
    assert.throws(() => scanArchives([plain], { maximumFileSize: 3 }), /unknown option/u);

    const archive = path.join(root, "entries.tar");
    writeTar(archive, [{ name: "one.txt", data: "1" }, { name: "two.txt", data: "2" }]);
    assert.throws(() => scanArchives([archive], { maximumEntries: 1 }), /entry count limit/u);
    assert.throws(() => scanArchives([archive], { maximumMemberPathBytes: 2 }), /invalid member path/u);

    const oversized = path.join(root, "oversized.tar");
    writeTar(oversized, [{ name: "large.txt", data: "1234" }]);
    assert.throws(() => scanArchives([oversized], { maximumFileBytes: 3 }), /size limit/u);
    assert.throws(() => scanArchives([oversized], { maximumTotalBytes: 3 }), /size limit/u);
    const nested = path.join(root, "nested.tar");
    writeTar(nested, [{ name: "inner.tar", data: "not scanned as a nested archive" }]);
    assert.throws(() => scanArchives([nested]), /nested archive must be scanned explicitly/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects symlink and hardlink files in a scanned directory", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-archive-secret-links-test-"));
  try {
    const directory = path.join(root, "release");
    fs.mkdirSync(directory);
    const target = path.join(directory, "target.json");
    fs.writeFileSync(target, '{"ok":true}\n');
    const symlink = path.join(directory, "symlink.json");
    fs.symlinkSync(target, symlink);
    assert.throws(() => scanArchives([directory]), /symlink|unsupported entry/u);

    fs.unlinkSync(symlink);
    const hardlink = path.join(directory, "hardlink.json");
    fs.linkSync(target, hardlink);
    assert.throws(() => scanArchives([directory]), /hardlink/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function writeTar(file, entries) {
  const blocks = [];
  for (const entry of entries) {
    const data = entry.type && entry.type !== "0" ? Buffer.alloc(0) : Buffer.from(entry.data ?? "");
    const header = Buffer.alloc(512);
    writeField(header, 0, 100, entry.name);
    writeField(header, 100, 8, "0000644\0");
    writeField(header, 108, 8, "0000000\0");
    writeField(header, 116, 8, "0000000\0");
    writeField(header, 124, 12, `${data.length.toString(8).padStart(11, "0")}\0`);
    writeField(header, 136, 12, "00000000000\0");
    header.fill(0x20, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    writeField(header, 157, 100, entry.linkname ?? "");
    writeField(header, 257, 6, "ustar\0");
    writeField(header, 263, 2, "00");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeField(header, 148, 8, `${checksum.toString(8).padStart(6, "0")} \0`);
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  fs.writeFileSync(file, Buffer.concat(blocks));
}

function writeField(buffer, offset, length, value) {
  Buffer.from(value).copy(buffer, offset, 0, length);
}
