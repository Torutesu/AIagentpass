import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { statSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const opsDir = dirname(fileURLToPath(import.meta.url));
const producer = join(opsDir, "create-macos-distribution-provenance.mjs");
const values = [
  "a".repeat(64),
  "b".repeat(40),
  "c".repeat(40),
  "Torutesu/AIagentpass",
  "v1.2.3-rc.1",
  "100",
  "2",
  "101",
  "200",
  "macos-arm64-release-01"
];

function run(args) {
  return execFileSync(process.execPath, [producer, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function rejectsWith(args, message) {
  assert.throws(
    () => run(args),
    (error) => {
      assert.notEqual(error.status, 0);
      assert.match(`${error.stdout ?? ""}\n${error.stderr ?? ""}`, message);
      return true;
    }
  );
}

async function fixture() {
  const base = await mkdtemp(join("/tmp", "agentpass-macos-provenance-"));
  await mkdir(join(base, "nested"));
  return { base, output: join(base, "nested", "provenance.json") };
}

async function withFixture(callback) {
  const value = await fixture();
  try {
    return await callback(value);
  } finally {
    await rm(value.base, { recursive: true, force: true });
  }
}

function argsFor(output, overrides = {}) {
  const args = [...values, output];
  for (const [index, value] of Object.entries(overrides)) args[Number(index)] = value;
  return args;
}

test("writes the canonical macOS distribution provenance record", async () => {
  await withFixture(async ({ output }) => {
    const result = JSON.parse(run(argsFor(output)));
    assert.deepEqual(result, { status: "written", output, kind: "agentpass.macos-distribution-provenance-v1" });

    const bytes = await readFile(output);
    const text = bytes.toString("utf8");
    assert.equal(text, "{\"artifact_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"ci_run_attempt\":\"2\",\"ci_run_id\":\"100\",\"kind\":\"agentpass.macos-distribution-provenance-v1\",\"release_tag\":\"v1.2.3-rc.1\",\"repository\":\"Torutesu/AIagentpass\",\"runner_id\":\"macos-arm64-release-01\",\"source_commit\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"source_tree\":\"cccccccccccccccccccccccccccccccccccccccc\",\"verification_job_id\":\"200\",\"verification_run_id\":\"101\"}\n");
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.equal(statSync(output).nlink, 1);
  });
});

test("rejects every malformed or unsafe provenance value", async () => {
  await withFixture(async ({ output }) => {
    const cases = [
      [0, "A".repeat(64), /artifact_sha256 has invalid grammar/u],
      [1, "d".repeat(39), /source_commit has invalid grammar/u],
      [2, "E".repeat(40), /source_tree has invalid grammar/u],
      [3, "owner", /repository has invalid grammar/u],
      [4, "release-1.2.3", /release_tag has invalid grammar/u],
      [5, "0", /ci_run_id has invalid grammar/u],
      [6, "01", /ci_run_attempt has invalid grammar/u],
      [7, "100", /ci_run_id and verification_run_id must be distinct/u],
      [8, "0", /verification_job_id has invalid grammar/u],
      [9, "runner-local-01", /runner_id contains a local marker/u],
      [10, "relative/output.json", /output has invalid grammar/u]
    ];
    for (const [index, value, message] of cases) rejectsWith(argsFor(output, { [index]: value }), message);
  });
});

test("rejects all supported local runner markers", async () => {
  await withFixture(async ({ output }) => {
    for (const marker of ["local", "static", "unit", "mock", "fixture", "fake", "simulator", "emulator", "sandbox", "test", "macos-latest"]) {
      rejectsWith(argsFor(output, { 9: `protected-${marker}-runner` }), /runner_id contains a local marker/u);
    }
  });
});

test("uses exclusive creation and preserves an existing output", async () => {
  await withFixture(async ({ output }) => {
    const sentinel = "do not overwrite\n";
    await writeFile(output, sentinel, { mode: 0o600 });
    rejectsWith(argsFor(output), /output already exists/u);
    assert.equal(await readFile(output, "utf8"), sentinel);
  });
});
