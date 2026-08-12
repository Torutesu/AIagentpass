#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const testFile = path.join(root, "test/support/p0b/harness.test.mjs");
const child = spawn(process.execPath, ["--test", testFile], { cwd: root, env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR }, shell: false, stdio: "inherit" });
child.once("error", () => process.exitCode = 1);
child.once("exit", (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
