#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const result = spawnSync(process.execPath, [path.join(directory, "agentpass.mjs"), "push-check", ...process.argv.slice(2)], { stdio: "inherit" });
process.exitCode = result.status ?? 1;
