#!/usr/bin/env node
import { fileURLToPath } from "node:url";

const agentpassEntryPoint = fileURLToPath(new URL("./agentpass.mjs", import.meta.url));
process.argv = [process.argv[0], agentpassEntryPoint, "git-sign", ...process.argv.slice(2)];
await import("./agentpass.mjs");
