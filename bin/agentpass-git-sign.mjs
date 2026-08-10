#!/usr/bin/env node
process.argv = [process.argv[0], process.argv[1], "git-sign", ...process.argv.slice(2)];
await import("./agentpass.mjs");
