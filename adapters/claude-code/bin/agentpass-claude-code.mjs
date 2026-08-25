#!/usr/bin/env node

import readline from "node:readline";
import { createClaudeCodeLaunchPlan, launchClaudeCodeLifecycle, projectClaudeCodeAdapterError } from "../src/adapter.mjs";
import { scanClaudeCodeAdapterArtifacts } from "../src/secret-scan.mjs";

function usage() {
  process.stderr.write("agentpass-claude-code: usage plan PROJECT_DIRECTORY | launch PROJECT_DIRECTORY TTL_SECONDS | scan\n");
  process.exitCode = 2;
}

async function readStdin() {
  const reader = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = [];
  let size = 0;
  for await (const line of reader) {
    size += Buffer.byteLength(line, "utf8") + 1;
    if (size > 2 * 1024 * 1024) throw new Error("input too large");
    lines.push(line);
  }
  return lines.join("\n");
}

try {
  const args = process.argv.slice(2);
  if (args.length === 2 && args[0] === "plan" && !args[1].startsWith("-")) {
    process.stdout.write(`${JSON.stringify(createClaudeCodeLaunchPlan({ projectDirectory: args[1] }))}\n`);
  } else if (args.length === 3 && args[0] === "launch" && !args[1].startsWith("-") && !args[2].startsWith("-")) {
    process.stdout.write(`${JSON.stringify(await launchClaudeCodeLifecycle({ projectDirectory: args[1], ttlSeconds: Number(args[2]) }, { platform: process.platform }))}\n`);
  } else if (args.length === 1 && args[0] === "scan") {
    const input = JSON.parse(await readStdin());
    process.stdout.write(`${JSON.stringify(scanClaudeCodeAdapterArtifacts(input))}\n`);
  } else {
    usage();
  }
} catch (error) {
  const envelope = projectClaudeCodeAdapterError(error);
  process.stderr.write(`agentpass-claude-code: ${envelope.error.code}\n`);
  process.exitCode = 1;
}
