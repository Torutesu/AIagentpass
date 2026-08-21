#!/usr/bin/env node

import readline from "node:readline";
import { createCursorLaunchPlan, projectCursorAdapterError } from "../src/adapter.mjs";
import { scanCursorAdapterArtifacts } from "../src/secret-scan.mjs";

function usage() {
  process.stderr.write("agentpass-cursor: usage plan PROJECT_DIRECTORY | scan\n");
  process.exitCode = 2;
}

async function readStdin() {
  const reader = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = [];
  for await (const line of reader) {
    lines.push(line);
    if (lines.join("\n").length > 2 * 1024 * 1024) throw new Error("input too large");
  }
  return lines.join("\n");
}

try {
  const args = process.argv.slice(2);
  if (args.length === 2 && args[0] === "plan" && !args[1].startsWith("-")) {
    process.stdout.write(`${JSON.stringify(createCursorLaunchPlan({ projectDirectory: args[1] }))}\n`);
  } else if (args.length === 1 && args[0] === "scan") {
    const input = JSON.parse(await readStdin());
    process.stdout.write(`${JSON.stringify(scanCursorAdapterArtifacts(input))}\n`);
  } else {
    usage();
  }
} catch (error) {
  const envelope = projectCursorAdapterError(error);
  process.stderr.write(`agentpass-cursor: ${envelope.error.code}\n`);
  process.exitCode = 1;
}
