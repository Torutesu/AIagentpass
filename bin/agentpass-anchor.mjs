#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createAnchorServer, enrollAnchorTenant, initializeAnchor, verifyAnchorTenant } from "../lib/anchor.mjs";

const [, , command, ...args] = process.argv;

function usage() {
  console.log(`AgentPass Anchor 0.17.0

Commands:
  init DIR                         initialize anchor storage and receipt key
  enroll DIR TENANT PUBLIC_KEY    enroll an audit checkpoint verification key
  verify DIR TENANT               verify the full append-only tenant chain
  serve DIR [--host HOST] [--port PORT]
`);
}

function flag(name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
}

try {
  if (command === "init") {
    if (!args[0]) throw new Error("Anchor init requires a storage directory");
    console.log(JSON.stringify(initializeAnchor(path.resolve(args[0])), null, 2));
  } else if (command === "enroll") {
    if (!args[0] || !args[1] || !args[2]) throw new Error("Anchor enroll requires DIR TENANT PUBLIC_KEY");
    const publicKey = fs.readFileSync(path.resolve(args[2]), "utf8");
    console.log(JSON.stringify(enrollAnchorTenant(path.resolve(args[0]), args[1], publicKey), null, 2));
  } else if (command === "verify") {
    if (!args[0] || !args[1]) throw new Error("Anchor verify requires DIR TENANT");
    console.log(JSON.stringify(verifyAnchorTenant(path.resolve(args[0]), args[1]), null, 2));
  } else if (command === "serve") {
    if (!args[0]) throw new Error("Anchor serve requires a storage directory");
    const host = flag("--host", "127.0.0.1");
    const port = Number(flag("--port", "8787"));
    if (typeof host !== "string" || !host) throw new Error("Anchor host is invalid");
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Anchor port is invalid");
    const server = createAnchorServer(path.resolve(args[0]));
    server.listen(port, host, () => console.log(`AgentPass anchor listening on http://${host}:${port}`));
    const shutdown = () => server.close(() => process.exit(0));
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    usage();
  }
} catch (error) {
  console.error(`agentpass-anchor: ${error.message}`);
  process.exitCode = 1;
}
