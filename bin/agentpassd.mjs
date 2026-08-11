#!/usr/bin/env node
import { createBroker } from "../lib/broker.mjs";
import { socketPath } from "../lib/config.mjs";

const server = createBroker();
server.once("listening", () => console.log(`AgentPass broker listening on ${socketPath()}`));

function shutdown() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
