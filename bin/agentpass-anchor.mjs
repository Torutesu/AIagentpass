#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { acquireAnchorPruneLease, createAnchorServer, enrollAnchorTenant, initializeAnchor, readAnchorPruneHead, releaseAnchorPruneLease, submitAnchorKeyTransition, submitAnchorPrune, verifyAnchorTenant } from "../lib/anchor.mjs";
import { canonicalJson } from "../lib/identity.mjs";

const [, , command, ...args] = process.argv;

function usage() {
  console.log(`AgentPass Anchor 0.18.0

Commands:
  init DIR                         initialize anchor storage and receipt key
  enroll DIR TENANT PUBLIC_KEY [--installation-id ID --recovery-policy FILE]
                                   enroll a key and optionally pin v3 recovery trust
  transition DIR TENANT FILE      accept a v2 rotation or v3 recovery transition
  prune DIR TENANT FILE LEASE     authorize an audit prune with an active exact lease
  prune-head DIR TENANT NONCE
                                   read a fresh signed audit-prune head (non-mutating)
  prune-lease-acquire DIR TENANT REQUEST
                                   acquire a lease from an audit-key-signed request
  prune-lease-release DIR TENANT LEASE REQUEST
                                   release a lease with a same-principal signed request
  verify DIR TENANT               verify the full append-only tenant chain
  serve DIR [--host HOST] [--port PORT]

Transition migration:
  New submissions require schema v2 (old/new key possession) or schema v3
  (enrolled threshold recovery authorization plus replacement-key possession),
  with the final checkpoint receipt, zero-pending attestation, and event boundary.
  Stored v1 transitions remain verification-only history and are sealed into
  the first v2 event-chain root.
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
    const installationId = flag("--installation-id");
    const recoveryPolicyFile = flag("--recovery-policy");
    if ((installationId === undefined) !== (recoveryPolicyFile === undefined)) throw new Error("Recovery-enabled enrollment requires --installation-id and --recovery-policy together");
    const recoveryPolicy = recoveryPolicyFile === undefined ? undefined : JSON.parse(fs.readFileSync(path.resolve(recoveryPolicyFile), "utf8"));
    console.log(JSON.stringify(enrollAnchorTenant(path.resolve(args[0]), args[1], publicKey, { installationId, recoveryPolicy }), null, 2));
  } else if (command === "verify") {
    if (!args[0] || !args[1]) throw new Error("Anchor verify requires DIR TENANT");
    console.log(JSON.stringify(verifyAnchorTenant(path.resolve(args[0]), args[1]), null, 2));
  } else if (command === "transition") {
    if (!args[0] || !args[1] || !args[2]) throw new Error("Anchor transition requires DIR TENANT FILE");
    const transition = JSON.parse(fs.readFileSync(path.resolve(args[2]), "utf8"));
    console.log(JSON.stringify(submitAnchorKeyTransition(path.resolve(args[0]), args[1], transition), null, 2));
  } else if (command === "prune") {
    if (!args[0] || !args[1] || !args[2] || !args[3] || args.length !== 4) throw new Error("Anchor prune requires DIR TENANT FILE LEASE");
    const bytes = fs.readFileSync(path.resolve(args[2]));
    const authorization = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(Buffer.from(canonicalJson(authorization)))) throw new Error("Audit prune authorization file must be exact canonical JSON without trailing bytes");
    const leaseBytes = fs.readFileSync(path.resolve(args[3]));
    const lease = JSON.parse(leaseBytes.toString("utf8"));
    if (!leaseBytes.equals(Buffer.from(canonicalJson(lease)))) throw new Error("Audit prune lease file must be exact canonical JSON without trailing bytes");
    console.log(JSON.stringify(submitAnchorPrune(path.resolve(args[0]), args[1], authorization, Date.now(), lease), null, 2));
  } else if (command === "prune-head") {
    if (!args[0] || !args[1] || !args[2] || args.length !== 3) throw new Error("Anchor prune-head requires DIR TENANT NONCE");
    process.stdout.write(`${canonicalJson(readAnchorPruneHead(path.resolve(args[0]), args[1], args[2], Date.now()))}\n`);
  } else if (command === "prune-lease-acquire") {
    if (!args[0] || !args[1] || !args[2] || args.length !== 3) throw new Error("Anchor prune-lease-acquire requires DIR TENANT REQUEST");
    const bytes = fs.readFileSync(path.resolve(args[2])); const request = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(Buffer.from(canonicalJson(request)))) throw new Error("Audit prune lease request file must be exact canonical JSON");
    process.stdout.write(`${canonicalJson(acquireAnchorPruneLease(path.resolve(args[0]), args[1], request))}\n`);
  } else if (command === "prune-lease-release") {
    if (!args[0] || !args[1] || !args[2] || !args[3] || args.length !== 4) throw new Error("Anchor prune-lease-release requires DIR TENANT LEASE REQUEST");
    const lease = JSON.parse(fs.readFileSync(path.resolve(args[2]), "utf8"));
    const request = JSON.parse(fs.readFileSync(path.resolve(args[3]), "utf8"));
    console.log(JSON.stringify(releaseAnchorPruneLease(path.resolve(args[0]), args[1], lease, request), null, 2));
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
