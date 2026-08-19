#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import process from "node:process";

const [evidencePath = ""] = process.argv.slice(2);
const fail = (message) => { throw new Error(`cloud deployment evidence rejected: ${message}`); };
if (!evidencePath) fail("evidence path is required");

let evidence;
try { evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8")); }
catch { fail("evidence is not readable JSON"); }

const keys = Object.keys(evidence ?? {}).sort().join(",");
if (keys !== "artifact_digest,commit_sha,environment,health,revision,service,status") fail("unexpected evidence shape");
if (evidence.status !== "verified") fail("status must be verified");
if (evidence.environment !== "production") fail("environment must be production");
if (!/^sha256:[0-9a-f]{64}$/u.test(evidence.artifact_digest)) fail("artifact_digest must be a sha256 digest");
if (!/^[0-9a-f]{40}$/u.test(evidence.commit_sha)) fail("commit_sha must be a full git SHA");
if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(evidence.service)) fail("service is invalid");
if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(evidence.revision)) fail("revision is invalid");
if (!evidence.health || Object.keys(evidence.health).sort().join(",") !== "checked_at,status,url") fail("health evidence is incomplete");
if (evidence.health.status !== "ready") fail("health status must be ready");
if (!/^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]{0,251}(?::[0-9]{1,5})?\/health\/ready$/u.test(evidence.health.url)) fail("health URL must be an HTTPS readiness endpoint");
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(evidence.health.checked_at)) fail("health timestamp must be UTC RFC3339");

const canonical = JSON.stringify(evidence) + "\n";
const digest = crypto.createHash("sha256").update(canonical).digest("hex");
process.stdout.write(JSON.stringify({ status: "verified", evidence_sha256: digest, service: evidence.service, revision: evidence.revision }) + "\n");
