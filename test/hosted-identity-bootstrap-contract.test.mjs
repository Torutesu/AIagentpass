import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  CONTRACT_PATH,
  readAndValidateHostedIdentityBootstrapContract,
  validateHostedIdentityBootstrapContract
} from "../scripts/validate-hosted-identity-bootstrap.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");

function readContract() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, CONTRACT_PATH), "utf8"));
}

test("freezes the Hosted GitHub identity and first-organization bootstrap contract", () => {
  assert.deepEqual(readAndValidateHostedIdentityBootstrapContract({ root: ROOT }), {
    contract_id: "agentpass.hosted-identity-bootstrap",
    version: 1,
    route_count: 6,
    error_count: 16
  });
});

test("rejects a contract that trusts caller organization or role authority", () => {
  const contract = readContract();
  contract.routes[3].request.body_exact_keys.push("organization_id");
  assert.throws(() => validateHostedIdentityBootstrapContract(contract, { root: ROOT }), /organization create body is not exactly name/);
});

test("rejects a contract that replaces server-side GitHub verification with ChatGPT ambient identity", () => {
  const contract = readContract();
  contract.authority.identity_provider = "chatgpt";
  assert.throws(() => validateHostedIdentityBootstrapContract(contract, { root: ROOT }), /GitHub\/PostgreSQL/);
});

test("rejects weaker cookie, CSRF, or idempotency policy", () => {
  const contract = readContract();
  contract.transport.cookies[1].http_only = false;
  contract.transport.csrf.bootstrap_header = "x-csrf";
  contract.idempotency.organization_create.header = "X-Request-ID";
  assert.throws(() => validateHostedIdentityBootstrapContract(contract, { root: ROOT }), /Host\/HttpOnly\/Secure|CSRF header|idempotency contract/);
});
