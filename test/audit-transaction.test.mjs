import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { audit, verifyAudit } from "../lib/audit.mjs";
import { createAuthorizationTransaction } from "../lib/audit-transaction.mjs";

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function intent(requestId = crypto.randomUUID()) {
  return {
    request_id: requestId,
    trusted_context_digest: sha("trusted-context"),
    policy_sequence: 7,
    capability_sequence: 11,
    payload_digest: sha("commit-payload")
  };
}

function fixture({ realAudit = false, failEvent = null } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-audit-transaction-"));
  const events = [];
  let calls = 0;
  const appendAudit = (event) => {
    calls += 1;
    if (failEvent === event.event) throw new Error("injected append failure");
    if (realAudit) {
      const record = audit(event, directory);
      events.push(record);
      return record;
    }
    const record = { ...event, hash: sha(`${events.length}:${JSON.stringify(event)}`) };
    events.push(record);
    return record;
  };
  const transaction = createAuthorizationTransaction({ directory, appendAudit, verifyAudit: () => ({ valid: true }) });
  return { directory, events, transaction, get appendCalls() { return calls; } };
}

test("allow is intent -> signer -> durable result, using injected existing audit primitives", async () => {
  const value = fixture({ realAudit: true });
  const request = intent();
  let signerCalls = 0;
  const result = await value.transaction.execute({ intent: request, signer: async (input) => {
    signerCalls += 1;
    assert.deepEqual(input, { request_id: request.request_id, payload_digest: request.payload_digest });
    assert.deepEqual(value.events.map((event) => event.event), ["authorized_intent"]);
    return { status: 0, stdout: Buffer.from("signature") };
  } });

  assert.equal(result.outcome, "allow");
  assert.deepEqual(result.signature, Buffer.from("signature"));
  assert.equal(signerCalls, 1);
  assert.deepEqual(value.events.map((event) => event.event), ["authorized_intent", "allow"]);
  assert.equal(value.events[0].request_id, request.request_id);
  assert.equal(value.events[1].intent_hash, value.events[0].hash);
  assert.equal(verifyAudit(value.directory).valid, true);
  const state = fs.readFileSync(path.join(value.directory, "audit-transaction.state.json"), "utf8");
  assert.doesNotMatch(state, /commit-payload|trusted-context|session|capability_token|payload_base64/);
  assert.equal(fs.lstatSync(path.join(value.directory, "audit-transaction.state.json")).mode & 0o077, 0);
});

test("deny is durable, exactly once, and never calls the signer", async () => {
  const value = fixture();
  const request = intent();
  let signerCalls = 0;
  const first = await value.transaction.execute({ intent: request, decision: "deny", reason: "policy_denied", signer: () => { signerCalls += 1; } });
  const second = await value.transaction.execute({ intent: request, decision: "deny", reason: "policy_denied", signer: () => { signerCalls += 1; } });
  assert.equal(first.outcome, "deny");
  assert.equal(second.outcome, "deny");
  assert.equal(second.replayed, true);
  assert.equal(signerCalls, 0);
  assert.deepEqual(value.events.map((event) => event.event), ["deny"]);
});

test("a reported signer failure gets a durable error and is not retried", async () => {
  const value = fixture();
  const request = intent();
  let signerCalls = 0;
  const first = await value.transaction.execute({ intent: request, signer: async () => {
    signerCalls += 1;
    return { status: 19, stderr: "secret signer detail must not be audited" };
  } });
  const second = await value.transaction.execute({ intent: request, signer: async () => { signerCalls += 1; return Buffer.from("wrong"); } });
  assert.equal(first.outcome, "error");
  assert.equal(second.outcome, "error");
  assert.equal(signerCalls, 1);
  assert.equal(value.events.at(-1).event, "error");
  assert.doesNotMatch(fs.readFileSync(path.join(value.directory, "audit-transaction.state.json"), "utf8"), /secret signer detail/);
});

test("final append failure withholds the signature and retry appends the result without signing again", async () => {
  const value = fixture({ failEvent: "allow" });
  const request = intent();
  let signerCalls = 0;
  await assert.rejects(value.transaction.execute({ intent: request, signer: async () => { signerCalls += 1; return Buffer.from("secret-signature"); } }), (error) => error.code === "result_not_durable" && error.outcome === "outcome_unknown");
  assert.equal(signerCalls, 1);
  assert.equal(value.events.map((event) => event.event).join(","), "authorized_intent");
  assert.equal(value.transaction.getOutcome(request.request_id).outcome, "allow");

  value.transaction.appendAudit = (event) => {
    const record = { ...event, hash: sha(`${value.events.length}:${JSON.stringify(event)}`) };
    value.events.push(record);
    return record;
  };
  const retried = await value.transaction.execute({ intent: request, signer: async () => { signerCalls += 1; return Buffer.from("must-not-run"); } });
  assert.deepEqual(retried.signature, Buffer.from("secret-signature"));
  assert.equal(signerCalls, 1);
  assert.deepEqual(value.events.map((event) => event.event), ["authorized_intent", "allow"]);
});

test("intent append failure is fail-closed before signer use", async () => {
  const value = fixture({ failEvent: "authorized_intent" });
  let signerCalls = 0;
  await assert.rejects(value.transaction.execute({ intent: intent(), signer: async () => { signerCalls += 1; return Buffer.from("bad"); } }), (error) => error.code === "intent_not_durable");
  assert.equal(signerCalls, 0);
  assert.equal(fs.existsSync(path.join(value.directory, "audit-transaction.state.json")), false);
});

test("an ambiguous signer crash is durably surfaced as outcome_unknown", async () => {
  const value = fixture();
  const request = intent();
  let signerCalls = 0;
  const result = await value.transaction.execute({ intent: request, signer: async () => { signerCalls += 1; throw new Error("may have signed"); } });
  assert.equal(result.outcome, "outcome_unknown");
  assert.equal(signerCalls, 1);
  assert.equal(value.events.at(-1).event, "outcome_unknown");
  const restarted = createAuthorizationTransaction({ directory: value.directory, appendAudit: value.transaction.appendAudit, verifyAudit: () => ({ valid: true }) });
  const replay = await restarted.execute({ intent: request, signer: async () => { signerCalls += 1; return Buffer.from("bad"); } });
  assert.equal(replay.outcome, "outcome_unknown");
  assert.equal(signerCalls, 1);
});

test("explicit recovery turns a pending result into an outcome_unknown incident across restart", async () => {
  const value = fixture({ failEvent: "allow" });
  const request = intent();
  await assert.rejects(value.transaction.execute({ intent: request, signer: () => Buffer.from("signature") }), /result_not_durable/);
  const restarted = createAuthorizationTransaction({ directory: value.directory, appendAudit: value.transaction.appendAudit, verifyAudit: () => ({ valid: true }) });
  const incidents = await restarted.recover();
  assert.equal(incidents[0].outcome, "outcome_unknown");
  assert.equal(restarted.getOutcome(request.request_id).outcome, "outcome_unknown");
  assert.equal((await restarted.execute({ intent: request, signer: () => Buffer.from("must-not-run") })).outcome, "outcome_unknown");
});

test("same request ID with different authorization material is rejected", async () => {
  const value = fixture();
  const request = intent();
  await value.transaction.execute({ intent: request, decision: "deny" });
  await assert.rejects(value.transaction.execute({ intent: { ...request, policy_sequence: 8 }, decision: "deny" }), (error) => error.code === "request_id_reuse");
  assert.equal(value.events.length, 1);
});

test("concurrent transaction instances serialize one request and invoke signer once", async () => {
  const value = fixture();
  const other = createAuthorizationTransaction({ directory: value.directory, appendAudit: value.transaction.appendAudit, verifyAudit: () => ({ valid: true }) });
  const request = intent();
  let signerCalls = 0;
  const signer = async () => { signerCalls += 1; await new Promise((resolve) => setTimeout(resolve, 20)); return Buffer.from("signature"); };
  const results = await Promise.all([value.transaction.execute({ intent: request, signer }), other.execute({ intent: request, signer })]);
  assert.equal(signerCalls, 1);
  assert.deepEqual(value.events.map((event) => event.event), ["authorized_intent", "allow"]);
  assert.equal(results[0].outcome, "allow");
  assert.equal(results[1].outcome, "allow");
});

test("sensitive and unbounded input is rejected before any audit or signer operation", async () => {
  const value = fixture();
  let signerCalls = 0;
  await assert.rejects(value.transaction.execute({ intent: { ...intent(), session_token: "token" }, signer: () => { signerCalls += 1; return Buffer.from("x"); } }), /sensitive_or_unknown_field/);
  await assert.rejects(value.transaction.execute({ intent: { ...intent(), request_id: "../escape" }, signer: () => { signerCalls += 1; return Buffer.from("x"); } }), /request_id_invalid/);
  await assert.rejects(value.transaction.execute({ intent: { ...intent(), payload_digest: "f".repeat(65) }, signer: () => { signerCalls += 1; return Buffer.from("x"); } }), /payload_digest_invalid/);
  assert.equal(signerCalls, 0);
  assert.equal(value.events.length, 0);
});

test("state and lock symlinks are rejected, and corrupt or oversized state fails closed", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-audit-transaction-safe-"));
  const state = path.join(directory, "audit-transaction.state.json");
  fs.symlinkSync("/tmp", state);
  const linked = createAuthorizationTransaction({ directory, appendAudit: () => ({ hash: "a".repeat(64) }), verifyAudit: () => ({ valid: true }) });
  await assert.rejects(linked.execute({ intent: intent(), signer: () => Buffer.from("x") }), /Unsafe audit transaction state file/);
  fs.unlinkSync(state);
  fs.writeFileSync(state, "not-json", { mode: 0o600 });
  await assert.rejects(linked.execute({ intent: intent(), signer: () => Buffer.from("x") }), /transaction_state_invalid/);
  fs.writeFileSync(state, "x".repeat(2 * 1024 * 1024 + 1), { mode: 0o600 });
  await assert.rejects(linked.execute({ intent: intent(), signer: () => Buffer.from("x") }), /transaction_state_too_large/);
  fs.unlinkSync(state);
  fs.symlinkSync("/tmp", path.join(directory, "audit-transaction.state.lock"));
  await assert.rejects(linked.execute({ intent: intent(), signer: () => Buffer.from("x") }), /Unsafe audit transaction state file/);
});

test("invalid audit chain fails closed before signer invocation", async () => {
  const value = fixture();
  value.transaction.verifyAudit = () => ({ valid: false });
  let signerCalls = 0;
  await assert.rejects(value.transaction.execute({ intent: intent(), signer: () => { signerCalls += 1; return Buffer.from("x"); } }), /audit_chain_invalid/);
  assert.equal(signerCalls, 0);
});
