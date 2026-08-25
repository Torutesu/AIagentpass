import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  createOwnerRecoveryNotificationPublisher,
  OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES
} from "../../src/postgres/owner-recovery-notification-publisher.mjs";

const IDS = Object.freeze({
  organization_id: "11111111-1111-4111-8111-111111111111",
  event_id: "22222222-2222-4222-8222-222222222222",
  request_id: "33333333-3333-4333-8333-333333333333",
  subject_member_id: "44444444-4444-4444-8444-444444444444"
});
const EVENT = Object.freeze({
  schema_version: 1,
  kind: "owner-recovery-notification",
  ...IDS,
  event_type: "recovery.request.created",
  created_at: "2026-08-14T00:00:00.000Z"
});
const SECRET = "webhook-secret-do-not-leak";
const URL = "https://notify.example.test/owner-recovery";
const CONFIRMATION_URL = "https://notify.example.test/owner-recovery/acceptance";
const RESOLVER_BINDING_DIGEST = "a".repeat(64);
const FIXED_BINDING = Object.freeze({ bindingId: "owner-recovery-primary", bindingKeyVersion: 1, bindingDigest: "b".repeat(64) });
const PROVIDER_BINDING = Object.freeze({ binding_id: FIXED_BINDING.bindingId, key_version: FIXED_BINDING.bindingKeyVersion, binding_digest: FIXED_BINDING.bindingDigest });

function configuredPublisher(options) {
  return createOwnerRecoveryNotificationPublisher({ ...FIXED_BINDING, confirmationUrl: CONFIRMATION_URL, ...options });
}

function acceptanceResponse(accepted, binding = PROVIDER_BINDING, idempotency_key = EVENT.event_id) {
  return { accepted, idempotency_key, provider_binding: binding };
}

test("sends only the public event over HTTPS with event_id as Idempotency-Key", async () => {
  const transport = fakeTransport({ statusCode: 202, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } });
  const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  const result = await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT, signal: new AbortController().signal });
  assert.deepEqual(result, { accepted: true, duplicate: false, idempotency_key: EVENT.event_id });
  assert.equal(transport.requests.length, 1);
  const request = transport.requests[0];
  assert.equal(request.url.protocol, "https:");
  assert.equal(request.url.href, URL);
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.headers["idempotency-key"], EVENT.event_id);
  assert.equal(request.options.headers.authorization, `Bearer ${SECRET}`);
  assert.equal(request.options.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(request.body.toString("utf8")), EVENT);
  assert.equal(request.body.toString("utf8").includes(SECRET), false);
  assert.deepEqual(Object.keys(publisher.binding).sort(), ["binding_digest", "binding_id", "key_version"]);
  assert.match(publisher.binding.binding_digest, /^[0-9a-f]{64}$/u);
});

test("looks up acceptance with the closed binding contract and maps accepted/not-found", async () => {
  const acceptedTransport = fakeTransport({ statusCode: 200, body: acceptanceResponse(true) });
  const acceptedPublisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: acceptedTransport.requestFn });
  assert.deepEqual(await acceptedPublisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), { accepted: true, idempotency_key: EVENT.event_id });
  const acceptedRequest = acceptedTransport.requests[0];
  assert.equal(acceptedRequest.url.protocol, "https:");
  assert.equal(acceptedRequest.url.href, CONFIRMATION_URL);
  assert.equal(acceptedRequest.options.method, "POST");
  assert.equal(acceptedRequest.options.headers.authorization, `Bearer ${SECRET}`);
  assert.equal(acceptedRequest.options.headers["idempotency-key"], EVENT.event_id);
  assert.deepEqual(JSON.parse(acceptedRequest.body.toString("utf8")), {
    schema_version: 1,
    kind: "owner-recovery-notification-acceptance-lookup",
    provider_binding: PROVIDER_BINDING,
    idempotency_key: EVENT.event_id
  });
  assert.equal(acceptedRequest.body.toString("utf8").includes(SECRET), false);

  const notFoundTransport = fakeTransport({ statusCode: 404, body: acceptanceResponse(false) });
  const notFoundPublisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: notFoundTransport.requestFn });
  assert.deepEqual(await notFoundPublisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), { accepted: false, idempotency_key: EVENT.event_id });
});

test("requires confirmation configuration and never derives binding from either endpoint", () => {
  assert.throws(() => createOwnerRecoveryNotificationPublisher({
    webhookUrl: URL,
    authorizationSecret: SECRET,
    ...FIXED_BINDING
  }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);
  assert.throws(() => configuredPublisher({
    confirmationUrl: CONFIRMATION_URL,
    resolveConfirmationUrl: () => CONFIRMATION_URL
  }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);
  assert.throws(() => createOwnerRecoveryNotificationPublisher({
    webhookUrl: URL,
    confirmationUrl: CONFIRMATION_URL,
    authorizationSecret: SECRET,
    bindingId: FIXED_BINDING.bindingId,
    bindingKeyVersion: FIXED_BINDING.bindingKeyVersion
  }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);
});

test("rejects lookup binding or idempotency-key substitution", async () => {
  for (const body of [
    acceptanceResponse(true, { ...PROVIDER_BINDING, binding_id: "other-provider" }),
    acceptanceResponse(true, { ...PROVIDER_BINDING, key_version: 2 }),
    acceptanceResponse(true, { ...PROVIDER_BINDING, binding_digest: "c".repeat(64) }),
    acceptanceResponse(true, PROVIDER_BINDING, IDS.request_id)
  ]) {
    const transport = fakeTransport({ statusCode: 200, body });
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
    await assert.rejects(publisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), (error) => {
      assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED);
      assert.equal(error.message.includes(SECRET), false);
      assert.equal("cause" in error, false);
      return true;
    });
  }
});

test("fails closed on malformed lookup responses, including framing and truncation", async () => {
  for (const response of [
    { statusCode: 200, body: { accepted: true, idempotency_key: EVENT.event_id } },
    { statusCode: 200, body: { accepted: true, idempotency_key: EVENT.event_id, provider_binding: { ...PROVIDER_BINDING, extra: true } } },
    { statusCode: 200, rawBody: `{"accepted":true,"idempotency_key":"${EVENT.event_id}","idempotency_key":"${EVENT.event_id}","provider_binding":${JSON.stringify(PROVIDER_BINDING)}}` },
    { statusCode: 200, headers: { "content-type": "text/plain" }, body: acceptanceResponse(true) },
    { statusCode: 302, body: acceptanceResponse(true) },
    { statusCode: 404, body: acceptanceResponse(true) },
    { statusCode: 200, rawBody: "not-json" },
    { statusCode: 200, headers: { "content-length": "100" }, rawBody: "x" },
    { statusCode: 200, headers: { "transfer-encoding": ["chunked", "chunked"] }, body: acceptanceResponse(true) },
    { statusCode: 200, headers: { "transfer-encoding": "gzip" }, body: acceptanceResponse(true) }
  ]) {
    const transport = fakeTransport(response);
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
    await assert.rejects(publisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED });
  }

  const truncatedTransport = fakeTransport({
    statusCode: 200,
    headers: { "content-length": "999" },
    rawBody: JSON.stringify(acceptanceResponse(true)),
    truncated: true
  });
  const truncatedPublisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: truncatedTransport.requestFn });
  await assert.rejects(truncatedPublisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE });
});

test("bounds lookup responses before and during streaming", async () => {
  for (const response of [
    { statusCode: 200, headers: { "content-length": "6" }, rawBody: "1234567" },
    { statusCode: 200, chunks: ["123456", "7"], body: acceptanceResponse(true) }
  ]) {
    const transport = fakeTransport(response);
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn, maxResponseBytes: 6 });
    await assert.rejects(publisher.lookupAcceptance({ idempotency_key: EVENT.event_id }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESPONSE_TOO_LARGE });
  }
});

test("uses the confirmation and protected authorization resolvers for lookup", async () => {
  const calls = [];
  const transport = fakeTransport({ statusCode: 200, body: acceptanceResponse(true) });
  const publisher = configuredPublisher({
    webhookUrl: URL,
    confirmationUrl: undefined,
    resolveConfirmationUrl: async (input) => { calls.push(["confirmation", input]); return CONFIRMATION_URL; },
    authorizationSecret: undefined,
    resolveAuthorizationSecret: async (input) => { calls.push(["secret", input]); return SECRET; },
    requestFn: transport.requestFn
  });
  await publisher.lookupAcceptance({ idempotency_key: EVENT.event_id });
  assert.deepEqual(calls.map(([kind]) => kind), ["confirmation", "secret"]);
  assert.deepEqual(Object.keys(calls[0][1]).sort(), ["idempotency_key", "signal"]);
  assert.equal(calls[0][1].idempotency_key, EVENT.event_id);
  assert.equal(JSON.stringify(calls).includes(SECRET), false);

  const failedConfirmation = configuredPublisher({
    webhookUrl: URL,
    confirmationUrl: undefined,
    resolveConfirmationUrl: async () => { throw new Error(`confirmation secret=${SECRET}`); },
    authorizationSecret: SECRET,
    requestFn: transport.requestFn
  });
  await assert.rejects(failedConfirmation.lookupAcceptance({ idempotency_key: EVENT.event_id }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER && !error.message.includes(SECRET));

  const failedSecret = configuredPublisher({
    webhookUrl: URL,
    authorizationSecret: undefined,
    resolveAuthorizationSecret: async () => { throw new Error(`authorization secret=${SECRET}`); },
    requestFn: transport.requestFn
  });
  await assert.rejects(failedSecret.lookupAcceptance({ idempotency_key: EVENT.event_id }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER && !error.message.includes(SECRET));
});

test("follows the caller AbortSignal during acceptance lookup", async () => {
  const controller = new AbortController();
  const transport = fakeTransport({ hang: true });
  const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  const pending = publisher.lookupAcceptance({ idempotency_key: EVENT.event_id, signal: controller.signal });
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(pending, { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.ABORTED });
  assert.equal(transport.requests[0].destroyed, true);
});

test("supports fixed or resolver-supplied endpoint and secret without putting either in resolver event data", async () => {
  const transport = fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: true, idempotency_key: EVENT.event_id } });
  const calls = [];
  const publisher = configuredPublisher({
    resolveWebhookUrl: async (input) => { calls.push(["url", input]); return URL; },
    resolveAuthorizationSecret: async (input) => { calls.push(["secret", input]); return SECRET; },
    bindingDigest: RESOLVER_BINDING_DIGEST,
    requestFn: transport.requestFn
  });
  await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT });
  assert.deepEqual(calls.map(([kind]) => kind), ["url", "secret"]);
  assert.equal(JSON.stringify(calls).includes(SECRET), false);
  assert.equal(JSON.stringify(calls).includes("password"), false);
  assert.equal(transport.requests[0].url.href, URL);
});

test("rejects insecure or ambiguous configuration and malformed public input", async () => {
  assert.throws(() => createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);
  for (const options of [
    { webhookUrl: "http://notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://user:pass@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://:@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://notify.example.test/hook#fragment", authorizationSecret: SECRET },
    { webhookUrl: URL, authorizationSecret: SECRET, resolveWebhookUrl: () => URL },
    { webhookUrl: URL, authorizationSecret: SECRET, resolveAuthorizationSecret: () => SECRET },
    { webhookUrl: URL, authorizationSecret: "line\nbreak" }
  ]) assert.throws(() => configuredPublisher(options), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);

  const transport = fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } });
  const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: { ...EVENT, provider_secret: SECRET } }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT);
  await assert.rejects(publisher.publish({ idempotency_key: IDS.request_id, event: EVENT }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT);
});

test("requires an exact accepted JSON response and never follows redirects", async () => {
  for (const response of [
    { statusCode: 204, body: null },
    { statusCode: 302, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } },
    { statusCode: 200, headers: { "content-type": "text/plain" }, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } },
    { statusCode: 200, headers: { "content-type": ["application/json", "application/json"] }, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } },
    { statusCode: 200, headers: { "content-type": "application/json, text/plain" }, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } },
    { statusCode: 200, body: { accepted: true, duplicate: false } },
    { statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: IDS.request_id } },
    { statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id, provider_secret: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id, credential: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id, secret: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id, authorization: `Bearer ${SECRET}` } },
    { statusCode: 200, rawBody: `{"accepted":true,"duplicate":false,"idempotency_key":"${EVENT.event_id}","idempotency_key":"${EVENT.event_id}"}` },
    { statusCode: 200, rawBody: "not-json" }
  ]) {
    const transport = fakeTransport(response);
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
    await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
      assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED);
      assert.equal(error.message.includes(SECRET), false);
      assert.equal("cause" in error, false);
      return true;
    });
    assert.equal(transport.requests.length, 1);
  }
});

test("rejects ambiguous response framing before accepting a provider DTO", async () => {
  for (const headers of [
    { "content-length": "35", "Content-Length": "35" },
    { "content-length": ["35", "35"] },
    { "content-length": "35", "transfer-encoding": "chunked" }
  ]) {
    const transport = fakeTransport({ statusCode: 200, headers, body: { accepted: true, duplicate: false } });
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
    await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
      assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED);
      assert.equal(error.message.includes(SECRET), false);
      assert.equal("cause" in error, false);
      return true;
    });
    assert.equal(transport.requests.length, 1);
    assert.equal(transport.requests[0].response.destroyed, true);
  }
});

test("returns an explicit provider rejection only from the strict 2xx response contract", async () => {
  const transport = fakeTransport({ statusCode: 200, body: { accepted: false, duplicate: false, idempotency_key: EVENT.event_id } });
  const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  assert.deepEqual(await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), { accepted: false, duplicate: false, idempotency_key: EVENT.event_id });
});

test("bounds provider response bytes before and during streaming", async () => {
  for (const response of [
    { statusCode: 200, headers: { "content-length": "100" }, rawBody: "x" },
    { statusCode: 200, chunks: ["x".repeat(6), "y"], body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } }
  ]) {
    const transport = fakeTransport(response);
    const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn, maxResponseBytes: 6 });
    await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESPONSE_TOO_LARGE });
  }
});

test("follows the caller AbortSignal and maps provider diagnostics to a stable opaque error", async () => {
  const controller = new AbortController();
  const transport = fakeTransport({ hang: true });
  const publisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  const pending = publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT, signal: controller.signal });
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(pending, (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.ABORTED);
  assert.equal(transport.requests[0].destroyed, true);

  const failedTransport = fakeTransport({ requestError: new Error(`provider password=${SECRET}`) });
  const failed = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: failedTransport.requestFn });
  await assert.rejects(failed.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
    assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE);
    assert.equal(error.message.includes(SECRET), false);
    assert.equal("cause" in error, false);
    return true;
  });

  const responseFailure = fakeTransport({ responseError: new Error(`response body credential=${SECRET}`) });
  const responseFailedPublisher = configuredPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: responseFailure.requestFn });
  await assert.rejects(responseFailedPublisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
    assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE);
    assert.equal(error.message.includes(SECRET), false);
    assert.equal("cause" in error, false);
    return true;
  });
});

test("maps resolver failures and invalid resolver outputs without exposing details", async () => {
  const failed = configuredPublisher({
    resolveWebhookUrl: async () => { throw new Error(`url secret=${SECRET}`); },
    resolveAuthorizationSecret: () => SECRET,
    bindingDigest: RESOLVER_BINDING_DIGEST,
    requestFn: fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } }).requestFn
  });
  await assert.rejects(failed.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER && !error.message.includes(SECRET));

  const invalid = configuredPublisher({
    resolveWebhookUrl: () => "http://not-https.example.test/hook",
    resolveAuthorizationSecret: () => SECRET,
    bindingDigest: RESOLVER_BINDING_DIGEST,
    requestFn: fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false, idempotency_key: EVENT.event_id } }).requestFn
  });
  await assert.rejects(invalid.publish({ idempotency_key: EVENT.event_id, event: EVENT }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER });
});

function fakeTransport(spec = {}) {
  const requests = [];
  const requestFn = (url, options, onResponse) => {
    const request = new FakeRequest();
    const record = { url, options, request, get body() { return request.body; }, get destroyed() { return request.destroyed; } };
    requests.push(record);
    request.onEnd = (body) => {
      request.body = Buffer.from(body);
      if (spec.hang) return;
      queueMicrotask(() => {
        if (spec.requestError) { request.emit("error", spec.requestError); return; }
        const response = new FakeResponse(spec);
        record.response = response;
        onResponse(response);
        queueMicrotask(() => response.emitChunks());
      });
    };
    return request;
  };
  return { requestFn, requests };
}

class FakeRequest extends EventEmitter {
  destroyed = false;
  body;
  onEnd;

  end(body) { this.onEnd?.(body); }
  destroy() { this.destroyed = true; }
}

class FakeResponse extends EventEmitter {
  destroyed = false;

  constructor(spec) {
    super();
    this.statusCode = spec.statusCode ?? 200;
    this.headers = spec.headers ?? { "content-type": "application/json" };
    this.spec = spec;
  }

  destroy() { this.destroyed = true; }

  emitChunks() {
    if (this.spec.responseError) { this.emit("error", this.spec.responseError); return; }
    if (this.spec.rawBytes !== undefined) this.emit("data", Buffer.from(this.spec.rawBytes));
    else if (this.spec.rawBody !== undefined) this.emit("data", Buffer.from(this.spec.rawBody));
    else if (this.spec.chunks) for (const chunk of this.spec.chunks) this.emit("data", Buffer.from(chunk));
    else if (this.spec.body !== null) this.emit("data", Buffer.from(JSON.stringify(this.spec.body)));
    if (this.spec.truncated) { this.emit("aborted"); return; }
    this.emit("end");
  }
}
