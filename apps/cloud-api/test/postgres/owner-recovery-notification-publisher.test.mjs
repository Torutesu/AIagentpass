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

test("sends only the public event over HTTPS with event_id as Idempotency-Key", async () => {
  const transport = fakeTransport({ statusCode: 202, body: { accepted: true, duplicate: false } });
  const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  const result = await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT, signal: new AbortController().signal });
  assert.deepEqual(result, { accepted: true, duplicate: false });
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
});

test("supports fixed or resolver-supplied endpoint and secret without putting either in resolver event data", async () => {
  const transport = fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: true } });
  const calls = [];
  const publisher = createOwnerRecoveryNotificationPublisher({
    resolveWebhookUrl: async (input) => { calls.push(["url", input]); return URL; },
    resolveAuthorizationSecret: async (input) => { calls.push(["secret", input]); return SECRET; },
    requestFn: transport.requestFn
  });
  await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT });
  assert.deepEqual(calls.map(([kind]) => kind), ["url", "secret"]);
  assert.equal(JSON.stringify(calls).includes(SECRET), false);
  assert.equal(JSON.stringify(calls).includes("password"), false);
  assert.equal(transport.requests[0].url.href, URL);
});

test("rejects insecure or ambiguous configuration and malformed public input", async () => {
  for (const options of [
    { webhookUrl: "http://notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://user:pass@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://:@notify.example.test/hook", authorizationSecret: SECRET },
    { webhookUrl: "https://notify.example.test/hook#fragment", authorizationSecret: SECRET },
    { webhookUrl: URL, authorizationSecret: SECRET, resolveWebhookUrl: () => URL },
    { webhookUrl: URL, authorizationSecret: SECRET, resolveAuthorizationSecret: () => SECRET },
    { webhookUrl: URL, authorizationSecret: "line\nbreak" }
  ]) assert.throws(() => createOwnerRecoveryNotificationPublisher(options), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG);

  const transport = fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false } });
  const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: { ...EVENT, provider_secret: SECRET } }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT);
  await assert.rejects(publisher.publish({ idempotency_key: IDS.request_id, event: EVENT }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT);
});

test("requires an exact accepted JSON response and never follows redirects", async () => {
  for (const response of [
    { statusCode: 204, body: null },
    { statusCode: 302, body: { accepted: true, duplicate: false } },
    { statusCode: 200, headers: { "content-type": "text/plain" }, body: { accepted: true, duplicate: false } },
    { statusCode: 200, headers: { "content-type": ["application/json", "application/json"] }, body: { accepted: true, duplicate: false } },
    { statusCode: 200, headers: { "content-type": "application/json, text/plain" }, body: { accepted: true, duplicate: false } },
    { statusCode: 200, body: { accepted: true } },
    { statusCode: 200, body: { accepted: false, duplicate: true } },
    { statusCode: 200, body: { accepted: true, duplicate: false, provider_secret: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, credential: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, secret: SECRET } },
    { statusCode: 200, body: { accepted: true, duplicate: false, authorization: `Bearer ${SECRET}` } },
    { statusCode: 200, rawBody: '{"accepted":true,"accepted":true,"duplicate":false}' },
    { statusCode: 200, rawBody: "not-json" }
  ]) {
    const transport = fakeTransport(response);
    const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
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
    const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
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
  const transport = fakeTransport({ statusCode: 200, body: { accepted: false, duplicate: false } });
  const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  assert.deepEqual(await publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), { accepted: false, duplicate: false });
});

test("bounds provider response bytes before and during streaming", async () => {
  for (const response of [
    { statusCode: 200, headers: { "content-length": "100" }, rawBody: "x" },
    { statusCode: 200, chunks: ["x".repeat(6), "y"], body: { accepted: true, duplicate: false } }
  ]) {
    const transport = fakeTransport(response);
    const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn, maxResponseBytes: 6 });
    await assert.rejects(publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), { code: OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESPONSE_TOO_LARGE });
  }
});

test("follows the caller AbortSignal and maps provider diagnostics to a stable opaque error", async () => {
  const controller = new AbortController();
  const transport = fakeTransport({ hang: true });
  const publisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: transport.requestFn });
  const pending = publisher.publish({ idempotency_key: EVENT.event_id, event: EVENT, signal: controller.signal });
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(pending, (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.ABORTED);
  assert.equal(transport.requests[0].destroyed, true);

  const failedTransport = fakeTransport({ requestError: new Error(`provider password=${SECRET}`) });
  const failed = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: failedTransport.requestFn });
  await assert.rejects(failed.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
    assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE);
    assert.equal(error.message.includes(SECRET), false);
    assert.equal("cause" in error, false);
    return true;
  });

  const responseFailure = fakeTransport({ responseError: new Error(`response body credential=${SECRET}`) });
  const responseFailedPublisher = createOwnerRecoveryNotificationPublisher({ webhookUrl: URL, authorizationSecret: SECRET, requestFn: responseFailure.requestFn });
  await assert.rejects(responseFailedPublisher.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => {
    assert.equal(error.code, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE);
    assert.equal(error.message.includes(SECRET), false);
    assert.equal("cause" in error, false);
    return true;
  });
});

test("maps resolver failures and invalid resolver outputs without exposing details", async () => {
  const failed = createOwnerRecoveryNotificationPublisher({
    resolveWebhookUrl: async () => { throw new Error(`url secret=${SECRET}`); },
    resolveAuthorizationSecret: () => SECRET,
    requestFn: fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false } }).requestFn
  });
  await assert.rejects(failed.publish({ idempotency_key: EVENT.event_id, event: EVENT }), (error) => error.code === OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER && !error.message.includes(SECRET));

  const invalid = createOwnerRecoveryNotificationPublisher({
    resolveWebhookUrl: () => "http://not-https.example.test/hook",
    resolveAuthorizationSecret: () => SECRET,
    requestFn: fakeTransport({ statusCode: 200, body: { accepted: true, duplicate: false } }).requestFn
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
    this.emit("end");
  }
}
