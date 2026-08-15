import assert from "node:assert/strict";
import test from "node:test";
import { Readable } from "node:stream";

import { createCloudApi } from "../src/server.mjs";

const PATHS = Object.freeze({
  challenge: "/api/platform/v1/sessions/challenges",
  assertion: "/api/platform/v1/sessions",
  revoke: "/api/platform/v1/sessions/revoke"
});

async function dispatch(server, { url, headers = {}, body = "" } = {}) {
  const request = Readable.from([Buffer.from(body)]);
  request.method = "POST";
  request.url = url;
  request.headers = headers;
  return new Promise((resolve, reject) => {
    const response = {
      headersSent: false,
      statusCode: 200,
      headers: {},
      writeHead(status, values) { this.statusCode = status; this.headers = { ...values }; this.headersSent = true; },
      setHeader(name, value) { this.headers[name] = value; },
      end(value) { this.body = value; resolve(this); },
      destroy(error) { reject(error ?? new Error("response destroyed")); }
    };
    server.emit("request", request, response);
  });
}

test("platform session composition intercepts only its frozen paths and passes raw request input", async () => {
  const calls = [];
  const server = createCloudApi({
    store: {},
    platformSessionHttpApi: {
      paths: PATHS,
      async handle(request, response) {
        const chunks = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        calls.push({ method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString("utf8") });
        response.writeHead(209, { "X-Platform-Session": "boundary" });
        response.end(JSON.stringify({ ok: true }));
      }
    }
  });
  const response = await dispatch(server, {
    url: PATHS.challenge,
    headers: { origin: "https://console.agentpass.test", "content-type": "application/json", cookie: "__Host-agentpass_session=raw" },
    body: '{"operation":"platform.promotion.issue"}'
  });
  assert.equal(response.statusCode, 209);
  assert.equal(response.headers["X-Platform-Session"], "boundary");
  assert.deepEqual(JSON.parse(response.body), { ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, PATHS.challenge);
  assert.equal(calls[0].headers.cookie, "__Host-agentpass_session=raw");
  assert.equal(calls[0].body, '{"operation":"platform.promotion.issue"}');
});

test("platform session routes are physically absent when the composition is not injected", async () => {
  const server = createCloudApi({ store: {} });
  const response = await dispatch(server, { url: PATHS.challenge, body: "{}" });
  assert.equal(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.deepEqual(body.error, { code: "not_found", message: "Resource not found" });
  assert.match(body.request_id, /^[0-9a-f-]{36}$/u);
});
