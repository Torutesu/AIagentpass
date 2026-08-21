import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { HOSTED_BOOTSTRAP_HTTP_PATHS } from "../src/hosted-bootstrap/http-api.mjs";

const RAW_POST_BODY = Buffer.from('{"credential":{"opaque":"raw-body"}}', "utf8");

function hostedApi(calls, { throwAfterWrite = false } = {}) {
  return {
    paths: HOSTED_BOOTSTRAP_HTTP_PATHS,
    async handle(request, response) {
      const chunks = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      calls.push({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.concat(chunks)
      });
      const redirect = request.url.startsWith(`${HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart}?`)
        || request.url === HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart;
      response.writeHead(redirect ? 302 : 207, {
        Location: redirect ? "https://github.com/login/oauth/authorize?state=opaque" : undefined,
        "Set-Cookie": redirect ? ["__Host-agentpass_github_state=one; Path=/; Secure", "__Host-agentpass_bootstrap=two; Path=/; Secure"] : ["__Host-agentpass_session=three; Path=/; Secure"]
      });
      response.end(Buffer.from("boundary-response"));
      if (throwAfterWrite) throw new Error("boundary failed after writing");
    }
  };
}

async function dispatch(server, { method = "GET", url, headers = {}, body = Buffer.alloc(0) } = {}) {
  const request = Readable.from([Buffer.from(body)]);
  request.method = method;
  request.url = url;
  request.headers = headers;
  request.socket = { remoteAddress: "203.0.113.9" };

  return new Promise((resolve, reject) => {
    let settled = false;
    const response = {
      headersSent: false,
      writableEnded: false,
      destroyed: false,
      statusCode: 200,
      headers: {},
      writeHeadCount: 0,
      endCount: 0,
      writeHead(status, values = {}) {
        if (this.headersSent) throw new Error("response written twice");
        this.statusCode = status;
        this.headers = { ...values };
        this.headersSent = true;
        this.writeHeadCount += 1;
      },
      setHeader(name, value) { this.headers[name] = value; },
      end(value = "") {
        if (this.writableEnded) throw new Error("response ended twice");
        this.body = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
        this.writableEnded = true;
        this.endCount += 1;
        if (!settled) {
          settled = true;
          resolve(this);
        }
      },
      destroy(error) {
        this.destroyed = true;
        if (!settled) {
          settled = true;
          if (error) reject(error);
          else resolve(this);
        }
      }
    };
    server.emit("request", request, response);
  });
}

function createServer(hostedBootstrapHttpApi, humanCalls = []) {
  return createCloudApi({
    store: {},
    hostedBootstrapHttpApi,
    humanAuthApi: {
      async handle() {
        humanCalls.push(true);
        throw new Error("Human Auth must not receive Hosted bootstrap requests");
      }
    }
  });
}

test("dispatches the exact six Hosted bootstrap paths before Human Auth and preserves the raw request", async () => {
  const calls = [];
  const humanCalls = [];
  const server = createServer(hostedApi(calls), humanCalls);
  const routes = [
    ["GET", HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart],
    ["GET", `${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}?code=opaque-code&state=opaque-state`],
    ["GET", HOSTED_BOOTSTRAP_HTTP_PATHS.status],
    ["POST", HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate],
    ["POST", HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnOptions],
    ["POST", HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnVerify]
  ];

  const responses = [];
  for (const [method, url] of routes) {
    responses.push(await dispatch(server, {
      method,
      url,
      headers: { origin: "https://console.agentpass.test", "content-type": "application/json" },
      body: method === "POST" ? RAW_POST_BODY : Buffer.alloc(0)
    }));
  }

  assert.deepEqual(calls.map(({ method, url }) => [method, url]), routes);
  assert.equal(calls[5].body.equals(RAW_POST_BODY), true);
  assert.equal(humanCalls.length, 0);
  assert.equal(responses.every((response) => response.writeHeadCount === 1 && response.endCount === 1), true);
  assert.equal(responses[0].statusCode, 302);
  assert.equal(responses[0].headers.Location, "https://github.com/login/oauth/authorize?state=opaque");
  assert.deepEqual(responses[0].headers["Set-Cookie"], [
    "__Host-agentpass_github_state=one; Path=/; Secure",
    "__Host-agentpass_bootstrap=two; Path=/; Secure"
  ]);
});

test("does not widen the Hosted route surface to aliases or nonmatching paths", async () => {
  const calls = [];
  const humanCalls = [];
  const server = createServer(hostedApi(calls), humanCalls);
  for (const url of [
    `${HOSTED_BOOTSTRAP_HTTP_PATHS.status}/`,
    `${HOSTED_BOOTSTRAP_HTTP_PATHS.status}/extra`,
    `${HOSTED_BOOTSTRAP_HTTP_PATHS.status}x`,
    "/api/auth/bootstrap",
    "/api/auth/bootstrap/status-other"
  ]) {
    const response = await dispatch(server, { method: "GET", url, body: RAW_POST_BODY });
    assert.equal(response.statusCode, 404, url);
    assert.equal(response.writeHeadCount, 1, url);
    assert.equal(response.endCount, 1, url);
  }
  assert.equal(calls.length, 0);
  assert.equal(humanCalls.length, 0);
});

test("passes Hosted redirects and repeated Set-Cookie headers through without a second response", async () => {
  const calls = [];
  const server = createServer(hostedApi(calls));
  const response = await dispatch(server, {
    method: "GET",
    url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart,
    body: RAW_POST_BODY
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.Location, "https://github.com/login/oauth/authorize?state=opaque");
  assert.equal(response.headers["Set-Cookie"].length, 2);
  assert.equal(response.writeHeadCount, 1);
  assert.equal(response.endCount, 1);
  assert.equal(response.destroyed, false);
  assert.equal(calls[0].body.equals(RAW_POST_BODY), true);
});

test("does not write a generic response after the Hosted boundary has already ended it", async () => {
  const calls = [];
  const server = createServer(hostedApi(calls, { throwAfterWrite: true }));
  const response = await dispatch(server, {
    method: "GET",
    url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.writeHeadCount, 1);
  assert.equal(response.endCount, 1);
  assert.equal(response.destroyed, false);
});

test("strictly validates the optional Hosted bootstrap boundary and its exact route set", () => {
  const malformed = [
    null,
    [],
    {},
    { handle() {}, paths: {} },
    { handle() {}, paths: { ...HOSTED_BOOTSTRAP_HTTP_PATHS, extra: "/extra" } },
    { handle() {}, paths: { ...HOSTED_BOOTSTRAP_HTTP_PATHS, status: `${HOSTED_BOOTSTRAP_HTTP_PATHS.status}/` } },
    { handle() {}, paths: Object.values(HOSTED_BOOTSTRAP_HTTP_PATHS) }
  ];
  for (const value of malformed) {
    assert.throws(
      () => createCloudApi({ store: {}, hostedBootstrapHttpApi: value }),
      /hostedBootstrapHttpApi must expose handle\(\) and the exact Hosted bootstrap paths/
    );
  }
  assert.doesNotThrow(() => createCloudApi({ store: {}, hostedBootstrapHttpApi: hostedApi([]) }));
});
