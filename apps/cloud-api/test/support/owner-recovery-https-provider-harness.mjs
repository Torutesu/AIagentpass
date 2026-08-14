import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:https";

import {
  normalizeOwnerRecoveryDeliveryBinding,
  sameOwnerRecoveryDeliveryBinding
} from "../../src/postgres/owner-recovery-delivery-binding.mjs";

const MAX_REQUEST_BYTES = 1 * 1024 * 1024;
const DEFAULT_RESPONSE_BYTES = 64 * 1024;
const RESPONSE_MODES = new Set([
  "accepted",
  "malformed_json",
  "oversized_body",
  "truncated_content_length",
  "delayed_response",
  "binding_substitution",
  "idempotency_substitution"
]);

/**
 * Start a disposable HTTPS provider on loopback. The certificate is generated
 * into a temporary directory for this process and removed by close(). The
 * harness keeps only bounded counters and mode names; request bodies and
 * provider responses are never retained or emitted as diagnostics.
 */
export async function createOwnerRecoveryHttpsProviderHarness({
  binding,
  authorizationSecret = "owner-recovery-test-secret",
  maxResponseBytes = DEFAULT_RESPONSE_BYTES,
  responseDelayMs = 400
} = {}) {
  const delivery = normalizeOwnerRecoveryDeliveryBinding(binding);
  if (typeof authorizationSecret !== "string" || authorizationSecret.length === 0) throw new TypeError("authorization secret is invalid");
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) throw new TypeError("response limit is invalid");
  if (!Number.isSafeInteger(responseDelayMs) || responseDelayMs < 100) throw new TypeError("response delay is invalid");

  const certificate = createEphemeralCertificate();
  const lookupModes = new Map();
  const publishModes = new Map();
  const publishCounts = new Map();
  const lookupCounts = new Map();
  const sockets = new Set();
  const timers = new Set();
  let serverClosed = false;
  let server;

  const counts = {
    publish: 0,
    lookup: 0,
    invalid: 0
  };

  const serverOptions = {
    key: readFileSync(certificate.keyPath),
    cert: readFileSync(certificate.certPath),
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.3"
  };

  try {
    server = createServer(serverOptions, (request, response) => {
      response.on("error", () => {});
      void handleRequest(request, response).catch(() => {
        counts.invalid += 1;
        if (!response.headersSent) {
          response.statusCode = 400;
          response.end();
        } else {
          response.destroy();
        }
      });
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    server.on("clientError", (_error, socket) => socket.destroy());
    await listen(server);
  } catch (error) {
    cleanupCertificate(certificate.directory);
    throw error;
  }

  async function handleRequest(request, response) {
    if (request.method !== "POST" || (request.url !== "/webhook" && request.url !== "/confirm")) {
      counts.invalid += 1;
      response.statusCode = 404;
      response.end();
      return;
    }
    const body = await readBody(request);
    if (request.headers.authorization !== `Bearer ${authorizationSecret}`
      || request.headers["content-type"] !== "application/json") {
      counts.invalid += 1;
      response.statusCode = 401;
      response.end();
      return;
    }
    let parsed;
    try { parsed = JSON.parse(body); }
    catch {
      counts.invalid += 1;
      response.statusCode = 400;
      response.end();
      return;
    }
    const headerKey = request.headers["idempotency-key"];
    if (typeof headerKey !== "string" || parsed.idempotency_key !== undefined && parsed.idempotency_key !== headerKey) {
      counts.invalid += 1;
      response.statusCode = 400;
      response.end();
      return;
    }

    if (request.url === "/webhook") {
      await handlePublish(headerKey, parsed, response);
      return;
    }
    await handleLookup(headerKey, parsed, response);
  }

  async function handlePublish(idempotencyKey, event, response) {
    if (event.kind !== "owner-recovery-notification" || event.event_id !== idempotencyKey) {
      counts.invalid += 1;
      response.statusCode = 400;
      response.end();
      return;
    }
    counts.publish += 1;
    increment(publishCounts, idempotencyKey);
    const mode = publishModes.get(idempotencyKey) ?? "accepted";
    await writeModeResponse(response, mode, idempotencyKey, false);
  }

  async function handleLookup(idempotencyKey, requestBody, response) {
    if (requestBody.kind !== "owner-recovery-notification-acceptance-lookup"
      || !sameOwnerRecoveryDeliveryBinding(requestBody.provider_binding, delivery)) {
      counts.invalid += 1;
      response.statusCode = 400;
      response.end();
      return;
    }
    counts.lookup += 1;
    increment(lookupCounts, idempotencyKey);
    const mode = lookupModes.get(idempotencyKey) ?? "accepted";
    await writeModeResponse(response, mode, idempotencyKey, true);
  }

  async function writeModeResponse(response, mode, idempotencyKey, lookup) {
    if (!RESPONSE_MODES.has(mode)) throw new TypeError("response mode is invalid");
    if (!lookup && mode === "accepted") {
      writeJson(response, 200, { accepted: true, duplicate: false, idempotency_key: idempotencyKey });
      return;
    }
    if (mode === "malformed_json") {
      writeRaw(response, 200, "{\"accepted\":", "application/json");
      return;
    }
    if (mode === "oversized_body") {
      const body = JSON.stringify({ accepted: true, idempotency_key: idempotencyKey, provider_binding: delivery, padding: "x".repeat(maxResponseBytes + 64) });
      writeRaw(response, 200, body, "application/json");
      return;
    }
    if (mode === "truncated_content_length") {
      const body = JSON.stringify({ accepted: true, idempotency_key: idempotencyKey, provider_binding: delivery });
      writeRaw(response, 200, body, "application/json", Buffer.byteLength(body) + 7);
      return;
    }
    if (mode === "delayed_response") {
      const body = JSON.stringify({ accepted: true, idempotency_key: idempotencyKey, provider_binding: delivery });
      const timer = setTimeout(() => {
        timers.delete(timer);
        writeRaw(response, 200, body, "application/json");
      }, responseDelayMs);
      timers.add(timer);
      return;
    }
    if (mode === "binding_substitution") {
      writeJson(response, 200, {
        accepted: true,
        idempotency_key: idempotencyKey,
        provider_binding: { ...delivery, binding_digest: "b".repeat(64) }
      });
      return;
    }
    if (mode === "idempotency_substitution") {
      writeJson(response, 200, {
        accepted: true,
        idempotency_key: randomUUID(),
        provider_binding: delivery
      });
      return;
    }
    writeJson(response, 200, {
      accepted: true,
      idempotency_key: idempotencyKey,
      provider_binding: delivery
    });
  }

  function setLookupMode(idempotencyKey, mode) {
    validateMode(mode);
    lookupModes.set(idempotencyKey, mode);
  }

  function setPublishMode(idempotencyKey, mode) {
    validateMode(mode);
    publishModes.set(idempotencyKey, mode);
  }

  async function close() {
    if (serverClosed) return;
    serverClosed = true;
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
    for (const socket of sockets) socket.destroy();
    await closeServer(server);
    cleanupCertificate(certificate.directory);
  }

  const address = server.address();
  if (!address || typeof address !== "object") {
    await close();
    throw new Error("HTTPS provider did not bind to loopback");
  }
  const origin = `https://127.0.0.1:${address.port}`;

  return Object.freeze({
    webhookUrl: `${origin}/webhook`,
    confirmationUrl: `${origin}/confirm`,
    caCertificate: readFileSync(certificate.certPath, "utf8"),
    setLookupMode,
    setPublishMode,
    publishCount: (idempotencyKey) => publishCounts.get(idempotencyKey) ?? 0,
    lookupCount: (idempotencyKey) => lookupCounts.get(idempotencyKey) ?? 0,
    snapshot: () => Object.freeze({
      publish_calls: counts.publish,
      lookup_calls: counts.lookup,
      invalid_requests: counts.invalid
    }),
    close
  });
}

function createEphemeralCertificate() {
  const directory = mkdtempSync(join(tmpdir(), "agentpass-owner-recovery-https-"));
  const keyPath = join(directory, "key.pem");
  const certPath = join(directory, "cert.pem");
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", keyPath, "-out", certPath, "-days", "1",
      "-subj", "/CN=127.0.0.1",
      "-addext", "subjectAltName=IP:127.0.0.1"
    ], { stdio: ["ignore", "ignore", "ignore"], timeout: 10_000, maxBuffer: 16 * 1024 });
    return Object.freeze({ directory, keyPath, certPath });
  } catch (error) {
    cleanupCertificate(directory);
    throw error;
  }
}

function cleanupCertificate(directory) {
  rmSync(directory, { recursive: true, force: true });
}

function validateMode(mode) {
  if (typeof mode !== "string" || !RESPONSE_MODES.has(mode)) throw new TypeError("response mode is invalid");
}

function increment(map, key) {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on("data", (chunk) => {
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > MAX_REQUEST_BYTES) {
        request.destroy();
        reject(new Error("request body exceeded test limit"));
        return;
      }
      chunks.push(bytes);
    });
    request.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.once("error", reject);
    request.once("aborted", () => reject(new Error("request aborted")));
  });
}

function writeJson(response, statusCode, value) {
  writeRaw(response, statusCode, JSON.stringify(value), "application/json");
}

function writeRaw(response, statusCode, body, contentType, declaredLength = Buffer.byteLength(body)) {
  const bytes = Buffer.from(body, "utf8");
  response.statusCode = statusCode;
  response.setHeader("content-type", contentType);
  response.setHeader("content-length", declaredLength);
  response.end(bytes);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => error ? reject(error) : resolve());
  });
}
