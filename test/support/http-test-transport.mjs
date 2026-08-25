import { Readable } from "node:stream";

const VIRTUAL_HOST = "127.0.0.1";
const FIRST_VIRTUAL_PORT = 41_000;
const transports = new Map();
let nextVirtualPort = FIRST_VIRTUAL_PORT;
let originalFetch;

/**
 * Adapt a real node:http server handler to a fetch-shaped, socket-free test
 * transport. The server's request listener remains the production listener;
 * only the network boundary is replaced for tests that cannot bind sockets.
 */
export function startInMemoryHttpServer(server) {
  if (!server || typeof server.emit !== "function") throw new TypeError("HTTP server is required");
  const port = allocatePort();
  const address = Object.freeze({ address: VIRTUAL_HOST, family: "IPv4", port });
  let closed = false;
  const transport = { server, address, close: () => close() };
  transports.set(port, transport);
  installFetchTransport();

  const originalAddress = server.address.bind(server);
  const originalClose = server.close.bind(server);
  server.address = () => closed ? null : address;
  server.close = (callback) => {
    if (!closed) {
      closed = true;
      transports.delete(port);
    }
    queueMicrotask(() => callback?.());
    return server;
  };
  server.__agentpassInMemoryTransport = Object.freeze({ originalAddress, originalClose, address });
  return `http://${VIRTUAL_HOST}:${port}`;

  function close() {
    server.close();
  }
}

function allocatePort() {
  while (transports.has(nextVirtualPort)) nextVirtualPort += 1;
  if (nextVirtualPort > 65_535) throw new Error("in-memory HTTP transport virtual port range exhausted");
  return nextVirtualPort++;
}

function installFetchTransport() {
  if (originalFetch !== undefined) return;
  originalFetch = globalThis.fetch;
  if (typeof originalFetch !== "function") throw new Error("global fetch is unavailable");
  globalThis.fetch = async function testTransportFetch(input, init) {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const transport = url.hostname === VIRTUAL_HOST ? transports.get(Number(url.port)) : undefined;
    if (!transport) return originalFetch.call(this, input, init);
    return dispatch(transport.server, url, input, init);
  };
}

async function dispatch(server, url, input, init) {
  const requestInit = init ?? {};
  const request = Readable.from([await requestBody(input, requestInit)]);
  request.method = String(requestInit.method ?? input?.method ?? "GET").toUpperCase();
  request.url = `${url.pathname}${url.search}`;
  request.headers = headersFrom(input, requestInit);
  request.socket = { remoteAddress: VIRTUAL_HOST };
  request.httpVersion = "1.1";

  return new Promise((resolve, reject) => {
    let settled = false;
    const response = createResponse(resolve, reject, () => { settled = true; });
    try {
      server.emit("request", request, response);
    } catch (error) {
      if (!settled) reject(error);
    }
  });
}

async function requestBody(input, init) {
  if (init.body !== undefined && init.body !== null) return toBuffer(init.body);
  if (input && typeof input !== "string" && !(input instanceof URL) && input.body) return Buffer.from(await input.arrayBuffer());
  return Buffer.alloc(0);
}

function headersFrom(input, init) {
  const values = new Headers(input && typeof input !== "string" && !(input instanceof URL) ? input.headers : undefined);
  for (const [name, value] of new Headers(init.headers ?? {}).entries()) values.set(name, value);
  return Object.fromEntries(values.entries());
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value);
  throw new TypeError("in-memory HTTP request body must be bytes or a string");
}

function createResponse(resolve, reject, markSettled) {
  const chunks = [];
  const responseHeaders = new Map();
  let statusCode = 200;
  let ended = false;
  const response = {
    headersSent: false,
    writableEnded: false,
    statusCode,
    setHeader(name, value) {
      responseHeaders.set(String(name).toLowerCase(), value);
      return this;
    },
    getHeader(name) { return responseHeaders.get(String(name).toLowerCase()); },
    removeHeader(name) { responseHeaders.delete(String(name).toLowerCase()); },
    writeHead(status, statusMessage, headers) {
      statusCode = Number(status);
      this.statusCode = statusCode;
      const values = typeof statusMessage === "object" ? statusMessage : headers;
      for (const [name, value] of Object.entries(values ?? {})) responseHeaders.set(name.toLowerCase(), value);
      this.headersSent = true;
      return this;
    },
    write(chunk) {
      if (ended) throw new Error("response already ended");
      this.headersSent = true;
      chunks.push(toBuffer(chunk));
      return true;
    },
    end(chunk) {
      if (ended) return this;
      if (chunk !== undefined && chunk !== null) chunks.push(toBuffer(chunk));
      ended = true;
      this.writableEnded = true;
      this.headersSent = true;
      const headers = new Headers();
      for (const [name, value] of responseHeaders) {
        if (Array.isArray(value)) for (const item of value) headers.append(name, String(item));
        else headers.set(name, String(value));
      }
      markSettled();
      const body = [204, 205, 304].includes(statusCode) ? null : Buffer.concat(chunks);
      resolve(new Response(body, { status: statusCode, headers }));
      return this;
    },
    destroy(error) {
      if (ended) return this;
      ended = true;
      this.writableEnded = true;
      markSettled();
      reject(error ?? new Error("HTTP response destroyed"));
      return this;
    }
  };
  return response;
}
