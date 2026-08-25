import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export const BFF_ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
export const BFF_SESSION_ID = "22222222-2222-4222-8222-222222222222";
export const BFF_MEMBER_ID = "33333333-3333-4333-8333-333333333333";
export const BFF_SESSION_TOKEN = "s".repeat(43);
export const BFF_CSRF_TOKEN = "c".repeat(43);
export const BFF_AUTHORIZATION_ID = "44444444-4444-4444-8444-444444444444";
export const BFF_CHALLENGE_ID = "55555555-5555-4555-8555-555555555555";
export const BFF_CHALLENGE = Buffer.alloc(32, 0x43).toString("base64url");

export type BffCloudRole = "owner" | "admin" | "auditor" | "viewer";
export type BffCloudMode = "active" | "expired" | "revoked";

export type BffCloudObservation = Readonly<{
  method: string;
  path: string;
  cookiePresent: boolean;
  csrfPresent: boolean;
  origin: string | null;
  recentAuthPresent: boolean;
  idempotencyPresent: boolean;
}>;

export type BffCloudFixture = Readonly<{
  setState(state: { role?: BffCloudRole; mode?: BffCloudMode }): void;
  observations(): BffCloudObservation[];
  close(): Promise<void>;
}>;

type MutableState = {
  role: BffCloudRole;
  mode: BffCloudMode;
  observations: BffCloudObservation[];
};

const ORGANIZATION = {
  organization_id: BFF_ORGANIZATION_ID,
  name: "BFF boundary organization",
  version: 1,
  created_at: "2026-08-20T00:00:00.000Z",
  updated_at: "2026-08-20T00:00:00.000Z",
};

function json(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "content-length": String(payload.byteLength),
    ...headers,
  });
  response.end(payload);
}

function session(role: BffCloudRole) {
  return {
    session: {
      version: 1,
      session_id: BFF_SESSION_ID,
      member_id: BFF_MEMBER_ID,
      organization_id: BFF_ORGANIZATION_ID,
      role,
      created_at: "2026-08-20T00:00:00.000Z",
      expires_at: "2099-01-01T00:00:00.000Z",
      recent_auth_at: null,
    },
    csrf_token: BFF_CSRF_TOKEN,
  };
}

function error(response: ServerResponse, status: number, code: string): void {
  json(response, status, { error: { code, message: `fixture-${code}` } });
}

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  if (chunks.length === 0) return {};
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function record(request: IncomingMessage, url: URL, state: MutableState): void {
  state.observations.push({
    method: request.method ?? "",
    path: url.pathname,
    cookiePresent: typeof request.headers.cookie === "string" && request.headers.cookie.includes("__Host-agentpass_session="),
    csrfPresent: typeof request.headers["agentpass-csrf"] === "string",
    origin: typeof request.headers.origin === "string" ? request.headers.origin : null,
    recentAuthPresent: typeof request.headers["agentpass-recent-auth"] === "string",
    idempotencyPresent: typeof request.headers["idempotency-key"] === "string",
  });
}

function sessionCookie(): string {
  return `__Host-agentpass_session=${BFF_SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function clearSessionCookie(): string {
  return "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

async function handle(request: IncomingMessage, response: ServerResponse, state: MutableState): Promise<void> {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (url.pathname === "/healthz" && request.method === "GET") {
    json(response, 200, { ok: true });
    return;
  }

  if (url.pathname === "/__test__/state" && request.method === "POST") {
    const body = await readBody(request);
    if (body.role === "owner" || body.role === "admin" || body.role === "auditor" || body.role === "viewer") state.role = body.role;
    if (body.mode === "active" || body.mode === "expired" || body.mode === "revoked") state.mode = body.mode;
    state.observations.length = 0;
    json(response, 200, { ok: true });
    return;
  }

  if (state.mode === "expired") {
    record(request, url, state);
    error(response, 401, "session_expired");
    return;
  }

  if (state.mode === "revoked") {
    record(request, url, state);
    json(response, 401, { error: { code: "session_revoked", message: "fixture-session_revoked" } }, { "set-cookie": clearSessionCookie() });
    return;
  }

  record(request, url, state);
  const method = request.method ?? "GET";

  if (url.pathname === "/api/auth/session/resume" && method === "POST") {
    json(response, 200, session(state.role), { "set-cookie": sessionCookie() });
    return;
  }

  if (url.pathname === "/api/auth/webauthn/options" && method === "POST") {
    json(response, 200, {
      challenge_id: BFF_CHALLENGE_ID,
      options: {
        challenge: BFF_CHALLENGE,
        rpId: "127.0.0.1",
        userVerification: "required",
        timeout: 30_000,
      },
    });
    return;
  }

  if (url.pathname === "/api/auth/webauthn/verify" && method === "POST") {
    json(response, 200, { authorization_id: BFF_AUTHORIZATION_ID });
    return;
  }

  const organizationRoot = `/v1/organizations/${BFF_ORGANIZATION_ID}`;
  if (url.pathname === organizationRoot && method === "GET") {
    json(response, 200, { organization: ORGANIZATION });
    return;
  }

  if (url.pathname === `/api/auth/organizations/${BFF_ORGANIZATION_ID}` && method === "PATCH") {
    if (state.role !== "owner" && state.role !== "admin") {
      error(response, 403, "role_denied");
      return;
    }
    const body = await readBody(request);
    json(response, 200, { organization: { ...ORGANIZATION, name: body.name } });
    return;
  }

  error(response, 404, "not_found");
}

export async function startBffCloudFixture(port: number): Promise<BffCloudFixture> {
  const state: MutableState = { role: "owner", mode: "active", observations: [] };
  const server: Server = createServer((request, response) => {
    void handle(request, response, state).catch(() => {
      if (!response.headersSent) error(response, 500, "fixture_failure");
      else response.destroy();
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (cause: Error) => {
      server.off("listening", resolve);
      reject(cause);
    };
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });

  return Object.freeze({
    setState(next) {
      if (next.role !== undefined) state.role = next.role;
      if (next.mode !== undefined) state.mode = next.mode;
      state.observations.length = 0;
    },
    observations() {
      return state.observations.map((item) => ({ ...item }));
    },
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  });
}
