import { generateKeyPairSync } from "node:crypto";
import type { Page, Route } from "@playwright/test";

const CDP_CLEANUP_TIMEOUT_MS = 2_000;

export type BrowserRole = "owner" | "admin" | "auditor" | "viewer";

export const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
export const SESSION_ID = "22222222-2222-4222-8222-222222222222";
export const MEMBER_ID = "33333333-3333-4333-8333-333333333333";
export const OTHER_MEMBER_ID = "34444444-4444-4444-8444-444444444444";
export const CSRF_TOKEN = "c".repeat(43);
export const CREDENTIAL_ID_BYTES = Buffer.from("agentpass-e2e-credential");
export const CREDENTIAL_ID = CREDENTIAL_ID_BYTES.toString("base64url");
export const AUTHORIZATION_ID = "58888888-8888-4888-8888-888888888888";
export const CHALLENGE_ID = "57777777-7777-4777-8777-777777777777";
export const CHALLENGE = Buffer.alloc(32, 0x43).toString("base64url");
export const REGISTRATION_CHALLENGE = Buffer.alloc(32, 0x52).toString("base64url");
export const ACTIVE_EXPIRES_AT = "2099-01-01T00:00:00.000Z";

export function json(route: Route, body: unknown, status = 200): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

export function session(role: BrowserRole) {
  return {
    session: {
      version: 1,
      session_id: SESSION_ID,
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role,
      created_at: "2026-08-12T00:00:00.000Z",
      expires_at: ACTIVE_EXPIRES_AT,
      recent_auth_at: null,
    },
    csrf_token: CSRF_TOKEN,
  };
}

export function consoleSummary() {
  return {
    organization: {
      organization_id: ORGANIZATION_ID,
      name: "Browser E2E Organization",
      created_at: "2026-08-12T00:00:00.000Z",
      updated_at: "2026-08-12T00:00:00.000Z",
      version: 1,
    },
    devices: [{
      device_id: "41111111-1111-4111-8111-111111111111",
      name: "E2E Mac",
      status: "active",
      created_at: "2026-08-12T00:00:00.000Z",
      last_seen_at: "2026-08-12T00:30:00.000Z",
      version: 1,
      bundle_sequence: 1,
      bundle_expires_at: ACTIVE_EXPIRES_AT,
      last_ack_at: "2026-08-12T00:30:00.000Z",
      desired_generation: 1,
      observed_generation: 1,
      refresh_state: "applied",
      blocked_reason: null,
    }],
    agents: [],
    policies: [],
    audit: { health: [], activity: [], next_cursor: null },
  };
}

export type VirtualAuthenticator = Readonly<{
  cdp: Awaited<ReturnType<ReturnType<Page["context"]>["newCDPSession"]>>;
  authenticatorId: string;
  credentialId: string;
}>;

async function boundedCleanup<T>(operation: Promise<T>, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((resolve) => {
        timer = setTimeout(() => resolve(fallback), CDP_CLEANUP_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export async function installVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  let authenticatorId: string | undefined;
  try {
    await cdp.send("WebAuthn.enable");
    ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    }));
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    await cdp.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: {
        credentialId: CREDENTIAL_ID_BYTES.toString("base64"),
        isResidentCredential: false,
        rpId: "localhost",
        privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
        signCount: 0,
      },
    });
    return Object.freeze({ cdp, authenticatorId, credentialId: CREDENTIAL_ID });
  } catch (error) {
    if (authenticatorId !== undefined) {
      await boundedCleanup(cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }), undefined);
    }
    await boundedCleanup(cdp.detach(), undefined);
    throw error;
  }
}

export async function removeVirtualCredential(authenticator: VirtualAuthenticator): Promise<void> {
  await authenticator.cdp.send("WebAuthn.removeCredential", {
    authenticatorId: authenticator.authenticatorId,
    credentialId: CREDENTIAL_ID_BYTES.toString("base64"),
  });
}

export async function disposeVirtualAuthenticator(authenticator: Pick<VirtualAuthenticator, "cdp" | "authenticatorId">): Promise<void> {
  try {
    await boundedCleanup(authenticator.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: authenticator.authenticatorId }), undefined);
  } finally {
    await boundedCleanup(authenticator.cdp.detach().catch(() => undefined), undefined);
  }
}

export async function browserStorageSnapshot(page: Page): Promise<{ local: Record<string, string>; session: Record<string, string> }> {
  return page.evaluate(() => {
    const read = (storage: Storage) => Object.fromEntries(Object.keys(storage).map((key) => [key, storage.getItem(key) ?? ""]));
    return { local: read(window.localStorage), session: read(window.sessionStorage) };
  });
}

export function requestOperation(route: Route): string {
  try {
    return String(JSON.parse(route.request().postData() ?? "{}").operation ?? "");
  } catch {
    return "";
  }
}

export function parseRequestBody(route: Route): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(route.request().postData() ?? "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
