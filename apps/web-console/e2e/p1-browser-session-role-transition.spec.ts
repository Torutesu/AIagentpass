import { expect, test, type Page } from "@playwright/test";
import {
  AUTHORIZATION_ID,
  CREDENTIAL_ID,
  CSRF_TOKEN,
  MEMBER_ID,
  ORGANIZATION_ID,
  OTHER_MEMBER_ID,
  browserStorageSnapshot,
  consoleSummary,
  deploymentReadiness,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

const DATE = "2026-08-12T00:00:00.000Z";
const FUTURE = "2099-01-02T12:00:00.000Z";
const REQUEST_ID = "69999999-9999-4999-8999-999999999999";
const ROLE_REQUEST_ID = "6b999999-9999-4999-8999-999999999999";

type TransitionState = {
  sessionRoles: string[];
  roleMutationRequests: number;
  roleMutationHeaders: Record<string, string>;
  roleMutationBodies: Array<Record<string, unknown>>;
  recentAuthOperations: string[];
};

function organization() {
  return {
    organization_id: ORGANIZATION_ID,
    name: "Session Role Transition Organization",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function member(memberId: string, displayName: string, role: "owner" | "admin") {
  return {
    membership_id: `${memberId.slice(0, 8)}-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,
    organization_id: ORGANIZATION_ID,
    member_id: memberId,
    display_name: displayName,
    role,
    status: "active",
    version: role === "admin" && memberId === MEMBER_ID ? 2 : 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function invitations() {
  return [{
    invitation_id: "85555555-5555-4555-8555-555555555555",
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    status: "pending",
    version: 1,
    created_at: DATE,
    expires_at: FUTURE,
    accepted_at: null,
    accepted_member_id: null,
  }];
}

async function installRoutes(page: Page): Promise<TransitionState> {
  const state: TransitionState = {
    sessionRoles: [],
    roleMutationRequests: 0,
    roleMutationHeaders: {},
    roleMutationBodies: [],
    recentAuthOperations: [],
  };
  let currentRole: "owner" | "admin" = "owner";

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.pathname === "/api/auth/session/resume" || url.pathname === "/api/auth/session") {
      state.sessionRoles.push(currentRole);
      return json(route, session(currentRole));
    }
    if (url.pathname === "/api/auth/webauthn/options") {
      const body = parseRequestBody(route);
      state.recentAuthOperations.push(String(body.operation ?? ""));
      return json(route, {
        challenge_id: "57777777-7777-4777-8777-777777777777",
        options: {
          challenge: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NA",
          rpId: "localhost",
          userVerification: "required",
          allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      const body = parseRequestBody(route);
      state.recentAuthOperations.push(String(body.operation ?? ""));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members/${MEMBER_ID}/role` && request.method() === "PATCH") {
      state.roleMutationRequests += 1;
      state.roleMutationHeaders = request.headers();
      state.roleMutationBodies.push(parseRequestBody(route));
      currentRole = "admin";
      return json(route, {
        request_id: ROLE_REQUEST_ID,
        member: member(MEMBER_ID, "現在の利用者", "admin"),
      });
    }
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, organizations: [organization()], next_cursor: null });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, {
        request_id: REQUEST_ID,
        members: [member(MEMBER_ID, "現在の利用者", currentRole), member(OTHER_MEMBER_ID, "別のOwner", "owner")],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, invitations: invitations(), next_cursor: null });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() === "GET") return json(route, { capabilities: [], revocations: [], events: [] });
    return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
  });

  return state;
}

test("downgrading the current member after WebAuthn refreshes session authority and removes Owner-only controls", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  const authenticator: VirtualAuthenticator = await installVirtualAuthenticator(page);
  const state = await installRoutes(page);
  try {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
    await page.getByRole("button", { name: "Organizations", exact: true }).click();
    await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
    await expect(page.getByText("現在の権限: Owner", { exact: true })).toBeVisible();

    const currentRole = page.getByLabel("現在の利用者のロール");
    await currentRole.selectOption("admin");
    await page.getByRole("button", { name: "現在の利用者をAdminに変更", exact: true }).click();

    await expect(page.getByText("現在の権限: Admin", { exact: true })).toBeVisible();
    await expect(currentRole).toHaveValue("admin");
    await expect(currentRole.locator("option", { hasText: "Owner" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "現在の利用者をOwnerに変更", exact: true })).toHaveCount(0);

    expect(state.roleMutationRequests).toBe(1);
    expect(state.roleMutationBodies).toEqual([{ role: "admin" }]);
    expect(state.roleMutationHeaders["agentpass-csrf"]).toBe(CSRF_TOKEN);
    expect(state.roleMutationHeaders["agentpass-recent-auth"]).toBe(AUTHORIZATION_ID);
    expect(state.roleMutationHeaders["if-match"]).toBe('"1"');
    expect(state.roleMutationHeaders["idempotency-key"]).toMatch(/^[A-Za-z0-9._~-]{8,255}$/u);
    expect(state.recentAuthOperations).toEqual([
      "human.organizations.member.role.update",
      "human.organizations.member.role.update",
    ]);
    expect(state.sessionRoles).toContain("owner");
    expect(state.sessionRoles).toContain("admin");
    expect(state.sessionRoles.filter((role) => role === "admin")).not.toHaveLength(0);

    const storage = await browserStorageSnapshot(page);
    expect(JSON.stringify(storage)).not.toContain(AUTHORIZATION_ID);
    expect(JSON.stringify(storage)).not.toContain(CREDENTIAL_ID);
    expect(consoleMessages.join("\n")).not.toContain(AUTHORIZATION_ID);
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});

test.afterEach(async ({ page }) => {
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
