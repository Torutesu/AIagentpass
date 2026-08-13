import crypto from "node:crypto";

import { createMigrationRunner } from "../../../apps/cloud-api/src/postgres/migration-runner.mjs";
import { createControlPlaneAuthorityRepository } from "../../../apps/cloud-api/src/postgres/control-plane-authority-repository.mjs";
import { createRefreshNonceCodec } from "../../../apps/cloud-api/src/postgres/refresh-nonce-codec.mjs";
import { startP0BHarness, P0BSkip, p0bRepositoryRoot } from "./harness.mjs";

const ROLES = Object.freeze(["owner", "admin", "auditor", "viewer"]);
const ROLE_SET = new Set(ROLES);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const SESSION_PATH = "/api/auth/session";
const USER_EMAILS = Object.freeze({
  owner: "p0b-owner@example.test",
  admin: "p0b-admin@example.test",
  auditor: "p0b-auditor@example.test",
  viewer: "p0b-viewer@example.test"
});

export class P0BLiveBrowserFixtureError extends Error {
  constructor(code, message = "P0-B live browser fixture failed") {
    super(message);
    this.name = "P0BLiveBrowserFixtureError";
    this.code = code;
  }
}

/**
 * Start the existing P0-B process harness with a real human-auth tenant.
 *
 * The returned object intentionally contains only public test coordinates:
 * URLs, UUIDs, roles, and browser helpers. PostgreSQL URLs, passwords,
 * cookies, CSRF values, identity keys, and WebAuthn material stay in the
 * harness or in private helper closures.
 */
export async function startP0BLiveBrowserFixture({
  env = process.env,
  repoRoot = p0bRepositoryRoot(),
  consoleBuild = true,
  waitTimeoutMs = 20_000,
  prepareDatabase
} = {}) {
  if (prepareDatabase !== undefined && typeof prepareDatabase !== "function") {
    throw new TypeError("P0-B database preparation must be a function");
  }

  let seed;
  let databasePool;
  let harness;
  try {
    harness = await startP0BHarness({
      env,
      repoRoot,
      consoleBuild,
      waitTimeoutMs,
      prepareDatabase: async (context) => {
        databasePool = context.pool;
        seed = await seedP0BHumanBrowserDatabase(context);
        if (prepareDatabase) {
          try {
            const safeContext = {
              pool: context.pool,
              organizationId: context.organizationId,
              seed: publicSeed(seed)
            };
            await prepareDatabase(Object.freeze({
              ...safeContext
            }));
          } catch {
            throw new P0BLiveBrowserFixtureError("database_prepare_failed", "P0-B live browser database preparation failed");
          }
        }
      }
    });
  } catch (error) {
    if (error instanceof P0BSkip) throw error;
    if (error instanceof P0BLiveBrowserFixtureError) throw error;
    throw new P0BLiveBrowserFixtureError("startup_failed", "P0-B live browser fixture startup failed");
  }

  if (!seed) {
    await harness.close().catch(() => {});
    throw new P0BLiveBrowserFixtureError("database_prepare_failed", "P0-B live browser database was not prepared");
  }

  const pageState = new WeakMap();
  let closed = false;
  const safeSeed = publicSeed(seed);

  const fixture = {
    baseURL: harness.consoleUrl,
    consoleUrl: harness.consoleUrl,
    cloudUrl: harness.cloudUrl,
    caCert: harness.caCert,
    organizationId: safeSeed.organizationId,
    roles: safeSeed.roles,
    devices: safeSeed.devices,
    tlsSpkiPin: harness.tlsSpkiPin,

    role(role) {
      return roleDescriptor(safeSeed, role);
    },

    /** Add the test identity headers needed by the real Console BFF. */
    async configureContext(context, role) {
      assertContext(context);
      const descriptor = roleDescriptor(safeSeed, role);
      await context.setExtraHTTPHeaders(identityHeaders(descriptor));
      return descriptor;
    },

    /** Page-scoped equivalent for specs that share a browser context. */
    async configurePage(page, role) {
      assertPage(page);
      const descriptor = roleDescriptor(safeSeed, role);
      await page.setExtraHTTPHeaders(identityHeaders(descriptor));
      return descriptor;
    },

    /**
     * Navigate through the real Console session bootstrap. The CSRF token is
     * retained only in a WeakMap for later WebAuthn helpers and is never
     * returned.
     */
    async bootstrap(page, role, { path = "/" } = {}) {
      assertPage(page);
      const descriptor = roleDescriptor(safeSeed, role);
      const target = consolePath(path, harness.consoleUrl);
      await page.setExtraHTTPHeaders(identityHeaders(descriptor));
      let releaseSummary;
      const sessionReady = new Promise((resolve) => { releaseSummary = resolve; });
      const summaryPattern = "**/api/console?resource=summary";
      await page.route(summaryPattern, async (route) => {
        await sessionReady;
        await route.fallback();
      });
      const responsePromise = page.waitForResponse((response) => {
        try {
          const url = new URL(response.url());
          return response.request().method() === "POST"
            && url.origin === new URL(harness.consoleUrl).origin
            && url.pathname === SESSION_PATH;
        } catch {
          return false;
        }
      });
      try {
        await page.goto(target.toString(), { waitUntil: "domcontentloaded" });
        const response = await responsePromise;
        const body = await response.json();
        const session = validateBootstrap(body, descriptor, safeSeed.organizationId);
        pageState.set(page, { role: descriptor, csrfToken: session.csrfToken, registered: pageState.get(page)?.registered === true });
        releaseSummary();
      } catch {
        releaseSummary();
        throw new P0BLiveBrowserFixtureError("session_bootstrap_failed", "P0-B live browser session bootstrap failed");
      }
      return descriptor;
    },

    /** Install a Chromium virtual authenticator without exposing its handle. */
    async installVirtualAuthenticator(page, role) {
      assertPage(page);
      try {
        roleDescriptor(safeSeed, role);
        const cdp = await page.context().newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        await cdp.send("WebAuthn.addVirtualAuthenticator", {
          options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            automaticPresenceSimulation: true,
            isUserVerified: true
          }
        });
      } catch {
        throw new P0BLiveBrowserFixtureError("webauthn_unavailable", "P0-B WebAuthn virtual authenticator is unavailable");
      }
    },

    /** Run the live registration ceremony and store the credential in PostgreSQL. */
    async registerWebAuthn(page) {
      assertPage(page);
      const state = pageState.get(page);
      if (!state) throw new P0BLiveBrowserFixtureError("session_required", "P0-B page has not completed session bootstrap");
      if (state.registered) return Object.freeze({ registered: true });
      try {
        const result = await page.evaluate(async ({ organizationId, csrfToken }) => {
          const toBytes = (value) => {
            const padding = "=".repeat((4 - (value.length % 4)) % 4);
            const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
            return Uint8Array.from(binary, (character) => character.charCodeAt(0));
          };
          const toBase64Url = (value) => {
            const bytes = new Uint8Array(value);
            let binary = "";
            for (const byte of bytes) binary += String.fromCharCode(byte);
            return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
          };
          const json = async (path, body) => {
            const response = await fetch(path, {
              method: "POST",
              headers: { accept: "application/json", "content-type": "application/json", "agentpass-csrf": csrfToken },
              credentials: "same-origin",
              body: JSON.stringify(body),
              cache: "no-store"
            });
            const value = await response.json();
            if (!response.ok) {
              const code = typeof value?.error?.code === "string" && /^[a-z][a-z0-9_]{0,95}$/.test(value.error.code) ? `_${value.error.code}` : "";
              throw new Error(`${path.endsWith("/options") ? "registration_options" : "registration_verify"}_${response.status}${code}`);
            }
            return value;
          };
          const issued = await json("/api/auth/webauthn/registration/options", { organization_id: organizationId });
          const options = issued?.options;
          if (!options || typeof options.challenge !== "string" || !options.user || typeof options.user.id !== "string") throw new Error("WebAuthn registration options are invalid");
          const publicKey = {
            ...options,
            challenge: toBytes(options.challenge),
            user: { ...options.user, id: toBytes(options.user.id) },
            ...(Array.isArray(options.excludeCredentials)
              ? { excludeCredentials: options.excludeCredentials.map((credential) => ({ ...credential, id: toBytes(credential.id) })) }
              : {})
          };
          const credential = await navigator.credentials.create({ publicKey });
          if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error("WebAuthn registration credential is unavailable");
          const browserCredential = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: toBase64Url(credential.response.clientDataJSON),
              attestationObject: toBase64Url(credential.response.attestationObject),
              transports: typeof credential.response.getTransports === "function" ? credential.response.getTransports() : []
            },
            clientExtensionResults: credential.getClientExtensionResults()
          };
          const verified = await json("/api/auth/webauthn/registration/verify", {
            organization_id: organizationId,
            challenge_id: issued.challenge_id,
            credential: browserCredential
          });
          if (typeof verified?.credential_id !== "string" || !/^[A-Za-z0-9_-]{22,1366}$/.test(verified.credential_id)
            || typeof verified.registered_at !== "string" || !Number.isFinite(Date.parse(verified.registered_at))) throw new Error("WebAuthn registration was not confirmed");
          return { registered: true };
        }, { organizationId: safeSeed.organizationId, csrfToken: state.csrfToken });
        if (result?.registered !== true) throw new Error("registration not confirmed");
      } catch (error) {
        const marker = String(error?.message ?? "").match(/registration_(?:options|verify)_[1-5][0-9]{2}(?:_[a-z][a-z0-9_]{0,95})?/u)?.[0];
        throw new P0BLiveBrowserFixtureError(marker ?? "webauthn_registration_failed", "P0-B WebAuthn registration failed");
      }
      state.registered = true;
      return Object.freeze({ registered: true });
    },

    async installWebAuthnAuthenticator(page, role) {
      return fixture.installVirtualAuthenticator(page, role);
    },

    async registerPasskey(page) {
      return fixture.registerWebAuthn(page);
    },

    /**
     * Run a real operation-bound recent-auth ceremony. The authorization is
     * supplied only to the callback, so it cannot appear in fixture metadata.
     */
    async withRecentAuth(page, operation, action) {
      assertPage(page);
      const state = pageState.get(page);
      if (!state) throw new P0BLiveBrowserFixtureError("session_required", "P0-B page has not completed session bootstrap");
      if (!state.registered) throw new P0BLiveBrowserFixtureError("credential_required", "P0-B page has no registered WebAuthn credential");
      if (typeof action !== "function") throw new TypeError("recent-auth action must be a function");
      if (!OPERATION.test(operation)) throw new TypeError("recent-auth operation is invalid");
      let authorizationId;
      try {
        authorizationId = await page.evaluate(async ({ organizationId, csrfToken, operation }) => {
          const toBytes = (value) => {
            const padding = "=".repeat((4 - (value.length % 4)) % 4);
            const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
            return Uint8Array.from(binary, (character) => character.charCodeAt(0));
          };
          const toBase64Url = (value) => {
            const bytes = new Uint8Array(value);
            let binary = "";
            for (const byte of bytes) binary += String.fromCharCode(byte);
            return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
          };
          const json = async (path, body) => {
            const response = await fetch(path, {
              method: "POST",
              headers: { accept: "application/json", "content-type": "application/json", "agentpass-csrf": csrfToken },
              credentials: "same-origin",
              body: JSON.stringify(body),
              cache: "no-store"
            });
            const value = await response.json();
            if (!response.ok) throw new Error("recent-auth request failed");
            return value;
          };
          const issued = await json("/api/auth/webauthn/options", { organization_id: organizationId, operation });
          const options = issued?.options;
          if (!options || typeof options.challenge !== "string") throw new Error("recent-auth options are invalid");
          const publicKey = {
            ...options,
            challenge: toBytes(options.challenge),
            ...(Array.isArray(options.allowCredentials)
              ? { allowCredentials: options.allowCredentials.map((credential) => ({ ...credential, id: toBytes(credential.id) })) }
              : {})
          };
          const credential = await navigator.credentials.get({ publicKey });
          if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("recent-auth credential is unavailable");
          const browserCredential = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: toBase64Url(credential.response.clientDataJSON),
              authenticatorData: toBase64Url(credential.response.authenticatorData),
              signature: toBase64Url(credential.response.signature),
              userHandle: credential.response.userHandle === null ? null : toBase64Url(credential.response.userHandle)
            },
            clientExtensionResults: credential.getClientExtensionResults()
          };
          const verified = await json("/api/auth/webauthn/verify", {
            organization_id: organizationId,
            operation,
            challenge_id: issued.challenge_id,
            credential: browserCredential
          });
          if (typeof verified?.authorization_id !== "string" || !verified.authorization_id) throw new Error("recent-auth authorization is invalid");
          return verified.authorization_id;
        }, { organizationId: safeSeed.organizationId, csrfToken: state.csrfToken, operation });
      } catch {
        throw new P0BLiveBrowserFixtureError("recent_auth_failed", "P0-B recent WebAuthn authentication failed");
      }
      try {
        return await action(Object.freeze({
          authorizationId,
          csrfToken: state.csrfToken,
          organizationId: safeSeed.organizationId,
          role: state.role.role
        }));
      } catch {
        throw new P0BLiveBrowserFixtureError("recent_auth_action_failed", "P0-B recent-auth action failed");
      }
    },

    async authenticateRecentAuth(page, operation, action) {
      return fixture.withRecentAuth(page, operation, action);
    },

    async invalidateRecentAuth(role, failure) {
      const descriptor = roleDescriptor(safeSeed, role);
      if (!new Set(["stale", "replayed", "cross_operation", "cross_tenant"]).has(failure)) throw new TypeError("recent-auth failure is invalid");
      const session = await databasePool.query(`SELECT id FROM human_sessions
        WHERE member_id=$1 AND organization_id=$2 AND revoked_at IS NULL
        ORDER BY created_at DESC,id DESC LIMIT 1`, [descriptor.memberId, safeSeed.organizationId]);
      const sessionId = session.rows?.[0]?.id;
      if (!sessionId) throw new P0BLiveBrowserFixtureError("session_required", "P0-B browser session is unavailable");
      if (failure === "stale") {
        await databasePool.query("UPDATE human_sessions SET recent_auth_at=clock_timestamp()-interval '10 minutes' WHERE id=$1", [sessionId]);
      } else if (failure === "replayed") {
        await databasePool.query("UPDATE human_sessions SET recent_auth_consumed_at=clock_timestamp() WHERE id=$1", [sessionId]);
      } else if (failure === "cross_operation") {
        await databasePool.query("UPDATE human_sessions SET recent_auth_operation='device.revoke' WHERE id=$1", [sessionId]);
      } else {
        await databasePool.query("UPDATE human_sessions SET recent_auth_organization_id=$2 WHERE id=$1", [sessionId, safeSeed.otherOrganizationId]);
      }
    },

    async resetManualWakeEvidence() {
      await databasePool.query("DELETE FROM device_manual_wake_requests WHERE organization_id=$1", [safeSeed.organizationId]);
      await databasePool.query("DELETE FROM device_manual_wake_events WHERE organization_id=$1", [safeSeed.organizationId]);
    },

    async close() {
      if (closed) return;
      closed = true;
      await harness.close();
    }
  };

  return Object.freeze(fixture);
}

export const createP0BLiveBrowserFixture = startP0BLiveBrowserFixture;

/** Seed migrations, provider identities, and active role memberships. */
export async function seedP0BHumanBrowserDatabase({ pool, organizationId, refreshNonceKeyId, refreshNonceKey, now = () => Date.now() } = {}) {
  if (!pool || typeof pool.connect !== "function") throw new TypeError("P0-B PostgreSQL pool is required");
  if (!UUID.test(organizationId)) throw new TypeError("P0-B organization ID is invalid");
  if (typeof now !== "function" || !Number.isSafeInteger(now()) || now() < 0) throw new TypeError("P0-B seed clock is invalid");
  const ids = Object.create(null);
  const otherOrganizationId = crypto.randomUUID();
  const devices = ["同期済み Mac", "反映待ち Mac", "ブロック中 Mac", "古い状態 Mac", "オフライン Mac", "失効済み Mac"]
    .map((label) => Object.freeze({ deviceId: crypto.randomUUID(), label, keys: crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }) }));
  for (const role of ROLES) {
    ids[role] = Object.freeze({
      role,
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      subject: `p0b-${role}-${crypto.randomUUID()}`
    });
  }
  const client = await pool.connect();
  let stage = "migration";
  try {
    await createMigrationRunner({ client, applicationVersion: "p0b-live-browser-fixture" }).run();
    stage = "tenant";
    await client.query("BEGIN");
    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)", [organizationId, "P0-B live browser", otherOrganizationId, "P0-B cross-tenant control"]);
    for (const role of ROLES) {
      const descriptor = ids[role];
      await client.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,NULL,$2)", [descriptor.memberId, `P0-B ${role}`]);
      await client.query("INSERT INTO upstream_identities (provider,subject,member_id) VALUES ('chatgpt',$1,$2)", [descriptor.subject, descriptor.memberId]);
      await client.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,$4,'active')", [organizationId, descriptor.membershipId, descriptor.memberId, role]);
    }
    for (const device of devices) {
      stage = "devices";
      const publicKey = device.keys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
      await client.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
        VALUES ($1,$2,$3,'p256-sha256',$4,'active','{}'::jsonb)`, [organizationId, device.deviceId, device.label, publicKey]);
    }
    stage = "policy";
    await client.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
      VALUES ($1,$2,1,'P0-B live policy',$3::jsonb,'active',$4)`, [organizationId, crypto.randomUUID(), JSON.stringify({
      operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] }
    }), ids.owner.memberId]);
    await client.query("COMMIT");
    stage = "nonce";
    const nonceCodec = createRefreshNonceCodec({ keys: { [refreshNonceKeyId]: refreshNonceKey }, activeKeyId: refreshNonceKeyId });
    stage = "authority";
    const authority = createControlPlaneAuthorityRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x6c), refreshNonceCodec: nonceCodec });
    const refreshIssuedAt = new Date(now()).toISOString();
    const reduction = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
      organization_id: organizationId,
      issued_at: refreshIssuedAt,
      expires_at: new Date(Date.parse(refreshIssuedAt) + 240_000).toISOString()
    });
    if (reduction.generation !== 2) throw new Error("authority generation mismatch");
    stage = "states";
    await pool.query("UPDATE device_control_plane_state SET observed_generation=2,refresh_state='applied',last_observed_at=clock_timestamp() WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[0].deviceId]);
    await pool.query("UPDATE device_control_plane_state SET observed_generation=1,refresh_state='pending' WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[1].deviceId]);
    await pool.query("UPDATE device_control_plane_state SET observed_generation=1,refresh_state='blocked',last_error_code='internal_error' WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[2].deviceId]);
    await pool.query("UPDATE device_control_plane_state SET observed_generation=2,refresh_state='stale' WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[3].deviceId]);
    await pool.query("UPDATE device_refresh_outbox SET status='acknowledged',first_delivered_at=clock_timestamp(),last_delivered_at=clock_timestamp(),acknowledged_at=clock_timestamp() WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[3].deviceId]);
    await pool.query("UPDATE device_control_plane_state SET observed_generation=1,refresh_state='offline' WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[4].deviceId]);
    await pool.query("UPDATE devices SET status='revoked' WHERE organization_id=$1 AND id=$2", [organizationId, devices[5].deviceId]);
    await pool.query("UPDATE device_control_plane_state SET observed_generation=2,refresh_state='revoked' WHERE organization_id=$1 AND device_id=$2", [organizationId, devices[5].deviceId]);
    return Object.freeze({ organizationId: organizationId.toLowerCase(), otherOrganizationId, roles: ids, devices });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    const reason = typeof error?.code === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(error.code) ? `_${error.code.toLowerCase()}` : "";
    throw new P0BLiveBrowserFixtureError(`database_seed_${stage}${reason}_failed`, "P0-B live browser database seed failed");
  } finally {
    client.release();
  }
}

function publicSeed(seed) {
  return Object.freeze({
    organizationId: seed.organizationId,
    otherOrganizationId: seed.otherOrganizationId,
    roles: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, roleDescriptor(seed, role)]))),
    devices: Object.freeze(seed.devices.map(({ deviceId, label }) => Object.freeze({ deviceId, label })))
  });
}

function roleDescriptor(seed, role) {
  if (!ROLE_SET.has(role)) throw new TypeError("P0-B role is invalid");
  const value = seed.roles[role];
  return Object.freeze({
    role,
    userId: value.subject ?? value.userId,
    memberId: value.memberId,
    membershipId: value.membershipId,
    organizationId: seed.organizationId
  });
}

function identityHeaders(descriptor) {
  return Object.freeze({
    "oai-authenticated-user-id": descriptor.userId,
    "oai-authenticated-user-email": USER_EMAILS[descriptor.role]
  });
}

function validateBootstrap(value, descriptor, organizationId) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !value.session || typeof value.csrf_token !== "string" || !TOKEN.test(value.csrf_token)) throw new Error("session response is invalid");
  const session = value.session;
  if (session.role !== descriptor.role || session.member_id !== descriptor.memberId || session.organization_id !== organizationId || !UUID.test(session.session_id)) throw new Error("session binding is invalid");
  return Object.freeze({ csrfToken: value.csrf_token });
}

function consolePath(value, origin) {
  if (typeof value !== "string" || value.length === 0 || !value.startsWith("/") || value.startsWith("//")) throw new TypeError("P0-B console path is invalid");
  let target;
  try { target = new URL(value, origin); } catch { throw new TypeError("P0-B console path is invalid"); }
  if (target.origin !== new URL(origin).origin || target.username || target.password || target.hash) throw new TypeError("P0-B console path is invalid");
  return target;
}

function assertPage(page) {
  if (!page || typeof page.evaluate !== "function" || typeof page.goto !== "function" || typeof page.setExtraHTTPHeaders !== "function") throw new TypeError("Playwright Page is required");
}

function assertContext(context) {
  if (!context || typeof context.setExtraHTTPHeaders !== "function") throw new TypeError("Playwright BrowserContext is required");
}
