import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

async function componentSource() {
  return readFile(componentPath, "utf8");
}

function functionBody(source, name, nextName) {
  const start = source.indexOf(`function ${name}`);
  const end = source.indexOf(`function ${nextName}`, start);
  assert.notEqual(start, -1, `${name} should exist`);
  assert.notEqual(end, -1, `${nextName} should delimit ${name}`);
  return source.slice(start, end);
}

test("all Console reads and mutations wait for one shared session bootstrap", async () => {
  const source = await componentSource();
  const wrapper = functionBody(source, "fetchConsole", "supportsWebAuthn");
  const bootstrapPathUses = source.match(/\/api\/auth\/session/g) ?? [];
  const directConsoleFetches = source.match(/\bfetch\s*\(\s*[`"]\/api\/console/g) ?? [];
  const wrappedConsoleFetches = source.match(/\bfetchConsole\s*\(\s*[`"]\/api\/console/g) ?? [];

  assert.equal(bootstrapPathUses.length, 1, "the component should have one bootstrap endpoint declaration");
  assert.equal(directConsoleFetches.length, 0, "Console calls must not bypass fetchConsole");
  assert.ok(wrappedConsoleFetches.length >= 7, "all production Console paths should use fetchConsole");
  assert.match(source, /const consoleSessionContext = createConsoleSessionContext\(\)/);
  assert.match(source, /if \(result\) return Promise\.resolve\(result\)/);
  assert.match(source, /if \(!pending\)/);
  assert.match(source, /const current = bootstrapConsoleSession\(signal\)/);
  assert.ok(wrapper.indexOf("await consoleSessionContext.get(init.signal ?? undefined)") < wrapper.indexOf("await fetch(path"), "bootstrap must finish before the Console request");
  assert.match(source, /withAbort\(pending, signal\)/);
});

test("every Console mutation carries the exact in-memory CSRF token and same-origin credentials", async () => {
  const source = await componentSource();
  const wrapper = functionBody(source, "fetchConsole", "supportsWebAuthn");

  assert.match(source, /const CSRF_HEADER = "agentpass-csrf"/);
  assert.match(wrapper, /if \(isMutationMethod\(method\)\) headers\.set\(CSRF_HEADER, session\.csrfToken\)/);
  assert.match(wrapper, /credentials: "same-origin"/);
  assert.match(wrapper, /cache: "no-store"/);
  assert.match(wrapper, /redirect: "error"/);
  assert.match(source, /fetchConsole\("\/api\/console\?operation=issue-device-enrollment", \{[\s\S]*?method: "POST"/);
  assert.match(source, /fetchConsole\("\/api\/console\?operation=emergency-stop", \{[\s\S]*?method: "POST"/);
  assert.match(source, /fetchConsole\(`\/api\/console\?operation=\$\{encodeURIComponent\(operation\)\}`, \{[\s\S]*?method: "POST"/);
});

test("session material stays out of React state, browser storage, and logs", async () => {
  const source = await componentSource();
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /useState\([^\n]*(?:csrf|csrf_token|organizationId|authorization|challenge|assertion)/i);
  assert.match(source, /let result: ConsoleSession \| undefined/);
  assert.match(source, /let pending: Promise<ConsoleSession> \| undefined/);
  assert.match(source, /return Object\.freeze\(\{ get, clear \}\)/);
  assert.match(source, /const \[preflight, setPreflight\] = useState<PublicEnrollmentPreflight \| null>\(null\)/);
  assert.match(source, /const \[enrollmentStoreId\] = useState\(allocateEnrollmentStoreId\)/);
  assert.match(source, /const enrollmentStores = new Map<number, Record<string, unknown>>\(\)/);
  assert.doesNotMatch(source, /useState<Record<string, string> \| null>/);
  assert.doesNotMatch(source, /useState<Record<string, unknown> \| null>/);
  assert.doesNotMatch(source, /set(?:Csrf|CSRF|OrganizationId|Authorization)/);
});

test("abort and unauthorized responses clear safely and permit a later retry", async () => {
  const source = await componentSource();
  const wrapper = functionBody(source, "fetchConsole", "supportsWebAuthn");
  const context = functionBody(source, "createConsoleSessionContext", "isMutationMethod");

  assert.match(source, /function throwIfAborted\(signal\?: AbortSignal\)/);
  assert.match(source, /function withAbort<T>\(promise: Promise<T>, signal\?: AbortSignal\)/);
  assert.match(source, /const current = bootstrapConsoleSession\(signal\)/);
  assert.match(source, /signal\.addEventListener\("abort", onAbort, \{ once: true \}\)/);
  assert.match(source, /signal\?\.aborted \|\| isAbortError\(error\)/);
  assert.match(wrapper, /if \(init\.signal\?\.aborted \|\| isAbortError\(error\)\) throw abortError\(\)/);
  assert.match(wrapper, /response\.status === 401 \|\| response\.status === 403/);
  assert.match(wrapper, /consoleSessionContext\.clear\(session\)/);
  assert.match(source, /function clearConsoleSessionOnUnauthorized\(error: unknown\)/);
  assert.match(source, /error instanceof WebAuthnClientError && \(error\.status === 401 \|\| error\.status === 403\)/);
  assert.match(source, /clearConsoleSessionOnUnauthorized\(error\);/);
  assert.match(context, /if \(pending === shared\) pending = undefined/);
  assert.match(context, /if \(!session \|\| result === session\) result = undefined/);
  assert.match(source, /const controller = new AbortController\(\)/);
  assert.match(source, /return \(\) => controller\.abort\(\)/);
});

test("expired sessions replace every operational surface with a reauthentication gate", async () => {
  const source = await componentSource();

  assert.match(source, /const \[sessionState, setSessionState\] = useState<"active" \| "expired" \| "signed-out">\("active"\)/);
  assert.match(source, /setSessionState\("expired"\)/);
  assert.match(source, /sessionState !== "active" \? <SessionEndedSurface reason=\{sessionState\} \/>/);
  assert.match(source, /REAUTHENTICATION REQUIRED/);
  assert.match(source, /window\.location\.reload\(\)/);
  assert.match(source, /sessionState === "active" && activeView === "emergency"/);
  assert.match(source, /CONSOLE_SESSION_ENDED_EVENT = "agentpass:session-ended"/);
  assert.match(source, /window\.dispatchEvent\(new Event\(CONSOLE_SESSION_ENDED_EVENT\)\)/);
  assert.match(source, /window\.addEventListener\(CONSOLE_SESSION_ENDED_EVENT, expireSession\)/);
  assert.match(source, /summaryEpoch\.current \+= 1/);
  assert.match(source, /capabilityEpoch\.current \+= 1/);
  assert.match(source, /adminAuditEpoch\.current \+= 1/);
  assert.match(source, /<SecuritySurface onSessionEnded=\{expireSession\} \/>/);
});

test("global sign-out uses the same-origin DELETE contract and clears operational state", async () => {
  const source = await componentSource();
  const logout = functionBody(source, "logoutConsoleSession", "supportsWebAuthn");

  assert.match(logout, /method: "DELETE"/);
  assert.match(logout, /\[CSRF_HEADER\]: session\.csrfToken/);
  assert.match(logout, /credentials: "same-origin"/);
  assert.match(logout, /payload\.session !== null/);
  assert.match(logout, /consoleSessionContext\.clear\(session\)/);
  assert.match(source, /setSessionState\("signed-out"\)/);
  assert.match(source, /signOutPending \? "終了中…" : "サインアウト"/);
});

test("session role is strictly parsed and authority-changing controls are least-privilege", async () => {
  const source = await componentSource();

  assert.match(source, /type ConsoleRole = "owner" \| "admin" \| "auditor" \| "viewer"/);
  assert.match(source, /hasExactKeys\(session, \["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"\]\)/);
  assert.match(source, /const canManage = sessionRole === "owner" \|\| sessionRole === "admin"/);
  assert.match(source, /const canEmergencyStop = sessionRole === "owner"/);
  assert.match(source, /if \(sessionRole !== "owner" && sessionRole !== "admin"\) throw new Error\("role denied"\)/);
  assert.match(source, /item\.id !== "emergency" \|\| sessionRole === null \|\| canEmergencyStop/);
  assert.match(source, /canManage && agent\.agentId/);
  assert.match(source, /canManage && policy\.policyId/);
  assert.match(source, /canManage && device\.deviceId/);
  assert.doesNotMatch(source, /badge: "3"/);
  assert.doesNotMatch(source, /useState\("\/work\/repo"\)/);
});
