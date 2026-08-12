import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { getOrganizationVisibility } from "../app/organization-client.ts";

const componentPath = new URL("../app/components/OrganizationPanel.tsx", import.meta.url);
const consolePath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("OrganizationPanel is standalone and covers the administration flow", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /export function OrganizationPanel/);
  assert.match(source, /createOrganizationClient/);
  for (const operation of ["listOrganizations", "createOrganization", "renameOrganization", "listMembers", "listInvitations", "createInvitation", "revokeInvitation", "acceptInvitation", "updateMemberRole", "removeMember"]) assert.match(source, new RegExp(`\\.${operation}\\(`));
  for (const state of ["loading", "empty", "error", "conflict"]) assert.match(source, new RegExp(state));
  assert.match(source, /oneTimeToken/);
  assert.match(source, /一度だけ表示/);
  assert.doesNotMatch(source, /AgentPassConsole/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
});

test("panel visibility matches owner/admin/auditor/viewer policy", () => {
  assert.equal(getOrganizationVisibility("owner").canManageMembers, true);
  assert.equal(getOrganizationVisibility("admin").canInvite, true);
  assert.equal(getOrganizationVisibility("auditor").canViewMembers, true);
  assert.equal(getOrganizationVisibility("auditor").canInvite, false);
  assert.equal(getOrganizationVisibility("viewer").canViewMembers, false);
  assert.equal(getOrganizationVisibility("viewer").canViewInvitations, false);
});

test("AgentPassConsole exposes the Organization administration view", async () => {
  const source = await readFile(consolePath, "utf8");
  assert.match(source, /import \{ OrganizationPanel \} from "\.\/OrganizationPanel"/);
  assert.match(source, /\| "organizations"/);
  assert.match(source, /label: "Organizations"/);
  assert.match(source, /activeView === "organizations" \? <OrganizationPanel \/> : null/);
  assert.match(source, /organization-content/);
});
