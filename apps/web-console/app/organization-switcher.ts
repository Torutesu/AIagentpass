import type { Organization, OrganizationClient } from "./organization-client";

const PAGE_LIMIT = 100;
const MAX_PAGES = 10;

export class OrganizationSwitcherError extends Error {
  constructor(message = "Organization pagination is invalid") {
    super(message);
    this.name = "OrganizationSwitcherError";
  }
}

/**
 * Loads the bounded server-authorized organization set used by the workspace
 * selector. Cursor loops, duplicate identities, and an unbounded result fail
 * closed instead of presenting an ambiguous tenant choice.
 */
export async function loadOrganizationSwitcherOrganizations(
  client: Pick<OrganizationClient, "listOrganizations">,
  signal?: AbortSignal,
): Promise<readonly Organization[]> {
  const organizations: Organization[] = [];
  const organizationIds = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | undefined;

  for (let pageNumber = 0; pageNumber < MAX_PAGES; pageNumber += 1) {
    const page = await client.listOrganizations({ limit: PAGE_LIMIT, ...(cursor === undefined ? {} : { cursor }), signal });
    for (const organization of page.items) {
      if (organizationIds.has(organization.id)) throw new OrganizationSwitcherError();
      organizationIds.add(organization.id);
      organizations.push(organization);
    }
    if (page.nextCursor === null) return Object.freeze([...organizations]);
    if (cursors.has(page.nextCursor)) throw new OrganizationSwitcherError();
    cursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }

  throw new OrganizationSwitcherError("Organization pagination exceeded the safe bound");
}
