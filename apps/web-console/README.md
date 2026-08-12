# AgentPass Web Console

The human operations surface for AgentPass Cloud. It is a vinext application intended for private OpenAI Sites hosting and talks to the Cloud API only through its server-side bridge.

## Prerequisites

- Node.js `>=22.13.0`

## Quick Start

```bash
npm install
npm run dev
npm run build
```

The server-side console bridge requires `AGENTPASS_CLOUD_API_URL`, `AGENTPASS_ORGANIZATION_ID`, `AGENTPASS_CLOUD_TOKEN`, and `AGENTPASS_OPERATOR_USER_IDS`. The last value is a comma-separated allowlist of stable SIWC user IDs. Authentication alone never grants use of the privileged Cloud token; a signed-in user must also be in this explicit operator allowlist. Keep the Site private and store the Cloud token only as a server secret.

Deploy this console only on a hosting path that injects SIWC identity headers after authentication and strips client-supplied copies. Do not expose the application server directly behind a generic proxy that forwards `oai-authenticated-user-*` headers. The explicit operator allowlist is mandatory, but it does not make forgeable upstream identity headers trustworthy.

## Security boundary

- SIWC establishes identity; `AGENTPASS_OPERATOR_USER_IDS` supplies authorization.
- The Cloud bearer token stays server-side and is never returned to the browser.
- The bridge enforces same-origin requests, strict request schemas, bounded responses, no redirects, and `no-store` caching.
- Emergency stop, revocation, policy, device, agent, capability, and audit operations all persist in the Cloud API; the UI has no shadow state.

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: verify the vinext build output
- `npm test`: build and run the console API/render tests

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
