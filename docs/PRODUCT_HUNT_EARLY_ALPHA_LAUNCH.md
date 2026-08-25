# Product Hunt Early Alpha Launch

## One-line hook

**AI can build your tiny app in minutes. AgentPass gives it a safe way to deploy and share it without handing over your cloud keys.**

## Concrete scene

You ask Claude Code or Cursor for a private CRM, sprint tracker, dashboard, or customer-specific workflow. The code is ready, but deployment, login, permissions, secret storage, and sharing become a second infrastructure project. AgentPass turns that handoff into a reviewable flow:

```text
Prompt → agent builds → inspect → source digest → publish plan → approve → share
```

## Who should try it

- Vibe coders who can build an app but do not want to configure cloud credentials.
- Small teams that need a private internal tool without adopting a full SaaS platform.
- API consumers who want a provider advisory to become a proposed, reviewable PR.

## Honest Early Alpha positioning

The OSS checkout proves contracts, deterministic planning, redaction, idempotency, tenant binding, and provider-neutral adapters locally. It does not claim live Cloudflare deployment, GitHub PR creation, external PostgreSQL qualification, or production macOS qualification without protected evidence. Keep those rows `not_proven` until the external run is bound to the exact source tree and artifacts.

## Demo sequence

1. Run `agentpass small-software inspect` in a toy project.
2. Run `agentpass small-software bundle` and show the source digest.
3. Run `agentpass small-software prepare` and show the bounded plan.
4. Use the MCP `agentpass_app_inspect` and `agentpass_apps_list` tools.
5. Show a share locator being revoked without exposing a bearer secret.
6. Show a maintenance patch proposal with exact changed paths and `not_proven` external status.

## Do not say

Do not say “one-click production deploy”, “fully autonomous merge”, or “your keys are impossible to steal”. The current release is **Early Alpha / plan-safe OSS**; real provider and hardware qualification is a separate gate.
