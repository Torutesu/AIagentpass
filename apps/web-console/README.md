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

Production human-session bootstrap requires these server-only settings: `AGENTPASS_CLOUD_API_URL`, `AGENTPASS_CONSOLE_ORIGIN`, `AGENTPASS_ORGANIZATION_ID`, `AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY` (PKCS#8 Ed25519 PEM), `AGENTPASS_IDENTITY_ASSERTION_ISSUER`, `AGENTPASS_IDENTITY_ASSERTION_AUDIENCE`, and `AGENTPASS_IDENTITY_ASSERTION_KID`. `AGENTPASS_IDENTITY_PROVIDER` defaults to `chatgpt`. The private key and all assertion configuration stay in the server environment; they are never rendered or returned to the browser. Production login does not require `AGENTPASS_CLOUD_TOKEN` or `AGENTPASS_OPERATOR_USER_IDS`.

After `getChatGPTUser` has verified the platform SIWC identity, the BFF signs one compact, short-lived identity assertion and sends it to Cloud only in the `agentpass-console-identity` request header. The protected header is exactly `{alg:"EdDSA",kid,typ:"agentpass.console.identity",version:1}`. The payload is exactly `{aud,exp,iat,iss,jti,nbf,org,origin,provider,sub}`; it contains no `kid` or `redirect_uri`. The signature covers `base64url(header) + "." + base64url(payload)`. The session POST body sent upstream is always exactly `{}`. Cloud verifies and consumes `jti` once, then returns only the rotated HttpOnly session cookie and CSRF/session metadata.

The old operator-token bootstrap is available only when `NODE_ENV` is `development` or `test` and `AGENTPASS_ALLOW_LEGACY_SESSION_BOOTSTRAP=true`, together with its explicit token and operator allowlist. Never enable that path in production. The `/api/console` control-plane bridge also uses the Human session cookie/CSRF boundary in production; its operator-bearer compatibility mode requires the separate explicit `AGENTPASS_ALLOW_LEGACY_OPERATOR_BRIDGE=true` development/test flag.

Deploy this console only on a hosting path that injects SIWC identity headers after authentication and strips client-supplied copies. Do not expose the application server directly behind a generic proxy that forwards `oai-authenticated-user-*` headers. The legacy operator bridge still requires its explicit allowlist when enabled for development/test, but that allowlist is not used by the production human-session bootstrap and does not make forgeable upstream identity headers trustworthy.

## Security boundary

- Platform-verified SIWC establishes the upstream identity; Cloud resolves the immutable provider/subject membership.
- Production session bootstrap uses a server-only Ed25519 assertion header; the browser never receives the assertion or a Cloud bearer token.
- The bridge enforces same-origin requests, strict request schemas, bounded responses, no redirects, and `no-store` caching.
- Device enrollment requires a recent WebAuthn proof, forwards it only to the enrollment endpoint, and returns the strict v2 invitation through a separately validated `no-store` response. The invitation is bound to a release candidate and P-256 device-key fingerprint; the UI keeps it only in ephemeral component memory. Reload or “表示を消す” removes the credential-bearing handoff.
- Emergency stop, revocation, policy, device, agent, capability, and audit operations all persist in the Cloud API; the UI has no shadow state.

### Activity pagination limits

The Console activity cursor is an HMAC-protected position cursor. It intentionally contains no audit records and no per-device Cloud cursor state: the current 512-character Console cursor limit cannot safely carry an independently sized upstream cursor for every device. A later Console page therefore restarts each device stream at the Cloud head and follows authoritative `next_cursor` pages only as far as the deterministic merge requires.

To bound the resulting repeated-head work and protect availability from a hostile or non-progressing Cloud stream, one Console request may issue at most 64 upstream audit-page requests and accumulate at most 8,192 audit records. Exceeding either limit fails closed with HTTP 502 and `activity_pagination_budget_exceeded`; no partial activity page is returned. A future server-side cursor/state design can remove the repeated-head cost without expanding the browser-visible cursor.

## Enroll a Mac

Open **セットアップ → Macを安全に追加** and paste the one public preflight JSON emitted by the Mac setup flow. The guided form accepts exactly these four fields:

```json
{
  "version": 1,
  "platform": "macos",
  "candidate_id": "candidate-2026-08",
  "device_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

`candidate_id` is the signed release candidate selected by the setup flow and `device_key_fingerprint` is the SHA-256 fingerprint of the non-exportable P-256 public key. `platform` must be exactly `macos`. The Console rejects unknown fields, missing or malformed values, and any v2 invitation whose candidate/key binding differs from the imported DTO before it displays the invitation. A live handoff descriptor may add a separate correlation ID later; it is not part of this copy/paste preflight and is not a credential.

After the preflight preview, enter only a friendly device name and complete the browser-native step-up. The existing canonical v2 invitation is then issued for ten minutes. The imported preflight and invitation handoff are held only in ephemeral React memory; they are never written to local/session storage, a URL, analytics, or logs. The invitation is displayed once. Reload, dismissal, or expiry removes it. If an older setup flow cannot produce the DTO, use the clearly marked **上級者向け** fallback; it validates the same candidate and P-256 fingerprint rules without adding a correlation field to the base contract.

Copy the displayed invitation once and pass it to the CLI through stdin; never put it in argv, an environment variable, a repository, URL query, or shell history.

```bash
agentpass setup continue --execute \
  --enrollment-url 'https://api.example.com/v1' \
  --enrollment-stdin < enrollment.json
```

The Console bootstraps a durable Human session first, then performs browser-native WebAuthn registration and operation-bound recent-auth ceremonies through the same-origin BFF. The enrollment credential is displayed once in memory and is never written to browser storage. A full Playwright virtual-authenticator suite and physical-Mac qualification remain release gates.

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: verify the vinext build output
- `npm test`: build and run the console API/render tests

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
