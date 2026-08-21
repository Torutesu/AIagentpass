# Agent readiness UI

The overview is the operator's first decision surface. It shows five states using only existing, safe metadata:

| Card | Source | Meaning |
| --- | --- | --- |
| Platform auth | same-origin Security metadata and browser WebAuthn support | Whether a passkey can be used for protected human operations |
| Human session | `/api/auth/session` | Whether the current browser session is active and when it expires |
| Agent session / Capability | summary agents plus `/api/console?resource=capabilities` | Whether a registered Agent has an unexpired, tenant/device-bound short-lived capability |
| Audit | summary audit health | Whether the returned device audit chains are continuous |
| Revoke / emergency stop | summary lifecycle plus `/api/console?resource=revocations` | Whether Agent/device revocation or organization stop is active |

The UI deliberately does not call an active capability a connected process. It shows the expiry and binding metadata only. Signed Capability envelopes, session cookies, CSRF values, WebAuthn assertions, private keys, and any reusable token are never rendered, logged, persisted in browser storage, or placed in a URL.

Browser-assisted Mac enrollment follows the same boundary: the v2 invitation credential exists only in the issuance/handoff call stack, is sent through the validated one-consume loopback handoff, and is never put in React state, the DOM, clipboard, browser storage, URLs, or logs. The UI retains only non-secret enrollment metadata. A missing, mismatched, failed, or non-exact handoff acknowledgement fails closed and discards the invitation; there is no manual credential-display fallback. Browser contract tests use mocked routes and do not prove a deployed listener or production browser environment.

When a state needs attention, the overview presents one plain-language reason and one next operation. If the summary or auth state cannot be verified, the UI fails closed and clears operational data rather than showing a stale or invented healthy state.

This is a presentation contract. It does not replace Cloud authorization, revocation, audit-chain verification, or the native Agent enforcement path.
