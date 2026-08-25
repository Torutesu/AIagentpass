# Cloudflare Small Software runtime adapter

`apps/cloud-api/src/providers/cloudflare/` is the provider boundary for Small
Software runtime publication. The Cloud API uses the provider-neutral
`reserveOperation`, `inspectOperation`, and `reconcileOperation` methods; no
Cloudflare SDK, Wrangler process, provider response, or credential is allowed
to cross into the domain service.

## Modes and qualification

The adapter defaults to `mode: "plan"`. Plan mode builds a bounded publication
descriptor and performs no network or provider action. Its result is always
`status: "planned"` with `qualification_status: "not_proven"` and reason
`plan_only`.

Live mode requires an injected `transport.request` and a
`credentialProvider`. The credential provider is workload-identity code owned
by the hosted composition; it is never logged or returned. If either live
dependency is absent, the adapter returns `status: "not_proven"` with reason
`live_runtime_unavailable`. Local fakes and plan output therefore cannot be
counted as Cloudflare qualification evidence.

Example configuration (the token is intentionally not an adapter option):

```js
const runtime = createCloudflareRuntimeAdapter({
  mode: "live",
  accountId: "0123456789abcdef0123456789abcdef",
  namespaceId: "agentpass-preview",
  ingressOrigin: "https://apps.example.com",
  transport: workloadIdentityCloudflareTransport,
  credentialProvider: workloadIdentityHeaders,
});
```

Only `https://api.cloudflare.com/client/v4` is accepted as the API origin.
Targets are bounded to Workers, Pages, R2, and D1, with fixed maximum artifact
size, resource count, binding count, route count, and in-memory operations.
Caller-supplied credential/token fields and unknown limits fail closed.

## Artifact and route invariants

Every publication requires a lower-case SHA-256 `artifact_digest` and a
request digest. If bytes are supplied at the boundary, the adapter recomputes
SHA-256 before making a provider request. A provider observation that reports a
different artifact digest is rejected as `cloudflare.digest_mismatch`.

Cloudflare deployment IDs and version IDs are metadata only; they are never
used as tenant or authorization identity. Active generations are monotonic,
and a stale callback cannot reactivate an older release. Routes always expose
`direct_route_allowed: false`; the canonical URL is the AgentPass ingress
origin, not a provider URL.

## Evidence boundary

The focused adapter suite covers plan-only side-effect freedom, live runtime
absence, artifact substitution, idempotency substitution, provider response
loss, response digest mismatch, stale generations, bounded resource kinds, and
credential redaction. These are contract tests. Real account/namespace/Worker,
Pages/R2/D1, route isolation, workload identity, and revocation propagation
remain protected external evidence and are `not_proven` until run on a
protected environment.
