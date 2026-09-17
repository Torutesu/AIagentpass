# AgentPass documentation index

Start here. Everything in `docs/` is either **current** (describes the system
as it exists or the work still ahead) or lives in [`archive/`](archive/)
(historical plans and completed-phase evidence, kept for provenance).

Convention: a plan or evidence document moves to `archive/` the day its phase
closes, with a one-line banner at the top noting when and why.

## Plans — current

- [V1 execution plan](V1_EXECUTION_PLAN.md) — authoritative product gates and definition of done
- [Implementation plan 2026-08-16](IMPLEMENTATION_PLAN_2026-08-16.md) — current source checkpoint and ticket lanes
- [Implementation plan 2026-08-15](IMPLEMENTATION_PLAN_2026-08-15.md) — prior baseline, still contract-referenced
- [Forward implementation plan 2026-08-16](FORWARD_IMPLEMENTATION_PLAN_2026-08-16.md) — contract-referenced forward work
- [Implementation roadmap](IMPLEMENTATION_ROADMAP.md) — milestone breakdown
- [Quality improvement plan](QUALITY_IMPROVEMENT_PLAN.md) — product-quality tracks in flight
- [Product Hunt early-alpha launch](PRODUCT_HUNT_EARLY_ALPHA_LAUNCH.md)
- [Hosted deployment options](HOSTED_DEPLOYMENT_OPTIONS.md)

## Contracts & specifications

- [Cloud API v1](CLOUD_API_V1.md)
- [Hosted identity bootstrap v1](HOSTED_IDENTITY_BOOTSTRAP_V1.md)
- [Small Software CLI](SMALL_SOFTWARE_CLI.md) · [Small Software Cloud spec](SMALL_SOFTWARE_CLOUD_SPEC.md) · [Self-maintaining APIs spec](SELF_MAINTAINING_APIS_SPEC.md)
- [Audit anchor](AUDIT_ANCHOR.md) · [Remote control](REMOTE_CONTROL.md)
- [Refresh nonce codec](REFRESH_NONCE_CODEC.md)

## Architecture & design

- [Agent platform architecture](AGENT_PLATFORM_ARCHITECTURE.md) · [Detailed design](DETAILED_DESIGN.md)
- ADRs: [001 native security boundary](ADR-001-native-security-boundary.md) · [002 headless distribution](ADR-002-headless-distribution.md) · [003 contract authority & versioning](ADR-003-contract-authority-and-versioning.md)
- Native: [broker](NATIVE_BROKER.md) · [Host XPC](NATIVE_HOST_XPC.md) · [Host XPC attach binding](HOST_XPC_ATTACH_BINDING.md) · [host activation lifecycle](HOST_ACTIVATION_LIFECYCLE.md)
- [Cursor agent runtime](CURSOR_AGENT_RUNTIME.md) · [Cloudflare runtime adapter](CLOUDFLARE_RUNTIME_ADAPTER.md)
- Recovery & migration: [threshold owner recovery design](THRESHOLD_OWNER_RECOVERY_DESIGN.md) · [offline recovery](OFFLINE_RECOVERY.md) · [legacy migration](LEGACY_MIGRATION.md)
- Deployment trust: [deployment attestation trust](DEPLOYMENT_ATTESTATION_TRUST.md) · [deployment evidence gate](DEPLOYMENT_EVIDENCE_GATE.md) · [production evidence boundary](PRODUCTION_EVIDENCE_BOUNDARY.md)

## Threat models & security gates

- [Platform threat model](PLATFORM_THREAT_MODEL.md) (see also root [THREAT_MODEL.md](../THREAT_MODEL.md))
- [Production readiness gate](PRODUCTION_READINESS_GATE.md) · [production hardening plan](PRODUCTION_HARDENING_PLAN.md) · [readiness audit 2026-08-20](PRODUCTION_READINESS_AUDIT_2026-08-20.md)
- [Platform auth qualification](PLATFORM_AUTH_QUALIFICATION.md) · [platform auth production operations](PLATFORM_AUTH_PRODUCTION_OPERATIONS.md)
- Independent reviews: [`reviews/`](reviews/)

## Runbooks & operations

- [Incident & revoke runbook](INCIDENT_AND_REVOKE_RUNBOOK.md)
- Release: [RELEASE](RELEASE.md) · [release preflight](RELEASE_PREFLIGHT.md) · [qualification evidence matrix](RELEASE_QUALIFICATION_EVIDENCE_MATRIX.md) · [XPC qualification](RELEASE_XPC_QUALIFICATION.md) · [`release/`](release/)
- PostgreSQL: [schema identity](POSTGRES_SCHEMA_IDENTITY.md) · [0011 preflight](POSTGRES_0011_PREFLIGHT.md) · [backup & restore](POSTGRES_BACKUP_RESTORE.md) · [cutover runbook](POSTGRES_CUTOVER_RUNBOOK.md)
- KMS: [qualification runbook](KMS_QUALIFICATION_RUNBOOK.md) · [signer rotation runbook](KMS_SIGNER_ROTATION_RUNBOOK.md) · [cloud signer KMS qualification](CLOUD_SIGNER_KMS_QUALIFICATION.md)
- Operations: [P0B E2E runbook](P0B_E2E_RUNBOOK.md) · [P0C hardware qualification](P0C_HARDWARE_QUALIFICATION.md) · [staging operations readiness](STAGING_OPERATIONS_READINESS_RUNBOOK.md) · [owner recovery delivery](OWNER_RECOVERY_DELIVERY_RUNBOOK.md) · [agent session physical qualification](AGENT_SESSION_N3E_PHYSICAL_QUALIFICATION.md)
- Operator runbooks: [`runbooks/`](runbooks/) · Qualification evidence contracts: [`qualification/`](qualification/)

## Archive

[`archive/`](archive/) holds closed-phase implementation plans, dated evidence
records, and point-in-time security reviews. Nothing there describes the
current system — read it for history only.
