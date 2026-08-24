# Hosted deployment options

AgentPass can be used as local OSS or as a hosted service. The local path runs
on each user's Mac. The hosted path runs a shared Console and Cloud API operated
by an administrator.

## 1. Self-hosted OSS (free software)

Each user operates AgentPass locally. There is no AgentPass subscription, but
each user is responsible for their own Mac and operations.

```bash
git clone https://github.com/Torutesu/AIagentpass.git
cd AIagentpass
npm install
npm link
agentpass init
agentpass check
agentpass setup-macos
agentpass broker install
agentpass broker ping
```

Optional integrations:

```bash
agentpass integrate claude-code --install
agentpass integrate cursor --install
```

This is the current Early Alpha path. Use a test repository first; do not use
production keys until the documented production gates have passed.

## 2. Low-cost private beta

The operator runs one hosted Console and Cloud API for a small invited group.
Free tiers are suitable only for development or a tightly limited beta; quotas
and suspension risk mean they are not production qualification evidence.

The operator must provide HTTPS Console and API origins, TLS-verified
PostgreSQL, a KMS/HSM signing provider, authentication, tenant isolation,
rate limits, backups, and an incident contact before inviting external users.

Never put database passwords, private keys, or KMS credentials in GitHub, source
files, browser storage, or this repository.

## 3. Operator-funded hosted service

The operator may pay the infrastructure bill and let users access the hosted
service without charging them. This does **not** make the service cost-free:
the operator pays for compute, database storage, backups, network traffic, KMS
keys and requests, monitoring, and support.

Before calling this a public service, add tenant isolation, authentication,
quotas, abuse protection, data retention/deletion rules, privacy terms,
backup/restore, incident response, and automatic cost alerts.

"Free for users" means the operator is subsidizing usage. It does not remove
the infrastructure or security costs.

## Recommended rollout

1. Publish the OSS repository as Early Alpha.
2. Run the local setup with test repositories.
3. Test a small invited private beta with hard quotas.
4. Only then decide whether to operate a free-to-users hosted service.
