# AgentPass Cloud API

Bootstrap a new self-hosted organization into a new protected directory:

```bash
npm run bootstrap -- --output-dir /absolute/protected/agentpass-cloud --organization-name "My team" --principal-id SIWC_USER_ID
```

The command prints the owner API token once. Store it as a server secret for the Web Console. It also writes the token verifier, Ed25519 bundle signer, public key, tenant store, and owner membership. Files are created without overwrite; secret files use mode `0600`.

Start the API behind a TLS reverse proxy:

```bash
export AGENTPASS_CLOUD_DATA_DIR=/absolute/protected/agentpass-cloud/data
export AGENTPASS_CLOUD_TOKEN_RECORDS_PATH=/absolute/protected/agentpass-cloud/token-records.json
export AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH=/absolute/protected/agentpass-cloud/bundle-private.pem
export AGENTPASS_CLOUD_HOST=127.0.0.1
export AGENTPASS_CLOUD_PORT=8080
npm start
```

The process binds loopback by default. Terminate with SIGINT/SIGTERM for graceful shutdown. Device replay evidence and both admission/principal rate-limit buckets survive restart. The file store takes an exclusive process lock and refuses a second writer. For multi-instance production, replace the reference file store, replay cache, and limiters with transactional shared storage; never share the JSON data directory between processes.

The API applies a peer-address admission limit before reading a body or running scrypt authentication, then applies a tenant/principal limit after authentication. Keep the runtime behind a TLS reverse proxy with its own connection and distributed rate limits. The reference runtime intentionally caps token records at 256 to bound authentication work.
