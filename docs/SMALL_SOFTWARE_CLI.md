# Small Software CLI

The CLI currently provides a provider-free, plan-only workflow. It reads an
`agentpass.app.json` manifest and the project inventory; it does not upload
source, contact Cloudflare, create a GitHub PR, or read credentials.

```sh
agentpass small-software inspect --path ./examples/small-software-demo
agentpass small-software bundle --path ./examples/small-software-demo
agentpass small-software prepare --path ./examples/small-software-demo
agentpass small-software publish --path ./examples/small-software-demo --plan-only
```

The repository includes this runnable manifest and Worker as a safe first
demo. Copy the directory before adding application-specific code.

The manifest must be inside the project root and use the frozen
`agentpass.app-manifest` v1 contract. Symlinks, non-regular files, path
traversal, unknown manifest fields, and secret-like values fail closed.

Every output is marked `status: "plan_only"`. A publish request without
`--plan-only` is rejected until protected provider credentials and independent
Cloudflare evidence are configured. `qualification_status: "not_proven"` is
intentional and is not a deployment success.
