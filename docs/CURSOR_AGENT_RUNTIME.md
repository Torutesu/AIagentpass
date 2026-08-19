# Cursor Agent runtime materialization

The Cursor adapter launches the AgentPass-managed runtime at:

`/Library/Application Support/AgentPass/CursorAgent/runtime`

The runtime is installed by a root-only macOS command. A launch request cannot
choose a runtime path, manifest, public key, shell, or `PATH` entry.

## Signed manifest contract

The input manifest is canonical JSON followed by exactly one LF. Its top-level
object has exactly `core` and `signature`:

```json
{
  "core": {
    "schema_version": 1,
    "runtime_id": "cursor-agent",
    "runtime_version": "2026.08.17",
    "release_digest": "sha256:<64 lowercase hex characters>",
    "materialization_epoch": 1,
    "files": [
      {
        "relative_path": "node",
        "sha256": "<64 lowercase hex characters>",
        "size": 123,
        "executable": true
      }
    ]
  },
  "signature": {
    "algorithm": "ed25519",
    "domain": "AgentPass-Cursor-Agent-Runtime-Manifest-v1\\u0000",
    "key_id": "cursor-runtime-release-2026-08",
    "signature_base64url": "<86 base64url characters>"
  }
}
```

`core.files` is sorted by `relative_path`. The signature input is the UTF-8
bytes of `AgentPass-Cursor-Agent-Runtime-Manifest-v1\0`, followed immediately
by canonical JSON of `core` (without a newline). The public key is not embedded
in the manifest. The caller supplies an independently pinned 44-byte Ed25519
SPKI DER file and its expected `key_id`; both must match before a signature is
accepted.

Both `runtime_version` and `key_id` use the conservative pattern
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. They do not accept `+`, `:`, path
separators, or control characters.

The source tree must be a closed inventory: every regular file appears exactly
once, every directory is derived from a listed file path, and there are no
symlinks, hard-linked files, special files, writable source objects, credential
paths, or log paths. It must contain exactly the required `node` and `index.js`
files; `node` is executable and `index.js` is non-executable. Runtime paths use
relative ASCII components from `[A-Za-z0-9._@+-]+` and are at most 1,024
bytes. Each file is at most 256 MiB; the aggregate limits are 4,096 files,
4,096 directories, 8,192 observed inventory entries, and 512 MiB total. The
signed manifest is at most 2 MiB. A
changed source file is read and hashed through one no-follow descriptor, then
the whole source inventory is checked again before publication.

## Independent trust config

The separately supplied public DER and key ID are materialized as this
canonical JSON file, with no trailing LF or other whitespace, before the
runtime is published:

`/Library/Application Support/AgentPass/Trust/cursor-agent-runtime-key-v1.json`

```json
{
  "schema_version": 1,
  "key_id": "cursor-runtime-release-2026-08",
  "public_key_der_base64url": "<44-byte Ed25519 SPKI DER>"
}
```

The config is derived only from the independently supplied 44-byte DER and
key ID. It is published with a private sibling staging file, fsync, and
exclusive hard-link publication; an existing config is accepted only when its
bytes are exactly equal. A mismatched config is never replaced.

## Materialization and publication

The materializer creates a private sibling staging directory beneath the
destination parent. It copies through no-follow descriptors, hashes each file
against the signed manifest, fsyncs files and directories, sets runtime files
to `0444` or `0555`, sets runtime directories to `0555`, and chowns the result
to root in production. The signed input is published as
`runtime-manifest.json` with exclusive hard-link publication, so an existing
manifest is never replaced.

The trust config and signed manifest are published and verified exactly first;
both their parent directories are fsync'd. Only then is the runtime directory
staged and published by an atomic same-parent rename after an absence check and
an exclusive `mkdir` reservation of the final name. If a process crashes after
metadata publication but before runtime publication, a later run may resume
only when both pre-existing metadata files are exact. A mismatched metadata
file fails closed. An existing runtime, symlink, or other object is terminal
no-clobber state, even if metadata is missing or mismatched. The destination
parent is root-owned and non-group/world-writable in production, which is part
of the root-only trust boundary.

A failed run removes only its own private staging path. It does not remove or
modify an existing destination.

## Production command

The CLI is intentionally fixed to macOS/root and does not accept a destination
override:

```sh
sudo node scripts/cursor-runtime/materialize.mjs \
  /absolute/path/to/cursor-agent-runtime \
  /absolute/path/to/runtime-manifest.json \
  /absolute/path/to/pinned-cursor-runtime-public-key.der \
  cursor-runtime-release-2026-08
```

The trusted DER file must be distributed through an independent release
configuration or operator-controlled provisioning step. A public key shipped
next to an untrusted runtime or copied from the manifest is not a trust root.
In production, the signed manifest, trusted DER file, source runtime directory,
and every source object must also be root-owned and non-writable by group or
other users.

Tests use the exported `materializeCursorAgentRuntime` function with temporary
paths and `production: false`; they may inject `trustConfigPath` or
`trustParent`, and they do not weaken the production CLI policy.
