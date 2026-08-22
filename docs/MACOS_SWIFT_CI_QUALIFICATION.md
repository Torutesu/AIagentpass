# macOS Swift qualification CI

The source-bound Swift lane is part of `.github/workflows/macos-hardware-qualification.yml`.
It runs after the exact commit/tree checkout binding and before the protected
release-artifact probes:

1. `swift test --package-path native/macos` runs with SwiftPM's scratch,
   config, security, and package-cache directories under `${RUNNER_TEMP}`.
2. `CLANG_MODULE_CACHE_PATH` points to the runner-temporary module cache.
   This is required because SwiftPM's manifest compilation can otherwise use a
   host-level Clang cache that is denied by the runner sandbox.
3. `native/macos/scripts/test-app-bundle.sh` builds and checks an ad-hoc
   universal app bundle. The script inherits the same module-cache policy and
   disables the SwiftPM subprocess sandbox only for this trusted CI checkout.
4. The lane writes an evidence JSON and SHA-256-bound test logs. The evidence
   binds source commit/tree, workflow run/attempt/job, runner identity,
   requested and observed architecture, Xcode/Swift versions, exact cache
   locations, exact commands, exit codes, and log digests.

The evidence artifact is a CI execution receipt, not a release assertion. It
does not qualify Developer ID signing, notarization, stapling, Secure Enclave,
launchd/NSXPC, or other protected physical-machine behavior. Those remain
`not_proven` until the existing protected qualification steps produce their
independent evidence.

For a local reproduction, use a fresh writable root and the same command shape:

```sh
cache_root="$(mktemp -d /private/tmp/agentpass-native-swift.XXXXXX)"
mkdir -m 700 -p "$cache_root/module-cache" "$cache_root/swiftpm-cache" \
  "$cache_root/swiftpm-config" "$cache_root/swiftpm-security" "$cache_root/scratch"
CLANG_MODULE_CACHE_PATH="$cache_root/module-cache" \
swift test --package-path native/macos --disable-sandbox \
  --cache-path "$cache_root/swiftpm-cache" \
  --config-path "$cache_root/swiftpm-config" \
  --security-path "$cache_root/swiftpm-security" \
  --scratch-path "$cache_root/scratch" --manifest-cache local
```

`SWIFT_MODULECACHE_PATH` alone is not the contract: the SwiftPM manifest
compiler in the affected toolchain follows `CLANG_MODULE_CACHE_PATH`.
