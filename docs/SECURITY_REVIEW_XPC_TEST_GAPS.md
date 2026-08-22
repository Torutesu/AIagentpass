# Host/Child XPC adversarial test lane

## Review-status boundary

This is a local adversarial test lane and not an independent third-party security
review. Its focused results cannot make the product production-ready. Production
approval additionally requires the signed, source/tree/image-bound review record
defined in [`SECURITY_REVIEW_PRODUCTION_GATE.md`](SECURITY_REVIEW_PRODUCTION_GATE.md),
with an externally provisioned reviewer identity, a separate reviewer key, an
unexpired decision, and no open critical/high finding. Until that protected evidence
exists, the disposition is `not_proven`.

監査日: 2026-08-19
対象: `native/macos/Tests/**` の Host/Child XPC 専用テストと test fixture
制約: production source、既存の非XPCテスト、protected path、commit/pushは変更していない

## 追加した証跡

### Host endpoint

- `NativeAgentAuthenticatedHostEndpointSecurityTests.swift`
  - expiry の観測時に Core session と Child registry が同時に revoke されること
  - signer failure と不正な空signatureで Child registry が残らないこと
  - sign response を破棄した後、同じ request sequence を再送しても signer が二重実行されないこと
  - attach の PID、PID generation、executable identity、ancestry、worktree digest の各 mismatch が deny されること
  - 空のsigner responseで Child registration と budget が revoke されること

### Peer process drift

- peer process drift は connection-owned session と Child registry を terminal
  revoke する実装とし、runnable regression test で確認する。

### Child XPC / registry

- `NativeAgentAuthenticatedChildGitAdversarialTests.swift`
  - PID generation / code identity substitution
  - sequence skip 後の terminal close
  - distinct payload に対する固定2回 budget
  - response-loss 後の同一 request replay

### SecureCoding schema

- `NativeAgentHostUnknownFieldNegativeTests.swift`
  - Host の全 request DTO と Child sign request に未知の keyed field を追加した archive を投入
  - authority boundary では未知フィールドを黙って無視せず deny することを要求

この未知フィールド検査は、既知の `capability` 等の禁止語検査とは別のものです。Host/Child DTO の decoder は任意の未知 keyed field を拒否し、回帰テストで確認済みです。

## 実行結果

### 実行できた検証

- `swiftc -parse`（追加した3つのSwiftテストファイル）: pass
- `git diff --check`: pass
- `swift test --package-path native/macos --filter AgentPassNativeServiceTests --disable-sandbox`（module cacheを `/private/tmp` に指定）: 13 tests, 0 failures

最初の `swift test` は `/Users/torutano/.cache/clang/ModuleCache` の権限拒否で開始できませんでした。module cacheを `/private/tmp` に移した再実行では、対象のHost/Childテストをビルド・実行できました。

### 残る外部ゲート

今回のテストレーンで、peer drift revoke と unknown keyed field rejection は
local code/test boundaryまで確認済みです。実launchd/NSXPC、署名済みartifact、
Secure Enclave、Cloud/PostgreSQLは引き続き外部 qualification が必要です。

静的根拠は、`NativeAgentAuthenticatedHostEndpoint.signHostPayload` が
`try revalidatePeer()` の失敗を `closeSessionAndRevoke` へ渡さず reply error に変換する制御フローと、`AgentPassHostXPCContract` が既知の禁止キー集合だけを `containsValue(forKey:)` で検査している点です。

## 未検証の外部ゲート

- 実 `launchd` Mach service による Host → Child attach/sign/revoke
- NSXPCの実response-loss、connection invalidation、process death、PID reuse
- raw audit-token provenance と実コード署名要件
- Developer ID署名、notarization、staple、Apple Silicon / Intel実機
- Secure Enclave / TPM signer、実PostgreSQL、Cloud signer/KMS
- Claude Code / Cursor のクリーンマシンE2E

このドキュメントはテストレーンの証跡であり、focused testがproduction readinessを証明するものではありません。
