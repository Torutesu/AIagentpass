# Host/Child XPC adversarial test lane

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

### Review finding kept out of the runnable suite

- peer process drift の後に Child registration が revoke されるべきだが、現行の
  `NativeAgentAuthenticatedHostEndpoint.signHostPayload` は `revalidatePeer()` の
  失敗を reply error に変換して return するため、`closeSessionAndRevoke` に到達しない。
  これは現行コードでは fail する回帰期待であり、passするテストとしては誤解を招くため、
  runnable testからは除外した。production sourceを変更しない制約のため、未修正の
  security findingとして記録する。

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

この未知フィールド検査は、既知の `capability` 等の禁止語検査とは別のものです。現在の decoder は既知の禁止キーを拒否する一方、任意の未知キーを拒否する allow-list にはなっていないため、現状では回帰テストが fail することを想定しています。

## 実行結果

### 実行できた検証

- `swiftc -parse`（追加した3つのSwiftテストファイル）: pass
- `git diff --check`: pass
- `swift test --package-path native/macos --filter AgentPassNativeServiceTests --disable-sandbox`（module cacheを `/private/tmp` に指定）: 13 tests, 0 failures

最初の `swift test` は `/Users/torutano/.cache/clang/ModuleCache` の権限拒否で開始できませんでした。module cacheを `/private/tmp` に移した再実行では、対象のHost/Childテストをビルド・実行できました。

### まだfailする想定のnegative test

現行production codeの安全性欠落を確認するため、次の検査は別レーンにあり、passすることを期待していません。

1. peer revalidation failure時の `closeSessionAndRevoke` 未到達
2. unknown keyed field の黙示的受理

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
