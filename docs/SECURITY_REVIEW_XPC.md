# Security review: dedicated Host/Child XPC identity boundary

判定: `not_proven`。これは checkout の静的読み取りによる repository-side review
record であり、実際の第三者レビューを実施・完了したという主張ではない。実機・
protected runner・署名付き reviewer identity の証跡が揃うまで、focused finding
やテスト結果を production approval に昇格させない。

監査日: 2026-08-19  
対象: `/Users/torutano/Documents/ChatGPT/AIagentpass/work/agentpass-c3`  
範囲: 専用 `dev.agentpass.agent-host` / `dev.agentpass.child-git` listener の実配線、audit-token provenance、connection/launch nonce binding、Child code-signing requirement。  
方法: checkout の静的読み取り監査。実装コード、protected path、設定、コミットは変更していない。

## 結論

専用 listener の fail-closed adapter と Core の identity/replay state machine は存在する。しかし、現在の本番相当の Host lifecycle は専用 Host listener へ収束しておらず、実 audit token は Service adapter から取得されていない。さらに、Host の launch nonce は Host session 内だけで終わり、Child XPC connection の認証材料になっていない。Child listener の XPC admission requirement も、Child helper の実際の署名主体ではなく Host 用 requirement を再利用している。

したがって、現時点で「専用 Host/Child XPC による audit-token provenance、nonce-bound Child channel、Child-specific code-signing admission が本番で有効」とは判定できない。既存の process code identity、UID、PID version、ancestry、worktree digest、replay/budget checks は有効な追加防御だが、以下の未達を置き換えない。

## 所見一覧

| ID | 優先度 | 所見 | 本番影響 |
| --- | --- | --- | --- |
| XPC-P1-01 | P1 | Dedicated Host/Child XPC が end-to-end の実経路になっていない | 新 boundary の provenance/nonce/Child admission は通常の署名経路を保護しない |
| XPC-P1-02 | P1 | Host/Child listener が live audit token を provenance として取得・再検証していない | `tokenIdentity` は raw audit token の証拠ではなく、audit token field drift を検出できない |
| XPC-P2-01 | P2 | launch nonce が Child connection/session に結合されていない | 同じ process identity に依存した cross-session / stale-connection confusion を防げない |
| XPC-P2-02 | P2 | Child XPC の requirement が Child helper 用でなく Host requirement の再利用 | 実 Child helper は admission で拒否されるか、運用者が要件を弱める誘因になる |

## XPC-P1-01 — Dedicated Host/Child XPC が実経路になっていない

### Evidence

- Service は listener を生成して `resume()` している: `native/macos/Sources/AgentPassNativeService/main.swift:4852-4855, 5011-5020`。Mach service 名の launchd 定義も `native/macos/Resources/dev.agentpass.native-service.plist:11-16` にある。
- しかし専用 Host protocol の production caller は確認できない。実際の Host executable は `dev.agentpass.agent-session` に接続し、`AgentPassAgentXPCInterface` を使っている: `native/macos/Sources/AgentPassNativeAgentHost/main.swift:6-11, 254-266, 294-320`。
- Host endpoint の runtime methods は Service 内に存在するだけである: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:178-194, 215-258, 264-313`。Host protocol 自身も「runtime code may use ... when it is implemented」と記載している: `native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift:59-62`。
- Lifecycle の既定 transport は `legacyFD3`: `native/macos/Sources/AgentPassNativeCore/NativeAgentHostLifecycleCoordinator.swift:294-308`。Child launch request の既定値も同じ: `native/macos/Sources/AgentPassNativeCore/NativeAgentHostChildSupervisor.swift:389-414`。
- XPC helper は実装されているが、authenticated mode は明示指定時だけ使われる: `native/macos/Sources/AgentPassNativeCore/NativeAgentHostChildSupervisor.swift:744-769`、`native/macos/Sources/AgentPassNativeCore/NativeAgentGitSigningHelper.swift:74-94`。

### 判定と影響

専用 listener が起動していることは、専用 listener が署名を実際に承認している証拠ではない。現在の標準 Host は旧 Agent session API と FD3 bridge を使用するため、専用 Host/Child の audit-token、nonce、Child-specific requirement の保証は実署名フローに到達しない。`docs/NATIVE_HOST_XPC.md:25-29` 自身も FD3 が migration blocker であること、real audit-token extraction/Developer ID/notarization/launchd を未証明としている。

### 修正案

1. Host executable の実クライアントを `dev.agentpass.agent-host` に切り替え、`AgentPassHostXPCInterface` で `prepare -> attach -> sign -> status/close` を実行する。
2. `NativeAgentHostLifecycleCoordinator` の production construction で `authenticatedXPC` を明示固定し、`legacyFD3` を通常経路から除外する。移行用 fallback を残す場合は明示的な開発/移行フラグに限定し、readiness を fail closed にする。
3. Host attach の成功、Child spawn、Child helper の `dev.agentpass.child-git` 接続、署名応答までを一つの実行経路として配線し、専用 path を通らない署名を release gate で拒否する。

### 本番検証ゲート

- Developer ID で署名・notarize・staple した実 artifact を install し、launchd の三つの Mach service に対して実 Host/Child round trip を行う。
- `dev.agentpass.agent-session`/FD3 経路では署名できず、`dev.agentpass.agent-host` -> `dev.agentpass.child-git` のみが署名できることを negative test で確認する。
- 実 child process の spawn、PID reuse/exec、connection invalidation、signer failure、timeout、response loss を含め、全てが close/revoke に収束することを確認する。
- Apple Silicon と Intel/T2 の実機、privileged XPC、Secure Enclave、Developer ID/notarization を別々の証跡として保存する。focused Core test の green はこの gate の代替にしない。

## XPC-P1-02 — live audit-token provenance が未達

### Evidence

- Host listener の admission/context は `processIdentifier`、`effectiveUserIdentifier`、`auditSessionIdentifier` と別途 PID observation を使うだけで、`connection.auditToken` または `audit_token_t` の抽出を行っていない: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostListener.swift:61-73`。
- Default `contextFactory` と protected-operation 時の再観測は、`NativeConnectionContext(osProcessID:effectiveUserID:auditSessionID:pidVersion:)` を呼ぶ: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostListener.swift:32-38, 85-92`。
- この initializer は raw token からの digest ではなく、固定 domain と PID/UID/audit-session/PID-version の合成値を `tokenIdentity` として作る: `native/macos/Sources/AgentPassNativeCore/NativeConnectionContext.swift:282-304`。auid、egid、ruid、rgid など audit token の残りの field は入っていない。
- Core には厳密な8-field adapter がある: `native/macos/Sources/AgentPassNativeCore/NativeConnectionContext.swift:21-29, 46-77`。しかし `NativeProcessObservationSource` は live XPC audit token の extraction/validation を意図的に claim していない: `native/macos/Sources/AgentPassNativeCore/NativeProcessIdentity.swift:149-154`。
- Child listener も UID/PID の admission と PID-based process observation のみである: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:265-285`。Child connection の audit-token context は作られていない。

### 判定と影響

現在の `tokenIdentity` は名称に反して complete audit-token provenance ではない。PID observation と code-signing/process policy が補助するため即時の UID-only bypass とは判定しないが、live connection の audit token を root of trust として capture/revalidate した証拠がなく、非PID field の token drift や peer provenance を audit boundary として否定できない。`NativeConnectionContextTests` の `:140-155` は synthetic initializer をテストしており、実 NSXPC token extraction の証拠ではない。

### 修正案

1. Service target に専用の OS adapter を追加し、connection accept 時と各 protected operation 直前に live `audit_token_t` を取得する。SDK surface が不足する場合は ObjC/C bridge で `audit_token_t.val[0...7]` を strict adapter に渡し、取得不能なら拒否する。
2. `NativeAuditTokenFieldAdapter` -> `NativeConnectionContext(capturing:)` を production path にし、token の PID/euid/pidversion と `NativeDarwinProcessObservationSource` の observation を同一 peer として一致検証する。request DTO、argv、environment、PID hint は authority にしない。
3. Host と Child の両 listener で同じ provenance contract を使い、accept-time token と operation-time token の全 field digest mismatch を terminal denial にする。

### 本番検証ゲート

- 実 launchd Mach service の Host/Child connection から取得した audit token の全8 field を、redacted digest と process observation に結合した証跡を採取する。
- 同一 UID の別 executable、別 Team ID、別 entitlement、exec、PID reuse、audit-session/token-field drift を実 connection で試し、accept または sign が必ず拒否されることを確認する。
- raw token をログ・DTO・永続化しないこと、strict eight-field vector test と real macOS adapter test が一致することを独立レビューする。

## XPC-P2-01 — launch nonce が Child connection に結合されていない

### Evidence

- `AgentPassHostPrepareRequest` は `launchNonce` を受け取るが、nonce は prepare request にだけ存在する: `native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift:125-165`。
- Host endpoint は nonce の digest を session 内に保存するだけである: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:188-200`、`native/macos/Sources/AgentPassNativeCore/NativeAgentAuthenticatedGitBridge.swift:335-344`。
- `AgentPassHostAttachChildRequest` に nonce/session proof はない: `native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift:234-311`。Child sign DTO も protocol version、sequence、payload だけである: `native/macos/Sources/AgentPassNativeCore/AgentChildGitXPCProtocol.swift:18-75`。
- Registry は `sessionID` を Entry に保存するものの、lookup は `identity.canonicalBindingHash` のみで、sign request の session/nonce を検証しない: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:37-83, 92-149`。
- One-shot Child client は新しい connection を作るが nonce/session credential を送信しない: `native/macos/Sources/AgentPassNativeCore/NativeAgentChildGitXPCClient.swift:24-60`。

### 判定と影響

launch nonce は「この Host connection が開始したこの Child channel」を証明していない。現在は process identity、PID version、ancestry、worktree digest、one-shot connection、replay/budget がリスクを狭めるため P2 とするが、同一 identity の stale child または別 session と channel が混線しないことを nonce だけでは保証できない。

### 修正案

1. Service が per-connection random nonce を生成し、Host session にのみ保持する。caller-supplied launch nonce を残す場合も、service nonce と二重に結合し、単なる request field の再利用にしない。
2. attach 成功時に session、nonce digest、child process binding、PID version、ancestry、worktree、expiry、request sequence を含む one-shot child attach ticket を memory-only で発行する。
3. Child XPC の最初の request に ticket/proof を持たせ、Service が connection の live provenance と registry entry に対して検証する。ticket は session close、connection invalidation、signer failure、expiry、response-loss reconciliation で即時無効化する。raw nonce を argv/environment/log に置かない。

### 本番検証ゲート

- 同じ signed child identity で二つの Host session を並行作成し、Session A の ticket を Session B/別 Child connection で使えないことを確認する。
- ticket replay、close後 replay、connection再接続、PID reuse、worktree交換、request sequence skip、sign response loss を実 Mach service で試す。
- process identity が一致しても nonce/session/ticket が違えば signer invocation が発生しないことを監査ログと signer spy/hardware evidence の両方で確認する。

## XPC-P2-02 — Child-specific code-signing requirement が未達

### Evidence

- `host_child_code_directory_hash` は optional で、example configuration は `null`: `native/macos/Sources/AgentPassNativeService/main.swift:451-455`、`native/macos/Resources/native-service.example.json:64-70`。null の場合 Host listener は fail closed する: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostListener.swift:75-79`。これは安全側だが、usable production configuration ではない。
- Hash が設定された場合の `hostChildPolicy` は UID、CodeDirectory hash、署名種別、ad-hoc拒否、ancestor unknown拒否だけで、Child bundle ID/team/required entitlement を固定していない: `native/macos/Sources/AgentPassNativeService/main.swift:4945-4952`。
- Child listener の `setCodeSigningRequirement` には `agentClientCodeSigningRequirement` が渡される: `native/macos/Sources/AgentPassNativeService/main.swift:5005-5009`、実際にそれを connection admission に適用する: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:265-269`。
- その requirement は Host principal `dev.agentpass.agent-host` と `dev.agentpass.agent-session-client` entitlement を要求する: `native/macos/Resources/native-service.example.json:69`、`native/macos/Sources/AgentPassNativeCore/NativeAgentCodeRequirement.swift:7-15`。
- 一方、authenticated Child helper は別 executable `dev.agentpass.git-sign-xpc` として署名される: `native/macos/scripts/build-app.sh:223-228, 267-275`。helper source は Child Mach service に接続するだけで、Host entitlement を付与する配線はない: `native/macos/Sources/AgentPassGitSigningXPCHelper/main.swift:9-15`。

### 判定と影響

Child listener の admission requirement は Child executable の fixed identity ではない。実 artifact では `dev.agentpass.git-sign-xpc` が Host requirement に一致せず、authenticated XPC mode が admission 前に拒否される可能性が高い。逆に動かすため requirement を緩めると、Child-specific signer admission が後退する。Host attach 側の optional hash policy は有用な second check だが、NSXPC connection の code-signing requirement の代替ではない。

### 修正案

1. Host 用 requirement と Child helper 用 requirement を分離する。Child 用は実際の fixed bundle/identifier、同一 Team ID、Developer ID chain、dedicated Child entitlement、必要なら immutable `cdhash` を明示する。
2. `NativeAgentAuthenticatedChildGitListenerDelegate` には Child-specific requirement を渡し、`agentClientCodeSigningRequirement` を再利用しない。
3. `hostChildPolicy` も bundle ID、Team ID、dedicated entitlement、expected ancestry を必須にし、authenticated XPC production mode では hash を mandatory にする。hash は XPC request/config caller からではなく、独立検証済み signed/notarized artifact から provision する。
4. `build-app.sh` で Child helper の entitlement を明示的に署名し、signed requirement evaluation と artifact identity manifest を生成する。

### 本番検証ゲート

- 実 install artifact について `codesign --verify --strict`、`codesign -dv --verbose=4`、signed entitlements、designated requirement evaluation、notarization/staple を記録する。
- 正規の `dev.agentpass.git-sign-xpc` だけが `dev.agentpass.child-git` に接続でき、Host app、management client、ad-hoc/別 Team/別 cdhash/別 entitlement は拒否されることを実 launchd で確認する。
- Child helper の hash、bundle/team/entitlement、ancestry の各一つを変更した negative test と、Host attach policy と Child listener admission の両方が deny する evidence を保存する。

## 既存実装で確認できた有効な防御

- Host endpoint は connection ごとに state を持ち、protected operation 前に peer context/process を再検証する: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:98-115, 264-297`。
- Child attach は independently observed process/worktree と request hint を比較し、registry は PID version、process/ancestry binding、worktree、sequence、payload replay、2回 budget を確認する: `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:226-248`、`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:92-149`。
- `NativeConnectionContext` の strict eight-field audit-token adapter、Core の code identity policy、XPC DTO の secret/authority field rejection は実装済みである。ただし、これらを real Service/launchd adapter と production Child identity に接続することが今回の未達である。

## 検証状況と判定境界

今回は読み取り監査のみで、テスト・外部 launchd・実機・notarization・Secure Enclave は実行していない。匿名 NSXPC harness は launchd privileged Mach-service、code-signing requirement、Secure Enclave を意図的に対象外としている: `native/macos/Tests/AgentPassNativeCoreTests/NativeXPCIntegrationHarnessTests.swift:20-40`。authenticatedXPC の unit test も injected supervisor hooks で FD3 handoff が無いことを確認するだけである: `native/macos/Tests/AgentPassNativeCoreTests/NativeAgentHostLifecycleCoordinatorTests.swift:324-340`。

従って本メモの判定は「focused/unit contract が存在しない」ではなく、「専用 XPC の実 audit-token provenance、nonce-bound Child connection、Child-specific signed admission、production end-to-end wiring が checkout 上のコードからは証明できない」である。上記の本番検証ゲートを満たすまで、専用 Host/Child XPC を production security boundary として完了扱いにしない。
