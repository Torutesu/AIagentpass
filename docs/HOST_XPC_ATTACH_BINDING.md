# Host XPC attach binding audit

監査日: 2026-08-19
対象: `/Users/torutano/Documents/ChatGPT/AIagentpass/work/agentpass-c3`
範囲: `NativeAgentHostChildSupervisor` から専用 Host XPC attach へ渡る child identity、ancestry、PID version、worktree digest、および attach 後の cleanup。
方法: 読み取り専用の静的追跡。実装コード、既存テスト、protected path は変更していない。監査中に別作業の未コミット差分が出現したため、`HEAD` と current working tree の判定を分けている。

## 判定

canonical codec と Service 側の比較は一致している。`HEAD` には `NativeAgentHostChildSupervisor` が child の identity/ancestry/worktree digest を計算して `NativeAgentAuthenticatedHostXPCClient.attach` を呼ぶ実配線がない。current working treeではこの配線を追加し、compile blockerを修正したうえでSupervisorの43件のtargeted testが通過している。ただし実launchd/実Macの `Supervisor spawn → attach → registry → Child sign` は未検証であり、production-readyとは判定しない。

さらに、Host sessionのterminal transitionとChild registry revokeは同一endpoint lock内へ収束させる必要があり、今回その実装を追加した。実Macでのresponse-lossとregistry revoke証跡は未取得である。

## 1. canonical representation と digest

### Process identity

`NativeProcessIdentity.canonicalRepresentation` は次の固定構造である (`native/macos/Sources/AgentPassNativeCore/NativeProcessIdentity.swift:210-228`):

```text
{
  "ancestry": [ordered entries from immediate parent outward],
  "process": {process facts},
  "version": "native_process_identity/v1"
}
```

実際の bytes はキーを UTF-8 lexical order でソートした JSON、空白なし、UTF-8 である。process facts には `uid`、`pid`、`pid_version`、boot identity、executable `(device_id,inode,file_size,modification_time_ns)`、CodeDirectory hash、bundle/team、signature kind、canonicalized entitlements が入る (`native/macos/Sources/AgentPassNativeCore/NativeProcessIdentity.swift:499-560`)。`canonicalBindingHash` はその UTF-8 bytes の SHA-256 hex、`canonicalAncestryBindingHash` は ancestry array だけの同じ形式の SHA-256 hex である。

Service の `NativeAgentConnectionGuard` は同じ `NativeProcessIdentity` の二つの hash を公開し (`native/macos/Sources/AgentPassNativeCore/NativeAgentConnectionGuard.swift:17-29`)、Child registry も登録・再検証時に同じプロパティを直接使う (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:56-78,92-120`)。従って、Service 側 canonical binding との codec-level mismatch は確認できない。

### PID version

Attach DTO は `childPIDVersion: Int64` とし、1 以上かつ 2100 年境界以下に制限する (`native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift:17-22,247-269`)。Darwin observer は `proc_bsdinfo.pbi_start_tvsec/usec` を `seconds * 1_000_000 + microseconds` として `UInt64 pidVersion` にする (`native/macos/Sources/AgentPassNativeCore/NativeDarwinProcessObservationSource.swift:35-50,366-380`)。

Attach 時は Service が request の PID で独立観測し、その観測 identity の `pid` と `pidVersion` を request と比較する (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:226-239`)。worktree observer も process snapshot を前後で比較するため、PID reuse/exec/chdir drift は fail closed になる (`native/macos/Sources/AgentPassNativeCore/NativeDarwinGitWorktreeObserver.swift:64-93`)。

この比較は安全側だが、`NativeAgentAuthenticatedHostListener` の `childFactory` は渡された expected PID version を `_` で捨て、PID だけで観測している (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostListener.swift:97-106`、実配線 `native/macos/Sources/AgentPassNativeService/main.swift:4987-4991`)。最終比較は endpoint に残るため bypass ではないが、実装契約として「observer 自身が expected PID version を検証する」構造にはなっていない。

### Worktree binding

Service の `NativeAgentWorktreeBinding` は v2 で、`AgentPass-Worktree-Binding-v2\0` と canonical JSON の SHA-256 を digest とする (`native/macos/Sources/AgentPassNativeCore/NativeAgentWorktreeBinding.swift:126-147,210-228`)。canonical input は layout、repository/git/common path、各 directory の device/inode/generation/owner/permissions、object format、HEAD、object/tree ID、sorted remotes である (`native/macos/Sources/AgentPassNativeCore/NativeAgentWorktreeBinding.swift:349-395`)。

専用 Host listener は `NativeDarwinGitWorktreeObserver` からこの digest を取得し、request digest と byte equality を比較する (`native/macos/Sources/AgentPassNativeService/main.swift:4967-4999`、`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:233-239`)。Child sign でも Service が再観測した digest と registry の登録値を比較する (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:108-120,197-213`)。ここも Service authority と比較形式は一致している。

## 2. Supervisor → attach の配線判定

`HEAD` の `NativeAgentHostChildSupervisor` の spawn spec/handle は executable、argv、environment、working-directory FD、process PID/PGID だけで、`NativeProcessIdentity`、PID version、ancestry hash、worktree digest を持たない (`native/macos/Sources/AgentPassNativeCore/NativeAgentHostChildSupervisor.swift:454-520`)。spawn 後も process handle を検証して session を返すだけで、identity/worktree observer または attach client 呼出しはない (`native/macos/Sources/AgentPassNativeCore/NativeAgentHostChildSupervisor.swift:744-851`)。

`NativeAgentAuthenticatedHostXPCClient.attach` は digest を caller supplied 引数として受け取るだけである (`native/macos/Sources/AgentPassNativeCore/NativeAgentAuthenticatedHostXPCClient.swift:123-152`)。この client を Supervisor/Lifecycle に接続する adapter は checkout から確認できない。実 Host executable も現在は `dev.agentpass.agent-session` に接続し、`AgentPassAgentXPCInterface` で旧 bootstrap/session API を使う (`native/macos/Sources/AgentPassNativeAgentHost/main.swift:254-266,294-320`)。専用 `dev.agentpass.agent-host` の endpoint/listener は Service 内に存在するが、通常 Host の実行経路へは収束していない。

current working tree の未コミット差分 `native/macos/Sources/AgentPassNativeCore/NativeAgentHostAuthenticatedLifecycleSupport.swift` と `NativeAgentHostChildSupervisor.swift` は、authenticated XPC の prepare を spawn 前、独立 child observation と digest decode/attach を spawn 後、failure 時の child terminate/reap と client close を追加している (`NativeAgentHostChildSupervisor.swift:794-912`, `NativeAgentHostAuthenticatedLifecycleSupport.swift:44-131`)。identity hash は既存の canonical hexを32-byteへ decodeしており、printable hexを再ハッシュしていないため、Service の `canonicalBindingHash` / `canonicalAncestryBindingHash` と表現上は一致する。worktree digest も同じ `NativeDarwinGitWorktreeObserver` の v2 digestを渡す。

current working treeの実装はcompile・targeted test済みだが、外部ゲートは未達である。

- `NativeAgentHostChildSupervisor.swift` のPID version変換とcanonical digest decodeは現在コンパイル・targeted testで検証済みである。`NativeAgentHostAuthenticatedXPCSupervisorFixture` はclient/observer factoryへ注入され、Supervisorからprepare/observe/attachが実際に呼ばれる。
- request digest はauthorityではなくService観測との比較用 hintであるため、Supervisor側の観測は一致しない場合にattachをfail closedにするための値であり、Service observerを最終authorityとする設計は維持すべきである。

## 3. cleanup の所見

### 有効な cleanup

- attach の child observation failure または digest mismatch では Core session を close する (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:226-239`)。
- 明示 `closeHostSession` と NSXPC invalidation では `unregisterRegisteredChild()` まで実行する (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostEndpoint.swift:344-380`)。
- Child registry は identity、ancestry、PID version、worktree drift、replay、budget failure で entry を閉じる (`native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedChildGitEndpoint.swift:92-173`)。

### 修正済み（外部検証待ち） — terminal session close と Child registry revoke

attach 成功後の全terminal transitionは `closeSessionAndRevoke` に収束するよう修正した。signer failure/invalid response、expiry、peer/process drift、明示close、XPC invalidationで `session.close()` と `unregisterRegisteredChild()` が同じendpoint lock内で実行される。

Child registryのsessionID照合強化と、response-loss後の実Mac revoke証跡は引き続き外部検証ゲートである。local endpoint unit coverageに、signer failure/expiry/invalidation時のunregister確認を追加する必要がある。

## 4. 実Mac検証ゲート

focused/unit test は canonical codec や injected observer の契約確認に限定し、実Mac gate の代替にしない。今回の checkout では `swift test` も試行したが、sandbox が `/Users/torutano/.cache/clang/ModuleCache` と SwiftPM manifest sandbox を拒否したため実行不能だった。この結果はコードの green/red ではない。

release 判定には、少なくとも次を同一 signed artifact で記録する。

1. Developer ID 署名・notarization・staple 済みの Host、Child helper、Service を launchd Mach service (`dev.agentpass.agent-host` / `dev.agentpass.child-git`) として起動する。
2. 実 child spawn の直後に、Supervisor が保持する PID/PID version と Service の独立 observation を比較し、canonical process hash と ordered ancestry hash の redacted digest vector が一致することを採取する。
3. worktree の embedded/linked layout、HEAD branch/detached、commit/tree、directory inode/generation、remote drift を含む v2 digest vector を、Supervisor hint・Service attach observation・Child sign-time re-observation の三地点で比較する。raw path、token、credential は証跡に出さない。
4. PID reuse、exec replacement、parent death、ancestor substitution、unknown ancestor、cwd/worktree swap、HEAD/tree/remote change、attach request digest substitution を negative test し、attach または signer invocation が必ず deny/close/revoke になることを確認する。
5. attach 後の Host signer failure、malformed/ lost response、expiry、peer drift、Host connection invalidation、Child connection invalidation、SIGTERM を実行し、registry entry、session、child process、FD が全て terminal cleanup に収束することを確認する。
6. Apple Silicon と Intel/T2 の実機で、real launchd、privileged XPC、Developer ID requirement、Secure Enclave signer、reboot/sleep-wake を別証跡として取得する。focused Core test、匿名 XPC harness、listener が `resume()` した事実だけでは gate を満たさない。

## 5. 結論の境界

現在確認できるのは次の範囲である。

- `NativeProcessIdentity` の canonical bytes/hash と Service の attach/registry 比較は同一実装を共有している。
- worktree v2 digest も Service の観測・attach compare・Child sign-time compare で同一 digest を使う。
- current working treeではSupervisorから専用attach clientへidentity/ancestry/worktreeを渡すpathが実装され、43件のtargeted testが通過している。
- terminal failureのregistry revoke routineは実装済みだが、実XPC response-loss・expiry・signer failureの端到達証跡は未取得である。
- 実Mac/launchd/signed artifact/Secure Enclave の検証証跡は今回取得していない。
