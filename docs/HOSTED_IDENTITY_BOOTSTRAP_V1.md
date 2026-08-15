# Hosted identity and first-organization bootstrap v1

この文書と [hosted-identity-bootstrap-v1.contract.json](../contracts/hosted-identity-bootstrap-v1.contract.json) は、Hosted profile の初回ログイン経路を固定する契約です。これは実装済みの本番機能を意味せず、`contract_frozen_implementation_pending` の状態で、実装を開始するための authority boundary です。

## 採用する本番経路

Hosted の identity authority は GitHub OAuth と PostgreSQL です。ブラウザから GitHub subject、email、member、organization、role を受け取りません。

1. Console が `/api/auth/bootstrap/github/start` に移動する。
2. Server が state と PKCE を生成し、GitHub に redirect する。state と verifier は server 側にだけ保持する。
3. `/api/auth/bootstrap/github/callback` で state、PKCE、redirect URI、OAuth code を検証する。
4. Server が GitHub token endpoint と `/user` API を呼び、numeric user id だけを `provider=github` の subject として採用する。
5. `upstream_identities` と `members` を server authority で解決する。identity assertion、GitHub token、email、raw provider response は Console に返さない。
6. membership が一度もない member だけが、bootstrap session から first organization を作成できる。Organization と owner membership は同一の server transaction で作る。
7. Organization 作成後も通常の Human Session は発行せず、bootstrap WebAuthn registration を完了させる。
8. WebAuthn challenge を consume して credential を保存できた時点で、bootstrap cookie を rotate し、通常の `__Host-agentpass_session` と CSRF token を発行する。

既存の `agentpass-console-identity` は、署名検証された別の Console identity adapter です。Hosted の初回 identity authorityとしてChatGPTのambient identityに依存することはありません。既存の Human Session、Organization service、WebAuthn verifier のデータモデル／検証規則を再利用しますが、Organization に束縛される現行 Human Session APIへ直接 bypass を追加しません。

## 既存ユーザーと membership の扱い

- active membership がある既存ユーザーは、新しい Organization を作りません。PostgreSQL から既存 membership を解決し、credential の有無に応じて通常 session または WebAuthn registration／step-up に進みます。
- member は存在するが membership 行が一件もない場合だけ、first-organization bootstrap が可能です。`organization_id` はリクエストに含めません。
- revoked membership の履歴がある場合は「membership がない」とは扱いません。新規 owner 化を防ぎ、招待または既存 recovery boundary を要求します。
- 複数 organization の選択は、caller が `organization_id` を指定することで行いません。server が membership を列挙し、後続の organization-bound session で選択します。
- first membership の role は常に server が `owner` として付与します。caller の `role`、`member_id`、`membership_id` は拒否します。

## Cookie、CSRF、Origin

| Cookie | 用途 | 属性 |
| --- | --- | --- |
| `__Host-agentpass_github_state` | OAuth state の一回限りの選択子 | HttpOnly / Secure / SameSite=Lax / Path=/ / 最大600秒 |
| `__Host-agentpass_bootstrap` | 短命な bootstrap attempt の opaque bearer | HttpOnly / Secure / SameSite=Strict / Path=/ / 最大900秒 |
| `__Host-agentpass_session` | WebAuthn gate 後の通常 Human Session | HttpOnly / Secure / SameSite=Strict / Path=/ |

Bootstrap の state-changing request は、設定済みの HTTPS Console origin と `agentpass-bootstrap-csrf` header を必須にします。CSRF token は status response で一度取得し、server では hash のみ保持します。`Authorization`、ChatGPT identity header、member／organization／role header は受け付けません。全 response は `no-store` です。

OAuth callback は GitHub からの redirect なので Origin header の有無を authority にしません。その代わり、one-use state、PKCE、exact redirect URI、code exchange、GitHub `/user` の server-side 検証を全て必須にします。

## One-time と idempotency

OAuth state と WebAuthn challenge は一回限りです。bootstrap session は一回の onboarding attempt にだけ使え、完了時に rotate／expire します。

Organization 作成には `Idempotency-Key`（`[A-Za-z0-9._~-]` の8–255文字）を要求します。key は verified member と operation に束縛します。

- 同じ key と同じ name は元の public organization response を返し、二重作成しません。
- 同じ key と異なる name は `409 bootstrap_idempotency_conflict` です。
- 同時実行や response loss の retry は一つの Organization と一つの owner membership に収束します。
- 作成後に別 key で再度 first organization を作ることは `409 bootstrap_already_completed` です。

## WebAuthn と recovery の境界

初回 credential が保存されるまで、通常の privileged Human Session を発行しません。registration は user verification required、設定済み rp_id／HTTPS origin、bootstrap attempt、server-derived member／organization、one-use challenge に束縛します。

その後の WebAuthn は、既存契約どおり subsequent authentication、credential追加、operation-bound step-up に利用できます。role変更、credential revoke、recoveryなどの敏感な操作には既存の recent-auth 契約を適用します。

bootstrap cookie を失った場合は GitHub OAuth を最初からやり直します。GitHub emailだけの復旧、ChatGPTだけの復旧、supportが送る member／organization／role header はありません。初回 onboarding 後は既存の owner recovery flow を使いますが、recovery が新しい first organization や role を自動付与することはありません。

## Migration と互換性

新規の canonical identity mapping は `upstream_identities(provider=github, subject)` です。`members.github_subject` は既存データの互換列として保持し、新しい caller input や再割当ての根拠にはしません。共有されている `0056_identity_epoch_invalidation` のidentity invalidation境界を前提に、過去の migration は変更しません。`0057_hosted_identity_bootstrap` がbootstrap attempt、one-use OAuth state、bootstrap idempotency、bootstrap WebAuthn bindingを追加し、`0058_hosted_oauth_pkce_envelope` がstate hashのexact照合と、attempt/state/redirect/expiryへAEAD束縛された短命PKCE verifier暗号文を追加します。`0059_hosted_identity_atomic_completion` は検証済みsubject単位で初回解決を直列化し、immutable mapping、member作成、membership履歴分類、OAuth消費、bootstrap cookie rotationを同一トランザクションにします。Hosted runtimeは0058/0059のv2関数だけを使用し、旧0057 start/consume/complete関数のEXECUTE権限を持ちません。

v1 の request は unknown field を拒否し、既存の legacy route をこの route に alias しません。authority や recovery の意味を変える場合は v2 と新しい contract id が必要です。

## 検証

```sh
npm run contracts:validate:hosted-identity-bootstrap
node --test test/hosted-identity-bootstrap-contract.test.mjs
```

validator は route inventory、GitHub/PostgreSQL authority、caller authority field の拒否、cookie／CSRF／Origin、idempotency、membership state、recovery、migration/version policy、既存データモデル参照を検査します。

実装順序、トランザクション境界、並列レーン、テスト行列、リリース判定は
[Hosted v1 implementation plan](./HOSTED_IMPLEMENTATION_PLAN_2026-08-15.md) を参照してください。
