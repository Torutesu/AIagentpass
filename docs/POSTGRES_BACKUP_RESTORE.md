# PostgreSQL backup／restore verification

バックアップの復旧判定は、サービスが起動することだけでは完了しない。隔離した復旧先で、元のPostgreSQLバックアップとauthority stateが同じ時点・同じtenant scopeであることを、`scripts/postgres/authority-manifest.mjs` の正規化manifestで検証する。

## Manifestが証明する範囲

Manifest schema v2 は、固定された次の全テーブルを対象にする。

- control plane: `organizations`, `members`, `memberships`, `devices`, `device_enrollments`, `agents`, `policies`, `revocations`, `capabilities`
- bundle／audit／outbox: `bundle_heads`, `bundle_acknowledgements`, `admin_audit_heads`, `admin_audit_events`, `outbox_events`, `device_audit_events`, `device_audit_heads`, `device_audit_gaps`
- human auth: `human_sessions`, `webauthn_credentials`, `webauthn_challenges`, `upstream_identities`, `human_identity_assertion_replays`
- security／operations: `organization_invitations`, `idempotency_records`, `device_request_nonces`, `rate_limit_buckets`, `schema_migration_attempts`

各テーブルについて、選択scopeに属する全行を同一の`REPEATABLE READ READ ONLY`トランザクションで読み、全列とJSONの全階層をSHA-256のrow digestへ取り込む。manifestには行の値、秘密、nonce、token、credential、cookie、private key、signature、`event_json`、`redacted_json`、payload、idempotency responseは出力しない。秘密らしいフィールドは値を別のSHA-256 digestへ置換してからrow digestを計算するため、値を公開せず改変を検知できる。

Manifest自体には、tenant scope、migration versionと各 migration checksum、全行数、列集合のdigest、各row digest、全constraintの名前・種別・定義digest・`validated`状態を含める。行数とrow digest数は必ず一致し、migrationはローカルのreview済み`contracts/postgres/*.sql`とversion／checksumが一致しなければ失敗する。`pg_constraint.convalidated=false`、未完了migration attempt、未知のmanifest field、nested unknown／secret-like fieldはfail-closedで拒否する。

作成時には、同一tenant内のmembership、device、agent、capability、audit、outbox、human-authの参照関係を検査する。revocationは`organization`、`device`、`agent`、`capability`のpolymorphic targetを実体と同じtenantで検証し、organization targetにtarget idがある状態や他tenantのtargetを拒否する。

## 取得

接続文字列は引数に渡さず、TLSを有効にした環境変数から渡す。出力は一時ファイルへ書き、内容をfsyncしてから同じdirectoryへatomicに配置する。既存出力は上書きせず、入力manifest・signature・artifactはbounded regular fileとして開き、symlinkを拒否する。

```sh
export AGENTPASS_DATABASE_URL='postgresql://...?...sslmode=verify-full'
node scripts/postgres/authority-manifest.mjs snapshot /secure/backup/authority-before.json
```

tenantを限定する場合は明示する。順序は正規化される。

```sh
node scripts/postgres/authority-manifest.mjs snapshot /secure/backup/org-a.json \
  --tenant=11111111-1111-4111-8111-111111111111
```

PostgreSQLバックアップ artifactとmanifestを暗号学的にbindする場合は、manifest作成時にartifactを指定する。artifact digestは同じmanifest hashに含まれる。

```sh
node scripts/postgres/authority-manifest.mjs snapshot /secure/backup/authority-before.json \
  --artifact=/secure/backup/base.dump
```

成功時のstdoutはhash（および指定時のartifact digest）だけを含む。

## detached signatureとartifactの検証

署名はこのツールが生成・保管・鍵管理するものではない。承認済みの外部署名者が作成したmanifestのcanonical UTF-8 bytes（末尾newlineを含む）に対するdetached signatureを、署名ファイルとして安全な領域から渡す。検証鍵は、inline secretをコマンドラインへ出さないため、次のどちらか一つをsecure environmentまたはregular file interfaceで供給する。

```sh
export AGENTPASS_MANIFEST_PUBLIC_KEY_FILE=/secure/keys/authority-manifest-public.pem
node scripts/postgres/authority-manifest.mjs verify \
  /secure/backup/authority-before.json \
  --signature-file=/secure/backup/authority-before.json.sig \
  --artifact=/secure/backup/base.dump
```

または、secret managerがプロセス環境へ注入する場合だけ次を使う。

```sh
export AGENTPASS_MANIFEST_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----...'
```

`verify`はmanifest hash、detached signature、artifact digest bindingをすべて確認する。artifact digestを持つmanifestにartifactを渡さない場合も成功扱いにしない。署名方式、鍵の生成、rotation、保管は既存の承認済みkey-management systemに委ねる。

## リストア比較

1. リストア先を通常のCloud APIから切り離し、migrationを適用・検証する。authorityを発行するプロセスは起動しない。
2. リストア先の接続文字列を`AGENTPASS_DATABASE_URL`に設定し、元と同じtenant scopeでmanifestを取得する。
3. 元artifactと復旧artifactをそれぞれdetached signature／artifact digestで検証する。
4. 正規化manifestを比較する。

```sh
export AGENTPASS_DATABASE_URL='postgresql://...?...sslmode=verify-full'
node scripts/postgres/authority-manifest.mjs snapshot /secure/restore/authority-after.json \
  --artifact=/secure/restore/base.dump
node scripts/postgres/authority-manifest.mjs compare \
  /secure/backup/authority-before.json \
  /secure/restore/authority-after.json \
  --left-signature-file=/secure/backup/authority-before.json.sig \
  --right-signature-file=/secure/restore/authority-after.json.sig \
  --left-artifact=/secure/backup/base.dump \
  --right-artifact=/secure/restore/base.dump
```

比較はmanifestを再正規化してから行う。tenant scopeが違えば`TENANT_MISMATCH`、署名・schema・hash・未知fieldが不正なら`INVALID_FILE`またはsignature／artifact diagnostic、正当なauthority state差分なら`MISMATCH`になる。差分値、tenant ID、row value、DB error、接続文字列、秘密は診断出力に含めない。成功のJSONは次の形である。

```json
{"same":true,"diagnostic":null}
```

`same:false`、非0終了、manifest欠落、scope不一致、checksum drift、constraint未検証、artifact／signature不一致のいずれかがあれば、Cloud API、Console、refresh／ACK配信を再接続せず復旧DBを本番authorityとして公開しない。

## 証跡

バックアップ世代ごとに、値そのものではなく次の証跡をアクセス制御された運用領域へ保存する。

```text
backup artifact digest
authority-before.json manifest_hash
authority-after.json manifest_hash
detached signature verification result
compare result
schema migration versions and checksums
constraint validation result
operator / UTC timestamp
```

manifestにはID、hash、sequence、状態が含まれるため一般公開しない。比較成功後も、段階的なreadiness、監査ログ、replay／nonce拒否、outbox状態を確認する。復旧DBを手動更新してmanifestを一致させてはならない。

## 制約

- この検証は、バックアップ暗号化、KMS／HSMの鍵可用性、object storageの耐久性そのものを証明しない。
- 時点の違うmanifestは期限・失効・sessionなどが変化する。PITRの復旧境界を元manifestと一致させる。
- artifact digestはファイルの内容をbindするが、DB接続先やバックアップサービスのidentityを代替しない。
- detached signatureの鍵管理をこのmanifest toolやmanifest fileへ追加してはならない。
