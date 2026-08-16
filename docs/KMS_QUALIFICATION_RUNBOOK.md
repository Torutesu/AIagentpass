# Hosted KMS qualification evidence runbook

このrunbookは、S2/W5のAWS/GCP KMS qualification結果を、実行環境とは独立した
verifierでproduction gate判定するための手順です。ここにあるコードはAWS/GCPへ接続
せず、providerの実行結果を安全なdigest参照として受け取ります。

## このlaneが受け付ける証拠

レポートは `contracts/schemas/kms-qualification-evidence-v1.schema.json` と
`scripts/kms-qualification/schema.mjs` の両方に適合しなければなりません。

- signer-purpose registryの8 purposeを、欠落・重複なく1回ずつ含む
- providerは `aws` または `gcp` のみ
- 各purposeにimmutable key resource、key version、public-key fingerprint、
  HSM、non-exportable、sign/verify結果を含む
- 8×8のcross-purpose IAM allow/deny matrixを含む。同一purposeだけallowで、
  他の63組はdenyでなければならない
- 各purposeについてrotation、disable、outage、throttle、response-lossの
  5シナリオを含む。response-lossは再署名なしのreconcileを証明する
- 2 instanceそれぞれのsource commit、image digest、config digestと、
  PostgreSQLのmigration head・managed signer operation bindingを含む
- すべての観測時刻はmillisecond RFC 3339 UTCで、skip countはproductionで0
- providerのraw response、stdout/stderr、diagnostic、credential、token、
  private key、自由記述のエラーメッセージはレポートに含めない

レポートの`report_digest`は署名欄を除いたcanonical JSONのSHA-256です。
署名者は`signatureInputBytes()`が返すcanonical inputを、固定domainと
`report_digest`に対して署名します。公開鍵DERと署名だけをレポートに埋め込み、
private keyは決してレポートやコマンド引数へ渡しません。レポート内の公開鍵は
自己申告値にすぎないため、verifierは必ず別経路で固定・配布された同一公開鍵DERと
key idを要求します。

## 実行結果の取り込み

AWSまたはGCPの保護されたqualification runnerは、provider SDKの生レスポンスを
保存・出力せず、runner内で次だけを判定します。

1. purposeごとの固定resource/versionへ要求を送る
2. HSM/non-exportability、公開鍵、sign/verifyを確認し、証拠ファイルのdigestだけを記録する
3. 同一purposeのsignをallow、他purposeのsignをdenyとしてIAM matrixを完成する
4. rotation、disable、outage、throttle、response-lossを実行し、各シナリオの
   期待状態と観測状態をenumで記録する
5. 同一commit/image/configの2 instanceを、PostgreSQLの
   `managed_signer_provider_operations`に対して競合実行する
6. redacted input JSONを生成する。raw provider outputやcredentialをinputへ入れない

### provider-independent runner core

このリポジトリには、provider SDKをimportしない固定件数runnerもあります。
`scripts/kms-qualification/runner.mjs`の`runKmsQualification()`へ、保護されたAWS/GCP
orchestrationを次の3操作として注入します。

- `describePurpose({ name, purpose, registry_version, protocol_version, signing_version, algorithm }, { signal })`
  は、`key_id`、`key_resource`、`key_version`、`lifecycle_epoch`、公開鍵fingerprintと、
  HSM/non-exportableの証拠digestだけを返す
- `signAndVerify({ purpose binding, request_bytes, request_digest }, { signal })`は、
  署名と検証をprovider側で完了し、`status`、`verified`、署名digest、証拠digest、
  観測時刻だけを返す。署名bytes、公開鍵、provider receiptは返さない
- `checkIam({ requester, target, action: "sign", expected, request_bytes, request_digest }, { signal })`
  は、allow/deny、status、証拠digest、観測時刻だけを返す

runnerはrequest digestを自分で生成し、purposeのsign/verifyを8回、ordered IAM probeを
64回だけ実行します。runner自身のretryはなく、同時実行数は最大8、各呼び出しには最大30秒の
deadlineがあります。戻り値は`purpose_bindings`と`iam_matrix`のredacted primitivesなので、
次のようにreport inputへ合成します。

```js
const probes = await runKmsQualification({ provider, operations });
const reportInput = {
  ...otherQualificationInputs,
  purpose_bindings: probes.purpose_bindings,
  iam_matrix: probes.iam_matrix
};
```

`validateKmsQualificationRunnerResult()`は、runnerから保管・転送するhandoffを再検証します。
unknown field、accessor、raw/response/result/output、credential、token、private key、
diagnostic、stdout/stderr、自由記述エラーを含む値は拒否します。runnerの成功は、実AWS/GCPで
実行されたことやproduction report全体の完成を意味しません。

inputからcanonical reportを作成します。

```sh
node scripts/kms-qualification/report.mjs \
  /absolute/path/to/redacted-kms-input.json \
  /absolute/path/to/kms-qualification.json
```

report CLIのstdoutは`sha256:...`だけ、失敗時のstderrはstable error codeだけです。

## detached signatureとproduction verification

report生成直後は`signature.status=unsigned_ready`です。運用上の専用署名鍵で
`signatureInputBytes(report)`を署名し、公開鍵DER、fingerprint、signature、key idを
signature欄へ設定して、report CLIでcanonical化し直します。署名鍵はAWS/GCP workload
identityで保護された署名サービスからのみ利用し、ローカルfixture鍵をproduction
証拠へ流用しません。

production gateの検証はcheckoutのHEADにsource commitが一致する環境で実行します。

```sh
node scripts/kms-qualification/verify.mjs \
  /absolute/path/to/signed-kms-qualification.json \
  /absolute/path/to/pinned-qualification-public-key.der \
  qualification-evidence-production-1
```

成功時はreport digestだけを出力し、次のいずれかを満たさない場合は非0終了します。

- source commitがverifier checkoutのHEADと不一致
- productionではない、mock origin、fixture credential、skipあり
- 8 purpose／IAM matrix／5シナリオ／2 instance PostgreSQL bindingの欠落または不一致
- HSM/non-exportability、immutable version/fingerprint、sign/verify、response-lossの不成立
- canonical JSON、report hash、detached signatureの不一致
- レポート埋め込み鍵と、独立してpinされた公開鍵DER／key idの不一致またはpin欠落

mock reportは開発用の構造テストに限ります。`execution.mode=mock`と
`credential_source=test_fixture`はproduction=trueと同時に正規化できず、仮に後から
productionを変更してもverifierのproduction gateを通りません。

## 保持とレビュー

保存するのは、signed report、runnerが作った参照digest、source commit、image/config
digest、実行時刻、stable verifier結果だけです。providerのcredential、raw response、
tenant情報、ログ本文は保存しません。AWS/GCPで実際にqualificationを完了したという
主張は、保護されたrunnerの実行と、署名済みreportの独立verificationが揃うまで行いません。

## 現時点の未完了項目

このlaneのsource verifierとnegative testは実装済みですが、以下は外部作業であり、
このリポジトリのmock/unit testでは完了扱いにしません。

- 実AWS/GCPアカウント、HSM key、purpose-separated workload identityの作成
- AWS/GCP orchestrationの実装：SDKのraw responseをプロセス内でenum/digestへ写像し、
  runnerの3操作へ接続する。raw responseやcredentialをファイル・stdout・証拠入力へ保存しない
- 64 IAM probeを実provider policyへ接続し、同一purposeだけallow、cross-purposeはdenyとなる
  workload identity/IAM policyの実証
- `signAndVerify`をmanaged signer + durable operation ledgerへ接続し、response-loss時は
  PostgreSQL reconciliationだけで収束させ、provider signを再実行しないことの実証
- 実providerでの全シナリオ実行と、署名済みproduction reportの発行
- protected PostgreSQL 2-instance runの実行・保管
- stagingでのproduction candidateへの適用、独立security review、最終go/no-go
