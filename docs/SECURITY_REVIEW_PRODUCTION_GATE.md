# Independent security-review production gate

この文書は、AgentPass の production-ready 判定に必要な security review
証跡の契約を定義する。ここに記載された fixture、focused test、静的監査、
レビュー計画は、実際の第三者レビューを実施した証明ではない。第三者が実際に
レビューを完了し、署名済み証跡を保護された経路で発行するまで、判定は
`not_proven` のままである。

## 判定境界

運用証跡には三つの独立した段階がある。

| 段階 | verifier の結果 | production-ready か |
| --- | --- | --- |
| 構造検証 | `structure_verified` | いいえ |
| 運用証跡の独立 qualification | `qualification_status: independently_qualified` | いいえ |
| 独立 security review を含む production 検証 | `security_review_status: review_record_verified` | 契約上のみ可。実行済み第三者証跡が必要 |

`verifyOperationsEvidenceBundle()` に運用証跡と qualification だけを渡した結果は、
常に `production_ready: false` と
`production_readiness_blocker: independent_security_review_required` を返す。
production 用の `verifyOperationsEvidenceForProduction()` または CLI の
`verify-production` だけが review record を要求する。review record が欠落、
自己レビュー、期限切れ、source 差し替え、または未署名なら fail-closed する。

CLI の production 検証は、operations index／qualification に加えて reviewer
record、reviewer 公開鍵、expected reviewer identity、full source-tree digest を
受け取る。これらを省略した通常の `verify` は、qualification が通っても
production approval にはならない。

## 独立 review record の必須条件

`agentpass.independent-security-review` v1 の canonical JSON は、少なくとも次を
満たす必要がある。

- `status` は `completed`。`not_reviewed`、`pending`、`self_review`、`not_proven`
  は合格状態ではない。
- `reviewer.kind` は `independent_external`、`role` は `security_reviewer`。
  `reviewer_id` と `organization` は、production verifier に out-of-band で渡す
  expected identity と完全一致する。文字列に `self`、`internal`、`author`、
  `owner`、`local`、fixture／mock 等の marker を許可しない。
- review signature の Ed25519 fingerprint は、運用アーカイブの self-attested
  key および operations qualification key と異なる。fingerprint は verifier の
  呼び出し元が保護された trust configuration から渡し、record 内の自己申告だけを
  trust root にしない。
- `findings.critical`、`findings.high`、`findings.open_critical_high` は全て 0。
  未解決の critical/high 所見を「承認済み」と再分類してはならない。
- `started_at < completed_at < expires_at`。全て UTC millisecond 精度で、現在時刻が
  `expires_at` 以上なら拒否する。レビューの validity window は最大90日とし、期限を
  延長する場合は元の record を編集せず、同じ source binding で新しい署名 record を
  発行する。

## source／artifact binding

review record は、レビュー対象を説明文だけで参照してはならない。次の全てを
canonical signed bytes に含め、verifier の expected 値と比較する。

1. release candidate ID
2. source commit
3. full source tree SHA-256
4. deployed image digest
5. operations `index.json` の canonical SHA-256
6. independent operations qualification record の SHA-256

いずれかが違う record は `security_review_binding_mismatch` として拒否する。
source tree の expected 値、reviewer identity、reviewer public-key fingerprint は
review record 自体から導出せず、protected promotion controller／trust configuration
から供給する。これにより、古い source をレビューした record、別 image の record、
別 candidate の record、qualification の差し替えを production 判定に使えない。

## 攻撃ケースと期待結果

| 攻撃 | 期待する fail-closed 結果 |
| --- | --- |
| review record を省略 | `independent_security_review_evidence_missing` |
| operations bundle の self-attested signature を reviewer key として再利用 | `security_review_key_not_separate` |
| qualification key を reviewer key として再利用 | `security_review_key_not_separate` |
| reviewer identity／organization を別の値に差し替え | `invalid_security_review_identity` |
| `kind=self_attested`、`status=not_reviewed`、または fixture/local reviewer | `invalid_security_review_identity` または schema rejection |
| critical/high/open critical-high のいずれかが非ゼロ | `security_review_findings_open` |
| `expires_at` を過ぎた record、または期限のない record | `security_review_expired`／`stale_security_review` |
| source commit/tree、candidate、image digest を差し替え | `security_review_binding_mismatch` |
| operations index／qualification bytes を差し替え | `security_review_binding_mismatch` |
| canonical JSON、signature、regular-file identity を改ざん | `invalid_security_review_signature` または protected-file rejection |
| ローカル focused test だけを external evidence として提出 | production gate は `not_proven` のまま |

攻撃者が review record と key を同時に新規作成できる場合、それは第三者性を
証明しない。そのため production では reviewer public key と expected identity を
独立した protected configuration に登録し、reviewer が実際に外部で管理する
署名鍵から証跡を受領する必要がある。

## 証跡の取り扱い

失敗した record は削除・編集して pass に変換しない。失敗 record、検証理由、再発行
された record をそれぞれ保持し、candidate／source tree／artifact／run ID と結び付ける。
実第三者レビューが未実施、署名鍵の trust provisioning が未確認、または protected
runner の実行証跡が欠けている場合、コード上の `production_ready: true` 契約を満たす
fixture があっても、製品の production approval は行わない。
