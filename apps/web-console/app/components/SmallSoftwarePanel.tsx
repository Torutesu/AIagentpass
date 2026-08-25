"use client";

/**
 * Small Software Cloud is intentionally honest about its current boundary.
 * This surface explains the workflow and exposes plan-only commands; it must
 * not manufacture a deployment, auth, or PR success signal in the browser.
 */
export function SmallSoftwarePanel() {
  const steps = [
    ["01", "Prompt", "Claude Code / Codexに作りたい小さなアプリを伝える"],
    ["02", "Inspect", "ソース・依存・公開設定を検査し、危険な差分を止める"],
    ["03", "Deploy", "plan-onlyでbundleとデプロイ計画を確認してから公開"],
    ["04", "Share", "認証・権限を付けた共有URLを発行する"],
    ["05", "Maintain", "API変更を検出し、修正候補とレビュー用PRを作る"],
  ] as const;

  return (
    <>
      <header>
        <p className="eyebrow">SMALL SOFTWARE CLOUD / EARLY ALPHA</p>
        <h1 className="page-heading" id="console-page-heading">作った小さなアプリを、<br />安全に共有する。</h1>
        <p className="page-intro">AIが作った社内CRMや業務ツールを、Cloudの重い設定なしで公開するための運用面です。現時点では計画・検査を中心に提供し、未検証の本番成功を表示しません。</p>
      </header>

      <section className="small-software-hero" aria-labelledby="small-software-status-heading">
        <div>
          <span className="section-kicker">CURRENT BOUNDARY</span>
          <h2 id="small-software-status-heading">Early Alpha / plan-only</h2>
          <p>ローカルで作ったアプリのinspect、bundle、publish計画と、Self-Maintaining APIの修正候補を安全に確認できます。実Cloudflare・実認証・GitHub PRの外部資格はまだ取得していません。</p>
        </div>
        <span className="tag amber">NOT PROVEN</span>
      </section>

      <ol className="small-software-steps" aria-label="Small Software Cloudの流れ">
        {steps.map(([number, title, copy]) => (
          <li className="small-software-step" key={number}>
            <span className="small-software-step-number">{number}</span>
            <h3>{title}</h3>
            <p>{copy}</p>
          </li>
        ))}
      </ol>

      <section className="small-software-command-panel" aria-labelledby="small-software-command-heading">
        <div className="section-heading-row"><div><span className="section-kicker">CLI WORKFLOW</span><h2 className="section-heading" id="small-software-command-heading">まずは計画を確認する</h2></div><span className="section-note">副作用なし</span></div>
        <p className="small-software-command-copy">リポジトリのルートで実行します。publishは明示的な計画確認なしに本番へ変更を加えません。</p>
        <pre className="small-software-code"><code>{`agentpass small-software inspect --path .\nagentpass small-software bundle --path . --plan-only\nagentpass small-software prepare --path . --plan-only\nagentpass small-software publish --path . --plan-only`}</code></pre>
      </section>

      <section className="small-software-maintenance" aria-labelledby="small-software-maintenance-heading">
        <div><span className="section-kicker">SELF-MAINTAINING APIs</span><h2 className="section-heading" id="small-software-maintenance-heading">通知で終わらず、修正候補まで</h2><p>API仕様の変更を検出したら、顧客コードを対象範囲として固定し、digest付きのpatch proposalとレビュー用PR intentを生成します。自動マージや秘密値の取得は行いません。</p></div>
        <div className="small-software-maintenance-badges"><span className="tag green">SCOPE BOUND</span><span className="tag green">HUMAN REVIEW</span><span className="tag amber">PR EXTERNAL NOT PROVEN</span></div>
      </section>
    </>
  );
}
