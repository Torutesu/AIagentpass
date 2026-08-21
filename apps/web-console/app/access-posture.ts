export type PostureTone = "green" | "amber" | "red";
export type PostureState = "ready" | "attention" | "blocked" | "checking" | "unavailable";

export type AccessPostureInput = Readonly<{
  summaryState: "loading" | "ready" | "error";
  session: Readonly<{ expiresAt: string; recentAuthAt: string | null }> | null;
  platformAuth: Readonly<{
    loadState: "loading" | "ready" | "error";
    browserSupported: boolean;
    passkeyCount: number;
  }>;
  agents: ReadonlyArray<Readonly<{ status: "active" | "revoked" }>>;
  devices: ReadonlyArray<Readonly<{ status: "pending" | "active" | "revoked"; refreshState: string | null; blockedReason: string | null }>>;
  capabilities: ReadonlyArray<Readonly<{ expiresAt: string }>>;
  auditHealth: ReadonlyArray<Readonly<{ chainStatus: "continuous" | "gap" | "unknown" }>>;
  stopped: boolean;
}>;

export type PostureItem = Readonly<{
  key: "platform-auth" | "human-session" | "agent-access" | "audit" | "revoke";
  label: string;
  state: PostureState;
  tone: PostureTone;
  status: string;
  detail: string;
}>;

export type PostureNextAction = Readonly<{
  title: string;
  detail: string;
  action: "retry" | "security" | "setup" | "activity" | "emergency";
  actionLabel: string;
}>;

export type AccessPosture = Readonly<{
  items: readonly PostureItem[];
  nextAction: PostureNextAction | null;
  activeCapabilityCount: number;
  expiredCapabilityCount: number;
  revokedAgentCount: number;
  revokedDeviceCount: number;
  auditGapCount: number;
}>;

export function deriveAccessPosture(input: AccessPostureInput, now = Date.now()): AccessPosture {
  const activeAgentCount = input.agents.filter((agent) => agent.status === "active").length;
  const revokedAgentCount = input.agents.filter((agent) => agent.status === "revoked").length;
  const activeCapabilityCount = input.capabilities.filter((capability) => Date.parse(capability.expiresAt) > now).length;
  const expiredCapabilityCount = input.capabilities.length - activeCapabilityCount;
  const revokedDeviceCount = input.devices.filter((device) => device.status === "revoked").length;
  const auditGapCount = input.auditHealth.filter((health) => health.chainStatus === "gap").length;
  const auditUnknownCount = input.auditHealth.filter((health) => health.chainStatus === "unknown").length;

  const platform = platformAuthItem(input.platformAuth);
  const humanSession = humanSessionItem(input, now);
  const agentAccess = agentAccessItem(activeAgentCount, activeCapabilityCount, expiredCapabilityCount, input.summaryState);
  const audit = auditItem(input.summaryState, input.auditHealth.length, auditGapCount, auditUnknownCount);
  const revoke = revokeItem(input.stopped, revokedAgentCount, revokedDeviceCount);

  return Object.freeze({
    items: Object.freeze([platform, humanSession, agentAccess, audit, revoke]),
    nextAction: nextAction({ input, platform, humanSession, agentAccess, audit, revoke, activeAgentCount }),
    activeCapabilityCount,
    expiredCapabilityCount,
    revokedAgentCount,
    revokedDeviceCount,
    auditGapCount,
  });
}

function platformAuthItem(auth: AccessPostureInput["platformAuth"]): PostureItem {
  if (auth.loadState === "loading") return item("platform-auth", "Platform auth", "checking", "amber", "確認中", "パスキー設定を安全なメタデータで確認しています。");
  if (auth.loadState === "error") return item("platform-auth", "Platform auth", "unavailable", "amber", "確認できません", "認証設定を取得できませんでした。秘密値は表示しません。");
  if (!auth.browserSupported) return item("platform-auth", "Platform auth", "blocked", "red", "このブラウザは未対応", "Touch ID / パスキーに対応したブラウザで再試行してください。");
  if (auth.passkeyCount === 0) return item("platform-auth", "Platform auth", "attention", "amber", "設定が必要", "再認証に使うパスキーが未登録です。");
  return item("platform-auth", "Platform auth", "ready", "green", "利用可能", `${auth.passkeyCount}件のパスキーを確認済み。秘密鍵は表示しません。`);
}

function humanSessionItem(input: AccessPostureInput, now: number): PostureItem {
  if (input.summaryState === "loading" || input.session === null) return item("human-session", "Human session", "checking", "amber", "確認中", "ブラウザのセッションを確認しています。");
  if (input.summaryState === "error") return item("human-session", "Human session", "unavailable", "red", "確認できません", "セッションを確認できないため、操作データを表示していません。");
  const expiresAt = Date.parse(input.session.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return item("human-session", "Human session", "blocked", "red", "期限切れ", "再認証するまでAgent操作を停止します。");
  return item("human-session", "Human session", "ready", "green", "有効", input.session.recentAuthAt ? "最近の追加認証を確認済み" : "追加認証が必要な操作では再確認します");
}

function agentAccessItem(activeAgentCount: number, activeCapabilityCount: number, expiredCapabilityCount: number, summaryState: AccessPostureInput["summaryState"]): PostureItem {
  if (summaryState !== "ready") return item("agent-access", "Agent session / Capability", "checking", "amber", "未確認", "CloudのAgentと短期権限を確認できるまで判断を保留します。");
  if (activeAgentCount === 0) return item("agent-access", "Agent session / Capability", "attention", "amber", "Agent未登録", "セットアップで端末とAgentを登録してください。");
  if (activeCapabilityCount > 0) return item("agent-access", "Agent session / Capability", "ready", "green", `${activeCapabilityCount}件が有効`, "有効期限と紐付けメタデータのみ表示。署名済みCapability値は表示しません。");
  if (expiredCapabilityCount > 0) return item("agent-access", "Agent session / Capability", "blocked", "red", "短期権限が期限切れ", "セットアップで必要なAgentに短期Capabilityを再発行してください。");
  return item("agent-access", "Agent session / Capability", "attention", "amber", "Capability未発行", "Agent sessionを開始する前に、対象Agentへ短期Capabilityを発行してください。");
}

function auditItem(summaryState: AccessPostureInput["summaryState"], healthCount: number, gapCount: number, unknownCount: number): PostureItem {
  if (summaryState !== "ready") return item("audit", "Audit", "checking", "amber", "未確認", "監査状態を確認できるまで、正常とは扱いません。");
  if (gapCount > 0) return item("audit", "Audit", "blocked", "red", `${gapCount}件の途切れ`, "監査ログを開いて、端末のチェーン欠落を確認してください。");
  if (healthCount === 0 || unknownCount > 0) return item("audit", "Audit", "attention", "amber", "確認範囲が限定的", "監査権限または端末の状態を確認してください。");
  return item("audit", "Audit", "ready", "green", "連続性を確認済み", `${healthCount}端末の監査チェーンを確認済みです。`);
}

function revokeItem(stopped: boolean, revokedAgentCount: number, revokedDeviceCount: number): PostureItem {
  if (stopped) return item("revoke", "Revoke / emergency stop", "blocked", "red", "組織停止中", "すべてのAgentを停止中です。再開前にセットアップと監査ログを確認してください。");
  const revoked = revokedAgentCount + revokedDeviceCount;
  if (revoked > 0) return item("revoke", "Revoke / emergency stop", "attention", "amber", `${revoked}件を停止済み`, "停止済みのAgent・端末があります。必要なら新しい登録を作成してください。");
  return item("revoke", "Revoke / emergency stop", "ready", "green", "停止操作を利用可能", "不審な動きがあれば、いつでもAgentを停止できます。");
}

function nextAction({ input, platform, humanSession, agentAccess, audit, revoke, activeAgentCount }: Readonly<{
  input: AccessPostureInput;
  platform: PostureItem;
  humanSession: PostureItem;
  agentAccess: PostureItem;
  audit: PostureItem;
  revoke: PostureItem;
  activeAgentCount: number;
}>): PostureNextAction | null {
  if (input.summaryState === "error") return { title: "Cloudの状態を再確認してください", detail: "安全状態を確認できないため、表示上のAgent状態を信頼しないでください。", action: "retry", actionLabel: "再同期する" };
  if (humanSession.state === "blocked") return { title: "もう一度サインインしてください", detail: "セッションが期限切れです。再認証するまで操作は停止しています。", action: "retry", actionLabel: "再認証する" };
  if (platform.state === "blocked" || platform.state === "attention" || platform.state === "unavailable") return { title: "Platform authを設定してください", detail: "パスキーを登録すると、Agentの登録や停止などの重要操作を安全に確認できます。", action: "security", actionLabel: "認証設定を開く" };
  if (revoke.state === "blocked") return { title: "停止中のAgentを確認してください", detail: "緊急停止の解除を急がず、監査ログと端末状態を確認してから再開します。", action: "emergency", actionLabel: "停止状態を見る" };
  if (audit.state === "blocked") return { title: "監査ログの欠落を確認してください", detail: "記録が途切れている端末の状態を確認するまで、正常とは判断しません。", action: "activity", actionLabel: "監査ログを見る" };
  if (agentAccess.state === "blocked" || agentAccess.state === "attention") return { title: activeAgentCount === 0 ? "最初のAgentを登録してください" : "Agentの短期権限を準備してください", detail: "必要なAgentだけに、期限付きのCapabilityを発行してから作業を開始します。", action: "setup", actionLabel: "セットアップを開く" };
  return { title: "準備完了です", detail: "Agentの作業を開始したら、監査ログで許可・ブロックの結果を確認できます。", action: "activity", actionLabel: "監査ログを見る" };
}

function item(key: PostureItem["key"], label: string, state: PostureState, tone: PostureTone, status: string, detail: string): PostureItem {
  return Object.freeze({ key, label, state, tone, status, detail });
}
