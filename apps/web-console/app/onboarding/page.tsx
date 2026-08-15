import type { Metadata } from "next";

import { HostedOnboarding } from "../components/HostedOnboarding";

export const metadata: Metadata = {
  title: "AgentPassをはじめる — AgentPass Console",
  description: "GitHubとパスキーを使ってAgentPassの安全なワークスペースを準備します。",
  robots: { index: false, follow: false },
};

export default function OnboardingPage() {
  return <HostedOnboarding />;
}
