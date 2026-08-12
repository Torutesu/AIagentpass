import type { Metadata } from "next";
import "./globals.css";

const metadataBase = new URL(
  process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000",
);

export const metadata: Metadata = {
  metadataBase,
  title: "AgentPass Console — 安全にAgentを動かす",
  description:
    "Claude Code と Cursor を、非エンジニアでも安心して運用するためのAgentPass管理コンソール。",
  applicationName: "AgentPass Console",
  generator: "AgentPass",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
  openGraph: {
    title: "AgentPass Console — 安全にAgentを動かす",
    description: "Agentが安全に作業できる状態を、ひと目で確認できます。",
    type: "website",
    siteName: "AgentPass Console",
    images: ["/og.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "AgentPass Console — 安全にAgentを動かす",
    description: "Claude Code と Cursor のための運用コンソール。",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
