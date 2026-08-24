# Product Hunt launch kit

This folder contains the launch-ready copy and artwork for the AgentPass Product Hunt submission.

## Product Hunt fields

- **Name:** AgentPass
- **Tagline:** Give AI coding agents permission to work — never the private key.
- **Topics:** Developer Tools, Artificial Intelligence, Privacy
- **Pricing:** Free
- **Status:** Early Alpha
- **Product URL:** https://github.com/Torutesu/AIagentpass
- **Maker:** Toru Tano (`Torutesu`)

### Description (under 260 characters)

AgentPass is an open-source macOS policy broker for Claude Code, Cursor, and other AI coding agents. It keeps signing keys inside the protected Mac boundary and grants short-lived, repository-scoped permission instead of handing agents private keys.

### First comment

AI coding agents are great at moving fast. The dangerous part is giving them a private key that can move everywhere. AgentPass keeps the key inside the protected Mac boundary and gives the agent only the smallest, shortest-lived permission needed for one Git operation.

This is an Early Alpha for macOS + Git SSH signing. Try it with a test repository, read the threat model, and tell us what would make the boundary useful in your workflow.

## Gallery order

1. `assets/agentpass-gallery-problem.png` — the exposed-key problem
2. `assets/agentpass-gallery-boundary.png` — the permission boundary

Product Hunt recommends 1270x760 gallery artwork and requires at least two images before the gallery is viewable. These source images are intentionally text-free so the captions remain readable in Product Hunt's UI.

## Demo video

`videos/agentpass-product-hunt/renders/agentpass-product-hunt_2026-08-24_18-06-19.mp4` is a 30-second silent Product Hunt demo. It follows one concrete scene: an AI agent asks to push, the unsafe broad-key path is rejected, and AgentPass grants one repository/branch/operation-scoped capability that expires in 10 minutes.

The terminal and policy card are marketing visualizations, not screenshots of a live hosted Console. Keep that distinction explicit in the launch copy.

## Launch checklist

- Use a personal Product Hunt account with a complete profile.
- Create a draft first; do not publish until the GitHub URL, images, and copy preview correctly.
- Upload `assets/agentpass-thumbnail.png` as the square thumbnail.
- Upload both gallery images in the order above.
- Select **Free** and **Early Alpha**; do not describe AgentPass as production-ready.
- Add the GitHub URL as the primary product link.
- Add the first comment immediately after publishing.
- Be available to answer questions about macOS support, the threat model, and the Early Alpha limits.

## Honest positioning

AgentPass is publishable as an Early Alpha open-source product. It is not yet a hosted, production-qualified SaaS, and the launch copy must not imply that external WebAuthn, cloud KMS, or production deployment qualification has been completed.
