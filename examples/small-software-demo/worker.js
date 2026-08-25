export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/_agentpass/health") return Response.json({ status: "ok" });
    return Response.json({ app: "team-briefing", message: "Small Software demo" });
  },
};
