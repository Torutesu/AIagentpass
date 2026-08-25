FROM node:20.19.4-bookworm-slim

ENV NODE_ENV=production \
    AGENTPASS_CLOUD_HOST=0.0.0.0 \
    AGENTPASS_CLOUD_PORT=8080

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY apps/cloud-api ./apps/cloud-api
COPY contracts ./contracts
COPY lib ./lib
COPY packages ./packages

RUN groupadd --system --gid 10001 agentpass \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin agentpass \
 && chown -R agentpass:agentpass /app

USER 10001:10001
EXPOSE 8080

CMD ["node", "apps/cloud-api/src/main.mjs"]
