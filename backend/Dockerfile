# =============================================================================
# Generic multi-stage Dockerfile for every AICC Node/Fastify backend service.
# Build with: docker build -f backend/Dockerfile --build-arg SERVICE=auth .
# (build context must be the repo root — pnpm needs the whole workspace).
# =============================================================================
ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS build
ARG SERVICE
RUN test -n "$SERVICE" || (echo "SERVICE build-arg is required" && exit 1)
RUN corepack enable && corepack prepare pnpm@9.12.0 --activate
WORKDIR /repo

# Workspace manifests first (keeps the install layer stable across services).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json ./frontend/package.json
COPY tests/contracts/package.json ./tests/contracts/package.json
COPY backend ./backend
RUN pnpm install --frozen-lockfile

# Build the target service and every workspace package it depends on.
RUN pnpm --filter "@aicc/${SERVICE}-service..." -r run build

# Self-contained production tree (workspace deps inlined, dev deps pruned).
RUN pnpm --filter "@aicc/${SERVICE}-service" deploy --prod /out

FROM ${NODE_IMAGE} AS runtime
ARG SERVICE
ARG PORT=4000
ENV NODE_ENV=production \
    PORT=${PORT}
WORKDIR /app
RUN addgroup -S aicc && adduser -S aicc -G aicc
COPY --from=build --chown=aicc:aicc /out ./
USER aicc
EXPOSE ${PORT}
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://localhost:'+(process.env.PORT||4000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
