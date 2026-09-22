# =============================================================================
# Frontend (Vite + React) image.
# Build with: docker build -f frontend/Dockerfile .
# (build context must be the repo root — pnpm workspace install needs it).
# =============================================================================
ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS build
RUN corepack enable && corepack prepare pnpm@9.12.0 --activate
WORKDIR /repo

# pnpm needs every workspace member's package.json to resolve the lockfile,
# even ones the frontend doesn't depend on — copy the whole workspace (source
# isn't needed for the untouched packages, but this keeps the install correct
# and simple).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY backend ./backend
COPY tests/contracts/package.json ./tests/contracts/package.json
COPY frontend ./frontend
RUN pnpm install --frozen-lockfile
RUN pnpm --filter ./frontend build

FROM nginx:alpine AS runtime
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /repo/frontend/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:80/ >/dev/null || exit 1
