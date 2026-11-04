FROM node@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS web-builder
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/tools/openapi/package.json ./tools/openapi/package.json
RUN corepack enable && corepack install --global pnpm@12.4.2 && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM golang@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/apophis-teamseatwatch ./cmd/apophis-teamseatwatch

FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS control-runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /out/apophis-teamseatwatch /apophis-teamseatwatch
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=web-builder /src/web/dist/owner /app/owner
COPY --from=web-builder /src/web/dist/public /app/public
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/apophis-teamseatwatch"]

FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS browser-artifact
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY .browser-artifacts/ShardX-Linux.zip /tmp/ShardX-Linux.zip
RUN echo '1de8a89ea228e4a0a602fd0c13c7a324fe5f310e9b08b0c4bf37e9ed0c474fcd  /tmp/ShardX-Linux.zip' | sha256sum -c - \
    && unzip -q /tmp/ShardX-Linux.zip -d /opt \
    && mv /opt/ShardX-Linux /opt/shardx \
    && echo '5b1533db3b08c9cc8f7c24e0c2e31b6202d0bb1dad880f04978d03ce9e4b3ffa  /opt/shardx/chrome' | sha256sum -c -

FROM control-runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends xvfb xauth fonts-liberation \
       libnss3 libatk-bridge2.0-0 libx11-xcb1 libxdamage1 libxrandr2 libgbm1 libasound2 \
       libpango-1.0-0 libcairo2 libgtk-3-0 libdrm2 libxcomposite1 libxfixes3 libxkbcommon0 \
       libatspi2.0-0 libcups2 libdbus-1-3 libexpat1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=browser-artifact /opt/shardx /opt/shardx
RUN /opt/shardx/chrome --version | grep -Eq '^ShardX 156\.0\.8078\.48[[:space:]]*$' \
    && mkdir -p /var/lib/teamseatwatch/browser-profiles \
    && chmod 700 /var/lib/teamseatwatch/browser-profiles
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "xvfb-run", "-a", "-s", "-screen 0 1366x768x24", "/apophis-teamseatwatch"]
