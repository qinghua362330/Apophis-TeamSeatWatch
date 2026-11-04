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
RUN echo '3ead1629a1c893f248cd01ee7c9125552b2cac5c91846cb71d6cb1b24883c213  /tmp/ShardX-Linux.zip' | sha256sum -c - \
    && unzip -q /tmp/ShardX-Linux.zip -d /opt \
    && mv /opt/ShardX-Linux /opt/shardx \
    && echo '094fa2e6205bfb3d45fe1c4e7479b1e248d088895b8285a4c9ddab48c9e1100e  /opt/shardx/chrome' | sha256sum -c -

FROM control-runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends xvfb xauth fonts-liberation \
       libnss3 libatk-bridge2.0-0 libx11-xcb1 libxdamage1 libxrandr2 libgbm1 libasound2 \
       libpango-1.0-0 libcairo2 libgtk-3-0 libdrm2 libxcomposite1 libxfixes3 libxkbcommon0 \
       libatspi2.0-0 libcups2 libdbus-1-3 libexpat1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=browser-artifact /opt/shardx /opt/shardx
# This checksum-qualified artifact emits one trailing space before its newline.
RUN test "$(/opt/shardx/chrome --version)" = 'ShardX 152.0.7977.65 ' \
    && mkdir -p /var/lib/teamseatwatch/browser-profiles \
    && chmod 700 /var/lib/teamseatwatch/browser-profiles
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "xvfb-run", "-a", "-s", "-screen 0 1366x768x24", "/apophis-teamseatwatch"]
