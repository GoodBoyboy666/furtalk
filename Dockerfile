# syntax=docker/dockerfile:1

FROM arigaio/atlas:1.3.0-alpine AS atlas

FROM node:24-alpine AS web-builder
WORKDIR /src/web

COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/ ./

RUN corepack enable \
    && corepack prepare pnpm@10.15.0 --activate \
    && pnpm install --frozen-lockfile \
    && pnpm build

FROM golang:1.25.13-alpine AS go-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY . .
COPY --from=web-builder /src/web/dist ./web/dist

RUN mkdir -p /out \
    && ./scripts/stage-web.sh \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -tags embed -trimpath -ldflags "-s -w" -o /out/furtalk ./cmd/app

FROM alpine:3.22 AS runtime

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S furtalk \
    && adduser -S -D -H -G furtalk furtalk \
    && mkdir -p /app/data \
    && chown -R furtalk:furtalk /app

WORKDIR /app
COPY --from=go-builder /out/furtalk ./furtalk
COPY --from=go-builder /src/configs ./configs
COPY --from=go-builder /src/migrations ./migrations
COPY --from=go-builder /src/atlas.runtime.hcl ./atlas.runtime.hcl
COPY --from=go-builder /src/scripts/docker-entrypoint.sh ./docker-entrypoint.sh
COPY --from=atlas /atlas /usr/local/bin/atlas

RUN chmod 0755 /app/docker-entrypoint.sh

USER furtalk
EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["--web"]
