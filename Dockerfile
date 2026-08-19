# syntax=docker/dockerfile:1

FROM arigaio/atlas:1.3.0-alpine AS atlas

FROM --platform=$BUILDPLATFORM node:24-alpine AS web-builder
WORKDIR /src/web

RUN corepack enable \
    && corepack prepare pnpm@10.15.0 --activate

COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY web/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine AS go-builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

ARG TARGETOS
ARG TARGETARCH
COPY cmd ./cmd
COPY internal ./internal
COPY tools/migrate-artalk ./tools/migrate-artalk
COPY scripts/stage-web.sh ./scripts/stage-web.sh
COPY --from=web-builder /src/web/dist ./web/dist

RUN mkdir -p /out \
    && ./scripts/stage-web.sh \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -tags embed -trimpath -ldflags "-s -w" -o /out/furtalk ./cmd/app \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags "-s -w" -o /out/migrate-artalk ./tools/migrate-artalk

FROM alpine:3.22 AS runtime

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S furtalk \
    && adduser -S -D -H -G furtalk furtalk \
    && mkdir -p /app/data /app/configs \
    && chown -R furtalk:furtalk /app

WORKDIR /app
COPY --from=go-builder /out/furtalk ./furtalk
COPY --from=go-builder /out/migrate-artalk ./migrate-artalk
COPY configs ./default-configs
COPY migrations ./migrations
COPY atlas.runtime.hcl ./atlas.runtime.hcl
COPY scripts/docker-entrypoint.sh ./docker-entrypoint.sh
COPY --from=atlas /atlas /usr/local/bin/atlas

RUN chown -R furtalk:furtalk /app/configs \
    && chmod 0755 /app/docker-entrypoint.sh

USER furtalk
EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["--web"]
