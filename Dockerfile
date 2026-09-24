FROM golang:1.26.6-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown

# One image, four binaries (docs/design.md §15): the AS, the two split
# ingestion/verifier services, and the ingress router. Which one a given
# container runs is picked at `docker run`/deploy time via CMD, e.g.
# `docker run ghcr.io/sirosfoundation/siros-status-service:latest ingestion-service`.
RUN CGO_ENABLED=0 GOOS=linux GOWORK=off go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /out/as ./cmd/as && \
    CGO_ENABLED=0 GOOS=linux GOWORK=off go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /out/ingestion-service ./cmd/ingestion-service && \
    CGO_ENABLED=0 GOOS=linux GOWORK=off go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /out/verifier-service ./cmd/verifier-service && \
    CGO_ENABLED=0 GOOS=linux GOWORK=off go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /out/ingress-router ./cmd/ingress-router

FROM alpine:3.23

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 statuslist

COPY --from=builder /out/as /usr/local/bin/as
COPY --from=builder /out/ingestion-service /usr/local/bin/ingestion-service
COPY --from=builder /out/verifier-service /usr/local/bin/verifier-service
COPY --from=builder /out/ingress-router /usr/local/bin/ingress-router

USER statuslist

EXPOSE 8080

# Requires HTTP_ADDR to be set in the container's env (e.g. ":8080") —
# the four binaries default to different ports when unset (8080-8083) so
# they can coexist during local dev, which a static HEALTHCHECK can't
# know about; a real deployment sets HTTP_ADDR explicitly per service
# anyway (see each cmd/*/main.go's flags in docs/design.md §15).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://localhost:${HTTP_ADDR##*:}/healthz" || exit 1

# No default CMD: the deployer names which of the four binaries this
# container runs, e.g. `ingestion-service`.
