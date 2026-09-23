FROM golang:1.26.6-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux GOWORK=off go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o status-list-service ./cmd/status-list-service

FROM alpine:3.23

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 statuslist

COPY --from=builder /app/status-list-service /usr/local/bin/status-list-service

USER statuslist

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

ENTRYPOINT ["status-list-service"]
