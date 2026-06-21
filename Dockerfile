# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata curl

# Download trivy binary from GitHub
ARG TRIVY_VERSION=0.62.1
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | \
    tar xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    trivy --version

COPY --from=builder /out/api /usr/local/bin/api
COPY migrations /migrations

ENV MIGRATIONS_DIR=/migrations
ENV TRIVY_PATH=/usr/local/bin/trivy

# Use /tmp as Trivy cache so it's writable by the 'nobody' user
ENV TRIVY_CACHE_DIR=/tmp/trivy-cache

USER nobody
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
