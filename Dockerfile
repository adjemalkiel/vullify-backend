# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata curl

# Install trivy via the official install script (v0.71.1)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
    sh -s -- -b /usr/local/bin v0.71.1 && \
    trivy --version

COPY --from=builder /out/api /usr/local/bin/api
COPY --from=builder /out/worker /usr/local/bin/worker
COPY migrations /migrations
COPY start.sh /start.sh
RUN chmod +x /start.sh

ENV MIGRATIONS_DIR=/migrations
ENV TRIVY_PATH=/usr/local/bin/trivy

USER nobody
EXPOSE 8080
ENTRYPOINT ["/start.sh"]
