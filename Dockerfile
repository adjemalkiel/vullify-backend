# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/api /usr/local/bin/api
COPY migrations /migrations

ENV MIGRATIONS_DIR=/migrations

USER nobody
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
