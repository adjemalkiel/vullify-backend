.PHONY: build run migrate-up migrate-down test

BINARY_DIR := bin

build:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/api ./cmd/api
	go build -o $(BINARY_DIR)/worker ./cmd/worker
	go build -o $(BINARY_DIR)/vullify ./cmd/cli

run:
	go run ./cmd/api

# Requires golang-migrate CLI: https://github.com/golang-migrate/migrate
# Example (Windows): scoop install migrate
# Example (macOS): brew install golang-migrate
DATABASE_URL ?= postgres://vullify:vullify@localhost:5432/vullify?sslmode=disable

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down

test:
	go test ./...
