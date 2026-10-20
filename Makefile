.PHONY: build test test-integration vet up down migrate

build:
	go build -o bin/sentinela-api ./cmd/api
	go build -o bin/sentinela-agent ./cmd/agent

vet:
	go vet ./...

test:
	go test -race ./...

# Requer Docker: sobe um Postgres efêmero na porta 55432 (apenas loopback).
test-integration:
	@docker rm -f sentinela-test-pg >/dev/null 2>&1 || true
	docker run -d --rm --name sentinela-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p 127.0.0.1:55432:5432 postgres:17-alpine
	@until docker exec sentinela-test-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/test?sslmode=disable go test -race -tags=integration -count=1 ./...; \
	  rc=$$?; docker rm -f sentinela-test-pg >/dev/null; exit $$rc

up:
	docker compose -f deploy/compose.yaml --env-file .env up --build -d

down:
	docker compose -f deploy/compose.yaml --env-file .env down

migrate:
	go run ./cmd/api migrate
