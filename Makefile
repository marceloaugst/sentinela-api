.PHONY: build test test-integration vet up down migrate

build:
	go build -o bin/sentinela-api ./cmd/api
	go build -o bin/sentinela-agent ./cmd/agent

vet:
	go vet ./...

test:
	go test -race ./...

# Requer Docker: sobe um Postgres (55432) e um ClickHouse (58123) efêmeros, apenas em loopback.
test-integration:
	@docker rm -f sentinela-test-pg sentinela-test-ch >/dev/null 2>&1 || true
	docker run -d --rm --name sentinela-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test -p 127.0.0.1:55432:5432 postgres:17-alpine
	docker run -d --rm --name sentinela-test-ch -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD=test -p 127.0.0.1:58123:8123 clickhouse/clickhouse-server:24.8-alpine
	@until docker exec sentinela-test-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	@until curl -sf http://127.0.0.1:58123/ping >/dev/null 2>&1; do sleep 1; done
	TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/test?sslmode=disable \
	  TEST_CLICKHOUSE_URL=http://127.0.0.1:58123 TEST_CLICKHOUSE_PASSWORD=test go test -race -tags=integration -count=1 ./...; \
	  rc=$$?; docker rm -f sentinela-test-pg sentinela-test-ch >/dev/null; exit $$rc

up:
	docker compose -f deploy/compose.yaml --env-file .env up --build -d

down:
	docker compose -f deploy/compose.yaml --env-file .env down

migrate:
	go run ./cmd/api migrate
