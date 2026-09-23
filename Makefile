MODULE = $(shell GOWORK=off go list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || echo "0.0.0")
GOBIN ?= $$(go env GOPATH)/bin
GOLINT := golangci-lint
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(shell date -u +%FT%TZ)"

export GOWORK := off

.PHONY: default
default: build

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the status-list-service binary
	go build $(LDFLAGS) -o bin/status-list-service ./cmd/status-list-service

.PHONY: run
run: build ## Run against docker-compose'd Redis/Postgres (see `make dev-up`)
	@test -n "$$SIGNING_KEY_PEM" || (echo "SIGNING_KEY_PEM is not set; try: export SIGNING_KEY_PEM=\"\$$(openssl ecparam -name prime256v1 -genkey -noout)\"" && exit 1)
	./bin/status-list-service

.PHONY: dev-up
dev-up: ## Start local Redis/Postgres for development
	docker compose up -d

.PHONY: dev-down
dev-down: ## Stop local Redis/Postgres
	docker compose down

.PHONY: test
test: ## Run unit tests (allocator + statuslist packages need no external services)
	go test -v -race ./...

.PHONY: test-short
test-short: ## Run unit tests, skipping the slow bijectivity sweep
	go test -short -race ./...

.PHONY: coverage
coverage: ## Generate coverage report
	go test -coverprofile=cover.out -covermode=atomic -coverpkg=./... ./...
	go tool cover -func=cover.out

.PHONY: lint
lint: ## Run golangci-lint
	@if command -v $(GOLINT) > /dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed. Run: make tools"; \
	fi

.PHONY: fmt
fmt: ## Format code
	go fmt ./...
	@if command -v goimports > /dev/null 2>&1; then \
		goimports -w -local $(MODULE) .; \
	fi

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	go clean
	rm -f bin/status-list-service cover.out cover.html

IMAGE ?= ghcr.io/sirosfoundation/siros-status-service

.PHONY: docker
docker: ## Build Docker image
	docker build -t $(IMAGE):latest --build-arg VERSION=$(VERSION) --build-arg BUILD_TIME=$(shell date -u +%FT%TZ) .

.PHONY: tools
tools: ## Install development tools
	go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
