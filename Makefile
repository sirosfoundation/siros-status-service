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
build: ## Build all four binaries: as, ingestion-service, verifier-service, ingress-router
	go build $(LDFLAGS) -o bin/as ./cmd/as
	go build $(LDFLAGS) -o bin/ingestion-service ./cmd/ingestion-service
	go build $(LDFLAGS) -o bin/verifier-service ./cmd/verifier-service
	go build $(LDFLAGS) -o bin/ingress-router ./cmd/ingress-router

.PHONY: run-as
run-as: build ## Run the AS — see README "Running locally" for the full four-service walkthrough
	@test -n "$$AS_SIGNING_KEY_PEM" || (echo "AS_SIGNING_KEY_PEM is not set; try: export AS_SIGNING_KEY_PEM=\"\$$(openssl ecparam -name prime256v1 -genkey -noout)\"" && exit 1)
	./bin/as

.PHONY: run-ingestion
run-ingestion: build ## Run ingestion-service — see README "Running locally" for required env vars
	@test -n "$$STATUSLIST_SIGNING_KEY_PEM" || (echo "STATUSLIST_SIGNING_KEY_PEM is not set; try: export STATUSLIST_SIGNING_KEY_PEM=\"\$$(openssl ecparam -name prime256v1 -genkey -noout)\"" && exit 1)
	SIGNING_KEY_PEM="$$STATUSLIST_SIGNING_KEY_PEM" ./bin/ingestion-service

.PHONY: run-verifier
run-verifier: build ## Run verifier-service — see README "Running locally" for required env vars
	@test -n "$$STATUSLIST_SIGNING_KEY_PEM" || (echo "STATUSLIST_SIGNING_KEY_PEM is not set; try: export STATUSLIST_SIGNING_KEY_PEM=\"\$$(openssl ecparam -name prime256v1 -genkey -noout)\"" && exit 1)
	SIGNING_KEY_PEM="$$STATUSLIST_SIGNING_KEY_PEM" ./bin/verifier-service

.PHONY: run-ingress
run-ingress: build ## Run ingress-router — see README "Running locally" for required env vars
	./bin/ingress-router

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
	rm -f bin/as bin/ingestion-service bin/verifier-service bin/ingress-router cover.out cover.html

IMAGE ?= ghcr.io/sirosfoundation/siros-status-service

.PHONY: docker
docker: ## Build Docker image
	docker build -t $(IMAGE):latest --build-arg VERSION=$(VERSION) --build-arg BUILD_TIME=$(shell date -u +%FT%TZ) .

.PHONY: tools
tools: ## Install development tools
	go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
