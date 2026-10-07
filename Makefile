BINARY  := wireaudit
BIN_DIR := bin
PKG     := ./cmd/wireaudit

# Public demo API used by `make smoke`. Its writes are faked server-side, but
# smoke only sends GETs anyway.
SMOKE_TARGET ?= https://jsonplaceholder.typicode.com

.DEFAULT_GOAL := help

.PHONY: help build install test vet lint fmt fmt-check check smoke clean

help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build ./bin/wireaudit
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)

install: ## Install wireaudit into GOBIN
	go install $(PKG)

test: ## Run unit tests
	go test ./...

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format all Go files
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt-formatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

check: fmt-check build vet test lint ## Everything CI should run

# Exit 1 means "findings reported" (expected against a real API); only exit 2
# (the run itself failed) fails the target.
smoke: build ## Probe $(SMOKE_TARGET) with GET-only endpoints
	$(BIN_DIR)/$(BINARY) --target $(SMOKE_TARGET) \
		--endpoint "GET /posts" --endpoint "GET /posts/1"; \
	rc=$$?; [ $$rc -le 1 ]

clean: ## Remove build output
	rm -rf $(BIN_DIR)
